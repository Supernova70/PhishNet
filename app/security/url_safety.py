"""SSRF-focused validation for browser navigation targets."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

Resolver = Callable[..., Iterable[tuple]]


class UnsafeUrlError(ValueError):
    """Raised when a URL must not be requested by the browser."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SafeUrl:
    normalized_url: str
    hostname: str
    port: int
    resolved_ips: tuple[str, ...]


def _public_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsafeUrlError("invalid_ip", f"Invalid IP address: {value}") from exc

    if not address.is_global:
        raise UnsafeUrlError("non_public_ip", f"Destination is not public: {address}")
    return address


def _normalized_parts(parts: SplitResult, ascii_host: str, port: int) -> str:
    default_port = (parts.scheme == "http" and port == 80) or (
        parts.scheme == "https" and port == 443
    )
    host_for_url = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = host_for_url if default_port else f"{host_for_url}:{port}"
    return urlunsplit(
        (parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")
    )


class UrlSafetyValidator:
    """Validate URL syntax, ports, DNS answers, and public routability."""

    def __init__(
        self,
        allowed_ports: tuple[int, ...] = (80, 443),
        resolver: Resolver = socket.getaddrinfo,
    ):
        self.allowed_ports = allowed_ports
        self._resolver = resolver

    def validate(self, url: str) -> SafeUrl:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise UnsafeUrlError("malformed_url", "URL or port is malformed") from exc

        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise UnsafeUrlError(
                "unsupported_scheme", "Only HTTP and HTTPS are allowed"
            )
        if not parts.hostname:
            raise UnsafeUrlError("missing_host", "URL has no hostname")
        if parts.username is not None or parts.password is not None:
            raise UnsafeUrlError(
                "embedded_credentials", "Embedded URL credentials are blocked"
            )

        port = port or (443 if scheme == "https" else 80)
        if port not in self.allowed_ports:
            raise UnsafeUrlError(
                "blocked_port", f"Destination port {port} is not allowed"
            )

        try:
            ascii_host = (
                parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
            )
        except UnicodeError as exc:
            raise UnsafeUrlError(
                "invalid_hostname", "Hostname is not valid IDNA"
            ) from exc

        addresses: set[str] = set()
        try:
            literal = ipaddress.ip_address(ascii_host)
        except ValueError:
            try:
                answers = self._resolver(
                    ascii_host,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
            except OSError as exc:
                raise UnsafeUrlError(
                    "dns_failure", "Hostname could not be resolved"
                ) from exc
            for answer in answers:
                sockaddr = answer[4]
                if sockaddr:
                    addresses.add(str(ipaddress.ip_address(sockaddr[0])))
        else:
            addresses.add(str(literal))

        if not addresses:
            raise UnsafeUrlError("dns_failure", "Hostname resolved to no addresses")
        for address in addresses:
            _public_ip(address)

        return SafeUrl(
            normalized_url=_normalized_parts(parts, ascii_host, port),
            hostname=ascii_host,
            port=port,
            resolved_ips=tuple(sorted(addresses)),
        )
