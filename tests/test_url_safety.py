import socket

import pytest

from app.security.url_safety import UnsafeUrlError, UrlSafetyValidator


def answer(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


def resolver_for(*ips: str):
    def resolve(*_args, **_kwargs):
        return [answer(ip) for ip in ips]

    return resolve


def test_public_url_is_normalized_and_resolved():
    validator = UrlSafetyValidator(resolver=resolver_for("93.184.216.34"))
    result = validator.validate("HTTPS://ExAmPle.com/login#fragment")
    assert result.normalized_url == "https://example.com/login"
    assert result.resolved_ips == ("93.184.216.34",)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fe80::1]/",
    ],
)
def test_non_public_ip_literals_are_blocked(url):
    with pytest.raises(UnsafeUrlError) as exc:
        UrlSafetyValidator().validate(url)
    assert exc.value.code == "non_public_ip"


def test_mixed_public_private_dns_answer_is_blocked():
    validator = UrlSafetyValidator(
        resolver=resolver_for("93.184.216.34", "192.168.1.20")
    )
    with pytest.raises(UnsafeUrlError) as exc:
        validator.validate("https://mixed.example/")
    assert exc.value.code == "non_public_ip"


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://example.com/file", "unsupported_scheme"),
        ("https://user:pass@example.com/", "embedded_credentials"),
        ("https://example.com:8443/", "blocked_port"),
        ("https:///missing", "missing_host"),
    ],
)
def test_structurally_unsafe_urls_are_blocked(url, code):
    validator = UrlSafetyValidator(resolver=resolver_for("93.184.216.34"))
    with pytest.raises(UnsafeUrlError) as exc:
        validator.validate(url)
    assert exc.value.code == code
