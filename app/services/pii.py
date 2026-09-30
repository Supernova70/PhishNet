"""PII masking for exports, reports, and graph labels.

Enabled via `settings.MASK_PII`. Masking is deliberately lossless for
domains and hashes (they are the IoCs being reported on) but hides
recipient local-parts and, optionally, host bits of IPs so exported
artifacts can be shared with third parties.
"""

from typing import Optional

from app.config import get_settings


def mask_email(addr: Optional[str]) -> Optional[str]:
    """`j.doe@corp.com` → `j***@corp.com`; keeps domain intact."""
    if not addr or "@" not in addr:
        return addr
    local, _, domain = addr.partition("@")
    if not local:
        return addr
    return f"{local[0]}***@{domain}"


def mask_ip(ip: Optional[str]) -> Optional[str]:
    """Masks the final host bits: `203.0.113.50` → `203.0.113.x`,
    `2001:db8::1` → `2001:db8::x`. Network prefix stays readable so
    origin/ASN analysis remains meaningful."""
    if not ip:
        return ip
    if ":" in ip:  # IPv6 — keep the prefix through the last '::' group
        head = ip.rsplit("::", 1)[0] if "::" in ip else ip
        return f"{head}::x"
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["x"])
    return ip


def maybe_mask_email(addr: Optional[str]) -> Optional[str]:
    return mask_email(addr) if get_settings().MASK_PII else addr


def maybe_mask_ip(ip: Optional[str]) -> Optional[str]:
    return mask_ip(ip) if get_settings().MASK_PII else ip
