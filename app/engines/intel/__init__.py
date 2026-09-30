"""Origin / geo / reputation providers for IP intelligence.

Everything network-facing is injectable (`http_get`, `fetch_text`,
`resolver`) so unit tests run fully offline — the same pattern as
`headers/dns_checks.py`.
"""

from app.engines.intel.geo_provider import (  # noqa: F401
    GeoResult,
    IpIntelProvider,
    IpWhoisIoProvider,
    MaxMindGeoLite2Provider,
    NullProvider,
    get_provider,
)
