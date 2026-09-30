"""Seed demo GeoIP cache for the crafted corpus.

The fixture emails intentionally use RFC 5737 documentation addresses
(198.51.100.0/24, 203.0.113.0/24) so tests and demos never touch live
hosts — which also means real GeoIP providers will never return a
country for them. The SIH plan's risk register sanctions exactly this
fix: "DB cache (`ip_intel`) + in-process TTL; **seeded demo intel**".

Rows are inserted with source='demo_seed' and only where no real
country data already exists, so live enrichment always wins later.

Usage:
    DATABASE_URL=sqlite:///./data/dev.db python scripts/seed_demo_intel.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.dependencies import SessionLocal  # noqa: E402
from app.models.ip_intel import IpIntel  # noqa: E402

# ip -> (country, country_code, region, city, lat, lon, asn, asn_org, isp,
#        ptr, is_vpn, is_tor, is_hosting)
DEMO: dict[str, tuple] = {
    # bulk-campaign origin (5 scans) — anonymized VPS in Moscow
    "203.0.113.20": (
        "Russia", "RU", "Moscow", "Moscow", 55.7558, 37.6173,
        49505, "Selectel", "Selectel DC", "vps-203-0-113-20.demo",
        False, False, True,
    ),
    # fixture labelled as a Tor exit (range 185.220.101.0/24 is real Tor space)
    "185.220.101.5": (
        "Germany", "HE", "Hesse", "Frankfurt", 50.1109, 8.6821,
        60729, "Zwiebelfreunde e.V.", "Tor Exit", "tor-exit-5.demo",
        False, True, False,
    ),
    "203.0.113.90": (
        "United States", "US", "California", "Los Angeles", 34.0522, -118.2437,
        14061, "DigitalOcean", "DigitalOcean LLC", "cdn-edge-90.demo",
        False, False, True,
    ),
    "203.0.113.101": (
        "Netherlands", "NH", "North Holland", "Amsterdam", 52.3676, 4.9041,
        202425, "IP Volume", "ipvolume ltd", "relay-101.demo",
        True, False, False,
    ),
    "198.51.100.34": (
        "United States", "US", "Texas", "Dallas", 32.7767, -96.797,
        35913, "Leaseweb", "Leaseweb USA", "mail-34.demo",
        False, False, True,
    ),
    "198.51.100.77": (
        "Brazil", "SP", "Sao Paulo", "Sao Paulo", -23.5505, -46.6333,
        28573, "Claro S.A.", "Claro Telecom", "mx-77.demo",
        False, False, False,
    ),
    "198.51.100.63": (
        "Singapore", "SG", "", "Singapore", 1.3521, 103.8198,
        3758, "Singapore Telecom", "Singtel", "sg-mx-63.demo",
        False, False, False,
    ),
    "198.51.100.120": (
        "Ukraine", "UA", "Kyiv", "Kyiv", 50.4501, 30.5234,
        200876, "UAB Host1", "host1 ua", "ws-120.demo",
        False, False, True,
    ),
    "203.0.113.66": (
        "Nigeria", "LA", "Lagos", "Lagos", 6.5244, 3.3792,
        37282, "MainOne Cable", "MainOne", "mail-66.demo",
        False, False, False,
    ),
    "203.0.113.70": (
        "India", "MH", "Maharashtra", "Mumbai", 19.076, 72.8777,
        13335, "Cloudflare", "Cloudflare WARP", "warp-70.demo",
        True, False, False,
    ),
    "203.0.113.44": (
        "United States", "NY", "New York", "New York", 40.7128, -74.006,
        16509, "Amazon.com", "AWS EC2", "ec2-44.demo",
        False, False, True,
    ),
    "203.0.113.130": (
        "Germany", "BE", "Berlin", "Berlin", 52.52, 13.405,
        24940, "Hetzner", "Hetzner Online", "hs-130.demo",
        False, False, True,
    ),
    "198.51.100.88": (
        "France", "IDF", "Ile-de-France", "Paris", 48.8566, 2.3522,
        16276, "OVH", "OVH SAS", "ovh-88.demo",
        False, False, True,
    ),
    "198.51.100.99": (
        "United Kingdom", "ENG", "England", "London", 51.5074, -0.1278,
        5089, "Virgin Media", "Virgin Media", "cable-99.demo",
        False, False, False,
    ),
    "198.51.100.11": (
        "Vietnam", "HN", "Hanoi", "Hanoi", 21.0278, 105.8342,
        45899, "VNPT", "VNPT JSC", "vnpt-11.demo",
        False, False, False,
    ),
    "198.51.100.10": (
        "Indonesia", "JK", "Jakarta", "Jakarta", -6.2088, 106.8456,
        58404, "PT Telkom", "Telkom Indonesia", "telkom-10.demo",
        False, False, False,
    ),
    "203.0.113.91": (
        "Romania", "B", "Bucharest", "Bucharest", 44.4268, 26.1025,
        60592, "M247", "M247 SRL", "m247-91.demo",
        False, False, True,
    ),
    "198.51.100.52": (
        "Canada", "ON", "Ontario", "Toronto", 43.6532, -79.3832,
        "812", "Rogers Communications", "Rogers", "rogers-52.demo",
        False, False, False,
    ),
    "198.51.100.140": (
        "South Africa", "GP", "Gauteng", "Johannesburg", -26.2041, 28.0473,
        37457, "Telkom SA", "Telkom Internet", "za-140.demo",
        False, False, False,
    ),
}


def main() -> int:
    db = SessionLocal()
    inserted = updated = 0
    try:
        for ip, row in DEMO.items():
            (
                country, cc, region, city, lat, lon,
                asn, asn_org, isp, ptr, is_vpn, is_tor, is_hosting,
            ) = row
            existing = db.get(IpIntel, ip)
            if existing is not None:
                if existing.country:
                    continue  # real/live data wins
                existing.country = country
                existing.country_code = cc
                existing.region = region or None
                existing.city = city
                existing.lat = lat
                existing.lon = lon
                existing.asn = int(asn)
                existing.asn_org = asn_org
                existing.isp = isp
                existing.ptr_host = ptr
                existing.is_vpn = is_vpn
                existing.is_tor = is_tor
                existing.is_hosting = is_hosting
                existing.source = "demo_seed"
                existing.fetched_at = datetime.utcnow()
                existing.expires_at = datetime.utcnow() + timedelta(days=365)
                updated += 1
            else:
                db.add(IpIntel(
                    ip=ip,
                    country=country, country_code=cc, region=region or None,
                    city=city, lat=lat, lon=lon,
                    asn=int(asn), asn_org=asn_org, isp=isp, ptr_host=ptr,
                    is_vpn=is_vpn, is_tor=is_tor, is_hosting=is_hosting,
                    source="demo_seed",
                    fetched_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + timedelta(days=365),
                ))
                inserted += 1
        db.commit()
        print(f"demo intel seeded: {inserted} inserted, {updated} filled, "
              f"{len(DEMO)} total mapped")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
