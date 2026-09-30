"""Intelligence endpoints — header forensics, origin trace, graph, campaigns.

Week 2 surface for the engines added alongside this plan:

  GET  /emails/{email_id}/headers   parsed Received chain + auth results
  GET  /emails/{email_id}/trace     origin trace + geo/ASN/reputation intel
  GET  /ips/{ip}                    cached (or refreshed) IP intelligence
  GET  /indicators                  IoC search for the graph/campaign UI
  GET  /graph                       nodes/edges JSON (node-capped)
  GET  /campaigns                   clustered phishing runs
  GET  /campaigns/{campaign_id}     campaign detail + member scans
  POST /campaigns/recluster         backfill clustering over all scans

All enrichment degrades gracefully: offline runs return cached/absent
intel instead of failing, and live lookups only happen when explicitly
requested (`refresh=true`) or DNS is opted in.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db
from app.engines.correlation.campaign_clustering import (
    ScanInput,
    cluster_scans,
    save_clusters,
)
from app.engines.correlation.graph_builder import build_graph_from_db
from app.engines.headers.received_parser import parse_received_chain
from app.engines.intel.origin import build_origin_trace
from app.models.campaign import Campaign
from app.models.email import Email
from app.models.indicator import Indicator
from app.models.ip_intel import IpIntel
from app.models.scan import Scan, Verdict
from app.services.ip_intel_service import IpIntelService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Intelligence"])

# Trace enrichment caps — keep provider quota use bounded per request.
TRACE_REFRESH_MAX_IPS = 10   # refresh=true: enrich synchronously
TRACE_BG_MAX_IPS = 6         # background: queued after the response


def _get_email(db: Session, email_id: int) -> Email:
    email = db.query(Email).filter(Email.id == email_id).first()
    if email is None:
        raise HTTPException(status_code=404, detail="Email not found")
    return email


def _hops_payload(db: Session, email: Email) -> list:
    from app.models.email_source import ReceivedHop

    rows = (
        db.query(ReceivedHop)
        .filter(ReceivedHop.email_id == email.id)
        .order_by(ReceivedHop.hop_index)
        .all()
    )
    if rows:
        return [
            {
                "hop_index": r.hop_index,
                "from_host": r.from_host,
                "from_ip": r.from_ip,
                "helo": r.helo,
                "by_host": r.by_host,
                "via": r.via,
                "protocol": r.protocol,
                "timestamp": (
                    r.timestamp_utc.isoformat() if r.timestamp_utc else None
                ),
                "is_internal": r.is_internal,
                "raw": r.raw,
            }
            for r in rows
        ]
    # Fallback: re-parse retained headers (emails ingested before hop rows)
    source = email.source
    if source and source.headers_json:
        hops = parse_received_chain(source.headers_json.get("received", []))
        return [
            {
                "hop_index": i,
                "from_host": h.from_host,
                "from_ip": h.from_ip,
                "helo": h.helo,
                "by_host": h.by_host,
                "via": h.via,
                "protocol": h.protocol,
                "timestamp": h.timestamp_utc.isoformat() if h.timestamp_utc else None,
                "is_internal": h.is_internal,
                "raw": h.raw,
            }
            for i, h in enumerate(hops)
        ]
    return []


@router.get("/emails/{email_id}/headers")
async def get_email_headers(email_id: int, db: Session = Depends(get_db)):
    """Parsed header evidence: Received chain + SPF/DKIM/DMARC results."""
    email = _get_email(db, email_id)
    source = email.source

    from app.models.email_source import AuthResult

    auth_row = (
        db.query(AuthResult).filter(AuthResult.email_id == email_id).first()
    )
    present = bool(source and source.headers_json)
    if present:
        from app.services.evidence_service import audit

        audit(
            db,
            "raw_view",
            actor="api",
            entity_type="email_headers",
            entity_id=email_id,
            detail={"raw_sha256": source.raw_sha256 if source else None},
        )
    return {
        "email_id": email_id,
        "present": present,
        "headers": (source.headers_json if source else None),
        "hops": _hops_payload(db, email),
        "auth": auth_row.to_dict() if auth_row else None,
        "raw_path": source.raw_path if source else None,
        "raw_sha256": source.raw_sha256 if source else None,
        "size_bytes": source.size_bytes if source else None,
    }


def _enrich_ips_background(ips: list) -> None:
    """Post-response job: fill the ip_intel cache for trace IPs.

    Runs after the response is sent so the trace page renders instantly
    with whatever is cached, then picks up geo/ASN rows a few seconds
    later (the FE re-polls while `enriching > 0`). Own session — the
    request-scoped one is already closed.
    """
    if not ips:
        return
    from app.dependencies import SessionLocal

    db = SessionLocal()
    try:
        settings = get_settings()
        ptr_resolver = (
            _live_dns_resolver() if settings.HEADER_DNS_CHECKS_ENABLED else None
        )
        service = IpIntelService(db, ptr_resolver=ptr_resolver)
        for ip in ips:
            try:
                service.enrich(ip)
                db.commit()
            except Exception:
                # Parallel trace views can race the same IP — a duplicate
                # insert means another task already wrote it, which is a
                # success, not a failure.
                try:
                    db.rollback()
                except Exception:  # pragma: no cover - defensive
                    pass
                if service.cached_only(ip) is None:
                    logger.warning(
                        "background ip enrichment failed for %s", ip, exc_info=True
                    )
    except Exception:
        logger.warning("background ip enrichment failed", exc_info=True)
        try:
            db.rollback()
        except Exception:  # pragma: no cover - defensive
            pass
    finally:
        db.close()


@router.get("/emails/{email_id}/trace")
async def get_email_trace(
    email_id: int,
    background_tasks: BackgroundTasks,
    refresh: bool = Query(False, description="Force live geo/IP enrichment"),
    db: Session = Depends(get_db),
):
    """Origin trace: earliest external hop + geo/ASN/reputation intel.

    Cache-only by default; missing IPs are enriched in the background
    (`enriching` in the payload tells the FE to re-poll), and
    `refresh=true` enriches synchronously (origin first, then hops).
    """
    email = _get_email(db, email_id)
    hops = _hops_payload(db, email)

    # Origin from parsed hop dicts (chronological order guaranteed)
    origin = build_origin_trace(
        [
            {
                "from_ip": h["from_ip"],
                "from_host": h["from_host"],
                "helo": h["helo"],
                "by_host": h["by_host"],
                "timestamp_utc": h["timestamp"],
                "is_internal": h["is_internal"],
            }
            for h in hops
        ]
    )

    # Cached per-hop geo (DB-only unless enrichment runs below) — feeds
    # the trace polyline (plan §6.1 / backlog FE-C6).
    hop_ips = sorted({h["from_ip"] for h in hops if h.get("from_ip")})
    all_ips = list(dict.fromkeys(([origin.ip] if origin else []) + hop_ips))
    now = datetime.utcnow()
    fresh: set = set()
    if all_ips:
        for (ip,) in (
            db.query(IpIntel.ip)
            .filter(IpIntel.ip.in_(all_ips))
            .filter((IpIntel.expires_at.is_(None)) | (IpIntel.expires_at > now))
            .all()
        ):
            fresh.add(ip)
    missing = [ip for ip in all_ips if ip not in fresh]

    intel = None
    enriching = 0
    if origin is not None or missing:
        settings = get_settings()
        ptr_resolver = (
            _live_dns_resolver() if settings.HEADER_DNS_CHECKS_ENABLED else None
        )
        service = IpIntelService(db, ptr_resolver=ptr_resolver)
        if refresh:
            if origin is not None:
                intel = service.enrich(origin.ip)
            extra = [ip for ip in missing if origin is None or ip != origin.ip]
            for ip in extra[: max(TRACE_REFRESH_MAX_IPS - 1, 0)]:
                service.enrich(ip)
            if missing:
                # get_db never commits — persist enrichment so the next
                # request is a cache hit instead of a network re-fetch.
                db.commit()
        else:
            if origin is not None:
                intel = service.cached_only(origin.ip)
            auto = bool(getattr(settings, "IP_INTEL_AUTO_ENRICH", True))
            if missing and auto:
                queued = missing[:TRACE_BG_MAX_IPS]
                enriching = len(queued)
                background_tasks.add_task(_enrich_ips_background, queued)

    cached_geo: dict = {}
    if hop_ips:
        for row in db.query(IpIntel).filter(IpIntel.ip.in_(hop_ips)).all():
            if row.lat is not None and row.lon is not None:
                cached_geo[row.ip] = {
                    "lat": row.lat,
                    "lon": row.lon,
                    "country": row.country,
                    "country_code": row.country_code,
                }
    for h in hops:
        h["geo"] = cached_geo.get(h["from_ip"]) if h.get("from_ip") else None

    return {
        "email_id": email_id,
        "origin": origin.to_dict() if origin else None,
        "hops": hops,
        "intel": intel.to_dict() if intel else None,
        "enriching": enriching,
    }


@router.get("/attribution/stats")
async def attribution_stats(
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    """Attribution-kind counts over recent verdicts (plan §6 KPI, FE-C5).

    Aggregates `breakdown.attribution.kind` from the newest verdicts —
    the data behind the dashboard's attribution split donut. Cache-only;
    never triggers lookups.
    """
    rows = (
        db.query(Verdict.breakdown)
        .order_by(Verdict.id.desc())
        .limit(limit)
        .all()
    )
    counts: dict = {}
    for (breakdown,) in rows:
        attribution = (breakdown or {}).get("attribution") or {}
        kind = attribution.get("kind") or "unknown"
        counts[kind] = counts.get(kind, 0) + 1
    total = sum(counts.values())
    return {
        "total": total,
        "kinds": [
            {"kind": kind, "count": n}
            for kind, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
    }


@router.get("/ips/stats")
async def ip_stats(db: Session = Depends(get_db)):
    """Aggregate cache-only geo stats for the dashboard (never hits network)."""
    from sqlalchemy import func

    rows = (
        db.query(IpIntel.country, func.count(IpIntel.ip))
        .group_by(IpIntel.country)
        .order_by(func.count(IpIntel.ip).desc())
        .limit(10)
        .all()
    )
    total = db.query(func.count(IpIntel.ip)).scalar() or 0
    return {
        "total_ips": int(total),
        "countries": [{"country": country, "count": int(n)} for country, n in rows],
    }


@router.get("/ips/geo")
async def ip_geo_points(db: Session = Depends(get_db)):
    """Geo-plottable IP points for the dashboard 3D globe (cache-only)."""
    from sqlalchemy import func

    rows = (
        db.query(IpIntel)
        .filter(IpIntel.lat.isnot(None), IpIntel.lon.isnot(None))
        .order_by(IpIntel.ip.asc())
        .all()
    )
    total = int(db.query(func.count(IpIntel.ip)).scalar() or 0)
    return {
        "points": [
            {
                "ip": r.ip,
                "lat": r.lat,
                "lng": r.lon,
                "country": r.country,
                "country_code": r.country_code,
                "city": r.city,
                "asn": r.asn,
                "asn_org": r.asn_org,
                "is_tor": bool(r.is_tor),
                "is_vpn": bool(r.is_vpn),
                "is_proxy": bool(r.is_proxy),
                "is_hosting": bool(r.is_hosting),
                "is_dnsbl_listed": bool(r.is_dnsbl_listed),
            }
            for r in rows
        ],
        "total_ips": total,
        "geoed": len(rows),
    }


@router.get("/ips/{ip}")
async def get_ip_intel(
    ip: str,
    refresh: bool = Query(False, description="Force live provider lookup"),
    db: Session = Depends(get_db),
):
    """
    IP intelligence. Default is strictly cache-only; `refresh=true`
    re-queries the configured provider (graceful when offline).
    """
    settings = get_settings()
    ptr_resolver = _live_dns_resolver() if settings.HEADER_DNS_CHECKS_ENABLED else None
    service = IpIntelService(db, ptr_resolver=ptr_resolver)
    row = service.enrich(ip) if refresh else service.cached_only(ip)
    if refresh and row is not None:
        # get_db never commits — persist the fresh lookup for later reads.
        db.commit()
    if row is None:
        return {"ip": ip, "intel": None}
    return {"ip": ip, "intel": row.to_dict()}


@router.get("/indicators")
async def list_indicators(
    q: Optional[str] = Query(None, description="Substring match on value"),
    type: Optional[str] = Query(None, description="Filter by indicator type"),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """Global IoC search: rows aggregated across scans by (type, value)."""
    from sqlalchemy import func

    query = db.query(
        Indicator.type,
        Indicator.value,
        func.count(func.distinct(Indicator.scan_id)).label("scan_count"),
        func.sum(Indicator.sighting_count).label("sightings"),
        func.min(Indicator.first_seen).label("first_seen"),
        func.max(Indicator.last_seen).label("last_seen"),
    )
    if type:
        query = query.filter(Indicator.type == type)
    if q:
        query = query.filter(Indicator.value.contains(q.lower()))
    rows = (
        query.group_by(Indicator.type, Indicator.value)
        .order_by(func.count(func.distinct(Indicator.scan_id)).desc(),
                  func.max(Indicator.last_seen).desc())
        .limit(limit)
        .all()
    )
    payload = [
        {
            "type": r.type,
            "value": r.value,
            "scan_count": r.scan_count,
            "sighting_count": int(r.sightings or 0),
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]
    return {"count": len(payload), "indicators": payload}


@router.get("/graph")
async def get_graph(
    min_score: float = Query(0.0, ge=0.0, le=100.0),
    campaign_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    """Attribution graph: node-capped JSON for the force-directed view."""
    return build_graph_from_db(
        db, min_score=min_score, campaign_id=campaign_id, scan_id=scan_id,
        limit=limit,
    )


def _live_dns_resolver():
    """Default dnspython resolver — only constructed when DNS is opted in."""
    from app.engines.headers.dns_checks import _default_resolver

    return _default_resolver


@router.get("/campaigns")
async def list_campaigns(
    status: Optional[str] = Query(None, description="Filter by status"),
    db: Session = Depends(get_db),
):
    query = db.query(Campaign)
    if status:
        query = query.filter(Campaign.status == status)
    rows = query.order_by(Campaign.email_count.desc(), Campaign.avg_score.desc()).all()
    return {"count": len(rows), "campaigns": [c.to_dict() for c in rows]}


@router.post("/campaigns/recluster")
async def recluster_campaigns(db: Session = Depends(get_db)):
    """
    Backfill: rebuild campaign clusters over all scans that have verdicts.

    Replaces existing campaign rows (they are derived data, always
    regenerable from indicators + subjects).
    """
    rows = (
        db.query(Scan, Verdict, Email)
        .join(Verdict, Verdict.scan_id == Scan.id)
        .join(Email, Email.id == Scan.email_id)
        .all()
    )
    if not rows:
        return {"campaigns": [], "scans_clustered": 0, "scans_total": 0}

    scan_ids = [s.id for s, _, _ in rows]
    indicators = (
        db.query(Indicator).filter(Indicator.scan_id.in_(scan_ids)).all()
    )
    by_scan: dict = {}
    for ind in indicators:
        by_scan.setdefault(ind.scan_id, []).append((ind.type, ind.value))

    inputs = [
        ScanInput(
            id=scan.id,
            subject=email.subject or "",
            score=verdict.final_score,
            indicators=tuple(by_scan.get(scan.id, ())),
            sent_at=scan.completed_at or email.fetched_at,
        )
        for scan, verdict, email in rows
    ]

    clusters = cluster_scans(inputs)
    campaigns = save_clusters(db, clusters)
    db.commit()

    return {
        "campaigns": [c.to_dict() for c in campaigns],
        "scans_clustered": sum(c.email_count for c in campaigns),
        "scans_total": len(rows),
    }


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    members = (
        db.query(Scan, Verdict, Email)
        .outerjoin(Verdict, Verdict.scan_id == Scan.id)
        .join(Email, Email.id == Scan.email_id)
        .filter(Scan.campaign_id == campaign_id)
        .order_by(Verdict.final_score.desc())
        .all()
    )
    return {
        "campaign": campaign.to_dict(),
        "scans": [
            {
                "scan_id": scan.id,
                "email_id": email.id,
                "subject": email.subject,
                "sender": email.sender,
                "final_score": verdict.final_score if verdict else 0.0,
                "classification": verdict.classification if verdict else None,
            }
            for scan, verdict, email in members
        ],
    }


# ── Case management (plan §5 B4 — status/notes update) ──────────────────

CAMPAIGN_STATUSES = {"open", "new", "investigating", "closed"}


class CampaignUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None


@router.patch("/campaigns/{campaign_id}")
async def update_campaign(
    campaign_id: int,
    payload: CampaignUpdate,
    db: Session = Depends(get_db),
):
    """Update analyst-managed campaign fields: status + notes (B4).

    `status` is validated against the workflow set; `open` remains the
    default so existing filters keep working.
    """
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if payload.status is not None:
        if payload.status not in CAMPAIGN_STATUSES:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid status '{payload.status}' — expected one of "
                    f"{sorted(CAMPAIGN_STATUSES)}"
                ),
            )
        campaign.status = payload.status
    if payload.notes is not None:
        campaign.notes = payload.notes[:4000]

    db.commit()
    db.refresh(campaign)
    return {"campaign": campaign.to_dict()}


# ── Domain intelligence (plan §5 B1) ─────────────────────────────────────


@router.get("/domains/{domain}/intel")
async def get_domain_intel(
    domain: str,
    dns: Optional[bool] = None,
    rdap: Optional[bool] = None,
):
    """DNS posture + RDAP registration age for one sending domain (B1).

    Lookups default to the `DOMAIN_INTEL_*_ENABLED` settings (offline in
    tests/demos) and can be overridden per request with `?dns=`/`?rdap=`.
    Failures degrade to `null` fields + `errors` — never a 500.
    """
    from app.config import get_settings
    from app.engines.intel.domain_intel import assess_domain, is_valid_domain

    if not is_valid_domain(domain):
        raise HTTPException(status_code=422, detail="Invalid domain name")

    settings = get_settings()
    use_dns = settings.DOMAIN_INTEL_DNS_ENABLED if dns is None else dns
    use_rdap = settings.DOMAIN_INTEL_RDAP_ENABLED if rdap is None else rdap

    intel = assess_domain(domain, use_dns=use_dns, use_rdap=use_rdap)
    payload = intel.to_dict()
    payload["lookups"] = {"dns": use_dns, "rdap": use_rdap}
    return payload
