"""Attribution graph — nodes/edges for the UI's force-directed view.

Output contract (per plan):
    {"nodes": [{"id","type","label","risk"}],
     "edges": [{"source","target","relation"}]}

Node types: email | domain | ip | hash | brand | campaign
(`brand` extends the plan's vocabulary — lookalike brands are first-class
nodes so shared-brand campaigns stay connected.)

Node risk on IOC nodes is the maximum risk of the emails attached to
them; emails are included highest-risk-first up to `limit` nodes
(server-side degree cap, plan: 500).

Implemented with plain dicts instead of networkx: the API only needs
JSON nodes/edges, and avoiding the dependency keeps the offline demo
install light.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

DEFAULT_NODE_LIMIT = 500


def _node(nodes: dict, node_id: str, ntype: str, label: str, risk: float) -> None:
    existing = nodes.get(node_id)
    if existing is None:
        nodes[node_id] = {
            "id": node_id,
            "type": ntype,
            "label": label,
            "risk": round(risk, 1),
        }
    else:
        existing["risk"] = max(existing["risk"], round(risk, 1))


def build_graph(
    emails: Sequence[dict],
    campaigns: Optional[Sequence[dict]] = None,
    limit: int = DEFAULT_NODE_LIMIT,
) -> dict:
    """
    Build graph JSON from plain email dicts:

        {id, subject, score, sender_domain, replyto_domain, origin_ip,
         url_domains, hashes, lookalike_brand, campaign_id}
    """
    nodes: Dict[str, dict] = {}
    edge_keys: set = set()
    edges_out: List[dict] = []

    def add_edge(source: str, target: str, relation: str) -> None:
        key = (source, target, relation)
        if key not in edge_keys:
            edge_keys.add(key)
            edges_out.append(
                {"source": source, "target": target, "relation": relation}
            )

    ordered = sorted(emails, key=lambda e: e.get("score", 0.0), reverse=True)

    def fits(extra: int = 1) -> bool:
        return len(nodes) + extra <= limit

    for email in ordered:
        if not fits():
            break
        eid = f"email:{email['id']}"
        score = float(email.get("score") or 0.0)
        _node(
            nodes, eid, "email",
            str(email.get("subject") or f"email #{email['id']}"),
            score,
        )

        def link_domain(domain: Optional[str], relation: str) -> None:
            if not domain or not fits():
                return
            did = f"domain:{domain}"
            _node(nodes, did, "domain", domain, score)
            add_edge(eid, did, relation)

        link_domain(email.get("sender_domain"), "sent_from")
        link_domain(email.get("replyto_domain"), "replies_to")
        for reg in email.get("url_domains") or []:
            link_domain(reg, "links_to")

        origin_ip = email.get("origin_ip")
        if origin_ip and fits():
            ipid = f"ip:{origin_ip}"
            _node(nodes, ipid, "ip", origin_ip, score)
            add_edge(eid, ipid, "originated_from")

        for sha in email.get("hashes") or []:
            if not fits():
                break
            hid = f"hash:{sha}"
            _node(nodes, hid, "hash", sha[:16], score)
            add_edge(eid, hid, "has_attachment")

        brand = email.get("lookalike_brand")
        if brand and fits():
            bid = f"brand:{brand}"
            _node(nodes, bid, "brand", brand, score)
            add_edge(eid, bid, "impersonates")

        campaign_id = email.get("campaign_id")
        if campaign_id and fits():
            cid = f"campaign:{campaign_id}"
            _node(nodes, cid, "campaign", f"campaign #{campaign_id}", score)
            add_edge(eid, cid, "same_campaign")

    # Campaign metadata nodes (label/status) when provided
    for camp in campaigns or []:
        cid = f"campaign:{camp['id']}"
        if cid in nodes:
            nodes[cid]["label"] = str(camp.get("name") or cid)

    return {"nodes": list(nodes.values()), "edges": edges_out}


def build_graph_from_db(
    db,
    min_score: float = 0.0,
    campaign_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    limit: int = DEFAULT_NODE_LIMIT,
) -> dict:
    """DB-backed wrapper: loads scans + verdicts + indicators, delegates."""
    from app.models.email import Email
    from app.models.indicator import Indicator
    from app.models.scan import Scan, Verdict

    rows = (
        db.query(Scan, Verdict, Email)
        .join(Verdict, Verdict.scan_id == Scan.id)
        .join(Email, Email.id == Scan.email_id)
        .filter(Verdict.final_score >= min_score)
    )
    if campaign_id is not None:
        rows = rows.filter(Scan.campaign_id == campaign_id)
    if scan_id is not None:
        rows = rows.filter(Scan.id == scan_id)
    scans = rows.order_by(Verdict.final_score.desc()).limit(limit).all()

    emails: List[dict] = []
    for scan, verdict, email in scans:
        indicators = (
            db.query(Indicator).filter(Indicator.scan_id == scan.id).all()
        )
        by_type: Dict[str, List[str]] = {}
        for ind in indicators:
            by_type.setdefault(ind.type, []).append(ind.value)
        emails.append(
            {
                "id": scan.id,
                "subject": email.subject,
                "score": verdict.final_score,
                "sender_domain": (by_type.get("sender_domain") or [None])[0],
                "replyto_domain": (by_type.get("replyto_domain") or [None])[0],
                "origin_ip": (by_type.get("origin_ip") or [None])[0],
                "url_domains": by_type.get("url_domain") or [],
                "hashes": by_type.get("attachment_hash") or [],
                "lookalike_brand": (by_type.get("lookalike_brand") or [None])[0],
                "campaign_id": scan.campaign_id,
            }
        )
    return build_graph(emails, limit=limit)
