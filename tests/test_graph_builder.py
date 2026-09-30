"""Attribition graph builder (pure, offline)."""

from app.engines.correlation.graph_builder import build_graph


def _email(id, score, **kw):
    base = {
        "id": id,
        "subject": f"Subject {id}",
        "score": score,
        "sender_domain": None,
        "replyto_domain": None,
        "origin_ip": None,
        "url_domains": [],
        "hashes": [],
        "lookalike_brand": None,
        "campaign_id": None,
    }
    base.update(kw)
    return base


class TestBuildGraph:
    def test_basic_email_nodes_and_edges(self):
        graph = build_graph([
            _email(
                1, 90.0,
                sender_domain="paypa1.com",
                origin_ip="203.0.113.50",
                url_domains=["evil.example"],
            )
        ])
        node_ids = {n["id"] for n in graph["nodes"]}
        assert "email:1" in node_ids
        assert "domain:paypa1.com" in node_ids
        assert "ip:203.0.113.50" in node_ids
        assert "domain:evil.example" in node_ids

        rels = {(e["source"], e["target"], e["relation"]) for e in graph["edges"]}
        assert ("email:1", "domain:paypa1.com", "sent_from") in rels
        assert ("email:1", "ip:203.0.113.50", "originated_from") in rels
        assert ("email:1", "domain:evil.example", "links_to") in rels

    def test_ioc_risk_is_max_of_attached_emails(self):
        graph = build_graph([
            _email(1, 40.0, origin_ip="203.0.113.50"),
            _email(2, 95.0, origin_ip="203.0.113.50"),
        ])
        ip_node = next(n for n in graph["nodes"] if n["id"] == "ip:203.0.113.50")
        assert ip_node["risk"] == 95.0

    def test_email_node_label_is_subject(self):
        graph = build_graph([_email(7, 10.0, subject="Quarterly invoice")])
        email_node = next(n for n in graph["nodes"] if n["id"] == "email:7")
        assert email_node["label"] == "Quarterly invoice"
        assert email_node["type"] == "email"

    def test_shared_ioc_links_two_emails(self):
        graph = build_graph([
            _email(1, 80.0, origin_ip="203.0.113.50"),
            _email(2, 60.0, origin_ip="203.0.113.50"),
        ])
        node_ids = [n["id"] for n in graph["nodes"]]
        assert node_ids.count("ip:203.0.113.50") == 1  # shared node, not duplicated
        ip_edges = [
            e for e in graph["edges"]
            if e["target"] == "ip:203.0.113.50" and e["relation"] == "originated_from"
        ]
        assert len(ip_edges) == 2  # both emails point at the shared IP

    def test_node_cap_prefers_highest_risk(self):
        emails = [_email(i, float(i), origin_ip=f"203.0.113.{i}") for i in range(1, 11)]
        graph = build_graph(emails, limit=5)
        email_nodes = [n for n in graph["nodes"] if n["type"] == "email"]
        assert len(graph["nodes"]) <= 5
        # riskiest emails survive the cap (IP node of #8 dropped to fit)
        assert {n["label"] for n in email_nodes} == {
            "Subject 10", "Subject 9", "Subject 8",
        }

    def test_hashes_brands_campaigns(self):
        graph = build_graph([
            _email(
                1, 85.0,
                hashes=["a" * 64],
                lookalike_brand="paypal",
                campaign_id=3,
            )
        ])
        node_ids = {n["id"] for n in graph["nodes"]}
        assert "hash:" + "a" * 64 in node_ids
        assert "brand:paypal" in node_ids
        assert "campaign:3" in node_ids
        rels = {e["relation"] for e in graph["edges"]}
        assert "impersonates" in rels
        assert "same_campaign" in rels

    def test_campaign_labels_applied(self):
        graph = build_graph(
            [_email(1, 50.0, campaign_id=3)],
            campaigns=[{"id": 3, "name": "paypal impersonation"}],
        )
        camp = next(n for n in graph["nodes"] if n["id"] == "campaign:3")
        assert camp["label"] == "paypal impersonation"

    def test_replyto_edge(self):
        graph = build_graph([
            _email(1, 50.0, replyto_domain="attacker.example")
        ])
        rels = {(e["source"], e["target"], e["relation"]) for e in graph["edges"]}
        assert ("email:1", "domain:attacker.example", "replies_to") in rels

    def test_empty_input(self):
        assert build_graph([]) == {"nodes": [], "edges": []}
