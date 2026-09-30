"""Offline FP/FN evaluation over labeled .eml directories.

Runs the real production pipeline (ScanService.run_scan_by_id) on every
email with network lookups disabled (no VT / no DNS checks / no dynamic
browsing), then scores classifications against filename-derived ground
truth:

    clean_*            → must be safe   (a hit here is a FALSE POSITIVE)
    everything else    → must be flagged (≥30; a miss is a FALSE NEGATIVE)
    --safe-dir emails  → every email is legitimately safe (real mailbox)

Usage:
    python scripts/eval_corpus.py
    python scripts/eval_corpus.py --safe-dir /path/to/real_mailbox_emls

Environment is forced to an offline configuration before app imports.
"""

from __future__ import annotations

import argparse
import os
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

# Offline, deterministic configuration — must precede app imports.
os.environ.setdefault("MODEL_PATH", "data/phishing_model.joblib")
os.environ["VIRUSTOTAL_API_KEYS"] = ""
os.environ["DYNAMIC_URL_ENABLED"] = "false"
os.environ["HEADER_DNS_CHECKS_ENABLED"] = "false"
os.environ["DNSBL_ENABLED"] = "false"
os.environ["PRESERVE_RAW_EMAIL"] = "true"
os.environ["ATTACHMENT_DIR"] = "/tmp/opencode/eval/uploads"
os.environ["RAW_EMAIL_DIR"] = "/tmp/opencode/eval/raw"
os.environ["DATABASE_URL"] = "sqlite:////tmp/opencode/eval.db"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import app.services.email_service as email_service_mod  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.models import Base  # noqa: E402
from app.models.email import Email  # noqa: E402
from app.models.scan import Scan, Verdict  # noqa: E402
from app.services.email_service import EmailService  # noqa: E402
from app.services.scan_service import ScanService  # noqa: E402

CORPUS_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "eml"


def expected_for(stem: str, all_safe: bool) -> str:
    if all_safe or stem.startswith("clean_"):
        return "safe"
    return "phish"


def import_dir(db, directory: Path, all_safe: bool) -> dict[int, str]:
    """Import an .eml directory; return {email_id: expected_label}.

    Ground truth comes from each file's name, joined onto imported rows
    via Message-ID (import itself never stores the file name).

    safe directories (--safe-dir, real mailbox) are imported WITHOUT
    email-source/header rows — the real inbox was fetched before raw
    retention existed, so prod scans those emails with header_score=0.
    Importing their synthesized minimal headers would fabricate a signal
    prod does not have.
    """
    msg_labels: dict[str, str] = {}
    for path in sorted(Path(directory).glob("*.eml")):
        msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        mid = str(msg.get("Message-ID", "")).strip().strip("<>")
        if mid:
            msg_labels[mid] = expected_for(path.stem, all_safe)

    settings = get_settings()
    stub = type("SettingsStub", (), {})()
    stub.PRESERVE_RAW_EMAIL = settings.PRESERVE_RAW_EMAIL
    stub.ATTACHMENT_DIR = settings.ATTACHMENT_DIR
    stub.raw_email_dir = settings.raw_email_dir
    original = email_service_mod.settings
    email_service_mod.settings = stub
    original_src = EmailService._store_email_source
    if all_safe:
        EmailService._store_email_source = lambda self, *a, **k: None
    try:
        EmailService(db).import_eml_files(str(directory))
    finally:
        email_service_mod.settings = original
        EmailService._store_email_source = original_src

    labels: dict[int, str] = {}
    for email in db.query(Email).all():
        mid = (email.message_id or "").strip().strip("<>")
        if mid in msg_labels:
            labels[email.id] = msg_labels[mid]
        elif not all_safe:
            print(f"  !! no ground truth for email {email.id}: {email.subject!r}")
    return labels


def _detail(b: dict, v) -> list[str]:
    """Component breakdown + top flags for a misclassified email."""
    ai = b.get("ai", {})
    url = b.get("url", {})
    att = b.get("attachment", {})
    hdr = b.get("header", {})
    lines = [
        f"ai={ai.get('score', 0):.1f} (ml={ai.get('ml_score', 0):.1f} "
        f"bec={ai.get('bec', {}).get('bec_score', 0):.1f} "
        f"lk={ai.get('lookalike', {}).get('score', 0):.1f} "
        f"lk_matches={ai.get('lookalike', {}).get('matches', [])})",
        f"url={v.url_score:.1f} att={v.attachment_score:.1f} "
        f"hdr={v.header_score:.1f}",
    ]
    for u in (url.get("per_url") or []):
        if u.get("score", 0) >= 15:
            lines.append(f"  url[{u['score']:.0f}] {u['url'][:100]}")
            for f in (u.get("top_flags") or [])[:5]:
                lines.append(f"     - {f}")
    for f in (att.get("per_file") or []):
        if isinstance(f, dict) and (f.get("risk_score") or 0) >= 20:
            lines.append(f"  att[{f.get('risk_score'):.0f}] {f.get('filename', '')[:70]}")
            for finding in (f.get("findings") or [])[:5]:
                lines.append(f"     - {finding}")
        elif not isinstance(f, dict) and getattr(f, "risk_score", 0) >= 20:
            lines.append(f"  att[{f.risk_score:.0f}] {getattr(f, 'filename', '')[:70]} "
                         f"{getattr(f, 'findings', [])[:5]}")
    lines.append(f"  hdr_flags={hdr.get('flags', [])}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline FP/FN evaluation")
    parser.add_argument("--safe-dir", action="append", default=[],
                        help="Directory of .eml files that are ALL legitimate (repeatable)")
    parser.add_argument("--corpus", default=str(CORPUS_DIR),
                        help="Labeled fixture corpus directory")
    args = parser.parse_args()

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    labels: dict[int, str] = {}
    labels.update(import_dir(db, Path(args.corpus), all_safe=False))
    for d in args.safe_dir:
        labels.update(import_dir(db, Path(d), all_safe=True))

    rows = []
    fp = fn = tp = tn = errors = 0
    for email_id, expected in sorted(labels.items()):
        email = db.query(Email).get(email_id)
        scan = Scan(email_id=email_id, status="pending")
        db.add(scan)
        db.commit()
        try:
            scan = ScanService(db).run_scan_by_id(scan.id)
        except Exception as exc:  # pipeline must never abort the eval
            print(f"  !! scan failed for email {email_id}: {exc}")
            db.rollback()
            errors += 1
            continue
        v = db.query(Verdict).filter(Verdict.scan_id == scan.id).first()
        if v is None:
            print(f"  !! no verdict for email {email_id}")
            errors += 1
            continue
        got = v.classification
        flagged = got != "safe"
        if expected == "safe" and flagged:
            fp += 1
            mark = "FP"
        elif expected == "phish" and not flagged:
            fn += 1
            mark = "FN"
        elif expected == "phish" and flagged:
            tp += 1
            mark = "ok"
        else:
            tn += 1
            mark = "ok"
        b = v.breakdown or {}
        ai = b.get("ai", {})
        lk = ai.get("lookalike", {})
        drivers = []
        if lk.get("score", 0) > 30:
            drivers.append(f"lookalike={lk['score']:.0f}")
        if ai.get("bec", {}).get("bec_score", 0) > 30:
            drivers.append(f"bec={ai['bec']['bec_score']:.0f}")
        if v.url_score >= 20:
            drivers.append(f"url={v.url_score:.0f}")
        if v.header_score >= 20:
            drivers.append(f"hdr={v.header_score:.0f}")
        if v.attachment_score >= 20:
            drivers.append(f"att={v.attachment_score:.0f}")
        rows.append((mark, email_id, expected, got, v.final_score,
                     " ".join(drivers) or "-", (email.subject or "")[:38],
                     _detail(b, v) if mark in ("FP", "FN") else ""))

    print(f"\n{'mark':<4} {'id':>3} {'expect':<6} {'got':<10} {'score':>6}  "
          f"{'drivers':<30} subject")
    for mark, eid, exp, got, score, drivers, subj, detail in rows:
        print(f"{mark:<4} {eid:>3} {exp:<6} {got:<10} {score:>6.1f}  "
              f"{drivers:<30} {subj}")
        for line in detail:
            print(f"       {line}")

    print(f"\nFP (safe flagged): {fp}   FN (phish missed): {fn}   "
          f"TP: {tp}   TN: {tn}   errors: {errors}")
    if fp or fn or errors:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
