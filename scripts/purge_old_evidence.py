#!/usr/bin/env python3
"""CLI: enforce RETENTION_DAYS on evidence artifacts.

Usage:
    python scripts/purge_old_evidence.py                # normal purge
    python scripts/purge_old_evidence.py --dry-run      # report only
    python scripts/purge_old_evidence.py --retention-days 30
    python scripts/purge_old_evidence.py --include-verdicts  # DANGEROUS
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.dependencies import SessionLocal  # noqa: E402
from app.services.retention import purge  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be deleted, delete nothing")
    parser.add_argument("--retention-days", type=int, default=None,
                        help="override settings.RETENTION_DAYS")
    parser.add_argument("--include-verdicts", action="store_true",
                        help="ALSO delete verdict rows for aged emails "
                             "(off by default; verdicts are the analytical "
                             "record)")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        summary = purge(
            db,
            retention_days=args.retention_days,
            dry_run=args.dry_run,
            include_verdicts=args.include_verdicts,
        )
        print(json.dumps(summary, indent=2))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
