#!/usr/bin/env python3
"""Import .eml files into the database (demo corpus / offline ingestion).

Usage:
    python scripts/import_eml.py tests/fixtures/eml
    python scripts/import_eml.py path/to/mbox-dir --limit 10
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.dependencies import SessionLocal  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.email_service import EmailService  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="Directory containing .eml files")
    parser.add_argument("--limit", type=int, default=None,
                        help="Import at most N files")
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"error: {directory} is not a directory", file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        # Tenancy: imported rows belong to the first admin (or first user),
        # so they show up in that account's inbox rather than nowhere.
        owner = (
            db.query(User).filter(User.role == "admin").order_by(User.id).first()
            or db.query(User).order_by(User.id).first()
        )
        if owner is None:
            print("error: no users in DB — sign in via Google once first",
                  file=sys.stderr)
            return 2

        if args.limit:
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as tmp:
                for i, f in enumerate(sorted(directory.glob("*.eml"))):
                    if i >= args.limit:
                        break
                    (Path(tmp) / f.name).symlink_to(f.resolve())
                summary = EmailService(db, user_id=owner.id).import_eml_files(tmp)
        else:
            summary = EmailService(db, user_id=owner.id).import_eml_files(str(directory))
        print(json.dumps(summary, indent=2))
        return 1 if summary["failed"] else 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
