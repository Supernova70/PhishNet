"""Backfill helpers (plan §4, B6) — target selection, no IMAP required."""

import importlib.util
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.models.email import Email
from app.models.email_source import EmailSource

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "backfill_raw_email.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("backfill_raw_email", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/backfill.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _email(db, mid):
    email = Email(
        message_id=mid,
        sender="a@example.com",
        subject="s",
        body_text="x",
        fetched_at=datetime(2026, 1, 1, 12, 0),
    )
    db.add(email)
    db.flush()
    return email


class TestNormalizeMessageId:
    def test_adds_brackets(self, mod):
        assert mod._normalize_message_id("abc@example.com") == "<abc@example.com>"

    def test_keeps_existing_brackets(self, mod):
        assert mod._normalize_message_id("<abc@example.com>") == "<abc@example.com>"

    def test_empty(self, mod):
        assert mod._normalize_message_id("") == ""
        assert mod._normalize_message_id(None) == ""


class TestHeadersMap:
    def test_lowercase_keys_and_repeats_preserved(self, mod):
        from email import policy
        from email.parser import BytesParser

        raw = (
            b"From: a@example.com\r\n"
            b"Received: hop2\r\n"
            b"Received: hop1\r\n"
            b"\r\n"
            b"body\r\n"
        )
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        headers = mod._headers_map(parsed)
        assert headers["from"] == ["a@example.com"]
        assert headers["received"] == ["hop2", "hop1"]


class TestTargets:
    def test_selects_only_emails_missing_raw_evidence(self, mod, db):
        no_source = _email(db, "<one@x>")
        with_source = _email(db, "<two@x>")
        db.add(
            EmailSource(
                email_id=with_source.id,
                raw_path="/tmp/two.eml.gz",
                raw_sha256="a" * 64,
                size_bytes=100,
            )
        )
        shaless = _email(db, "<three@x>")
        db.add(
            EmailSource(
                email_id=shaless.id,
                raw_path=None,
                raw_sha256=None,
                size_bytes=0,
            )
        )
        db.commit()

        ids = {e.id for e in mod._targets(db, None, [])}
        assert ids == {no_source.id, shaless.id}

    def test_limit_and_id_filter(self, mod, db):
        first = _email(db, "<first@x>")
        second = _email(db, "<second@x>")
        db.commit()

        limited = mod._targets(db, 1, [])
        assert [e.id for e in limited] == [first.id]

        only_second = mod._targets(db, None, [second.id])
        assert [e.id for e in only_second] == [second.id]
