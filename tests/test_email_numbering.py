"""Per-account email numbers — global Email.id interleaves accounts.

Emails are created interleaved between two users so their raw ids overlap
(A owns ids 1,3,5; B owns 2,4). Every user-facing "#N" must be the rank
within the account (oldest = #1), never the raw global id.
"""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.router import api_router
from app.auth.session import COOKIE_NAME, create_session_token
from app.dependencies import get_db
from app.models import Base
from app.models.email import Email
from app.models.scan import Scan
from app.models.user import User


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/numbering.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    user_a = User(id=1, google_sub="sub-a", email="a@example.com",
                  name="A", role="admin")
    user_b = User(id=2, google_sub="sub-b", email="b@example.com",
                  name="B", role="user")
    session.add_all([user_a, user_b])
    session.commit()

    # Interleave A,B,A,B,A → global ids 1..5; A owns 1,3,5 and B owns 2,4.
    ids = {"a": [], "b": []}
    for hour, owner in enumerate(["a", "b", "a", "b", "a"], start=1):
        email = Email(
            user_id=1 if owner == "a" else 2,
            message_id=f"<{owner}{hour}@x.test>",
            sender=f"sender{hour}@x.test",
            subject=f"mail {hour}",
            body_text="body",
            fetched_at=datetime(2026, 1, 1, hour, 0),
        )
        session.add(email)
        session.flush()
        ids[owner].append(email.id)

    # One scan each, on each user's newest email.
    for owner in ("a", "b"):
        session.add(Scan(
            user_id=1 if owner == "a" else 2,
            email_id=ids[owner][-1],
            status="complete",
        ))
    session.commit()

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_db] = lambda: session

    clients = {}
    for tag, user in (("a", user_a), ("b", user_b)):
        client = TestClient(app)
        client.cookies.set(COOKIE_NAME, create_session_token(user))
        clients[tag] = client

    return {"clients": clients, "ids": ids}


def test_email_list_numbers_are_per_account(env):
    # Inbox lists newest first (fetched_at desc) → A: 3,2,1 then B: 2,1.
    rows_a = env["clients"]["a"].get("/emails").json()["emails"]
    assert [r["number"] for r in rows_a] == [3, 2, 1]
    assert [r["id"] for r in rows_a] == list(reversed(env["ids"]["a"]))

    rows_b = env["clients"]["b"].get("/emails").json()["emails"]
    assert [r["number"] for r in rows_b] == [2, 1]
    assert [r["id"] for r in rows_b] == list(reversed(env["ids"]["b"]))


def test_scan_lists_carry_email_number(env):
    data_a = env["clients"]["a"].get("/scans").json()
    assert data_a["total"] == 1
    scan_a = data_a["scans"][0]
    assert scan_a["email_id"] == env["ids"]["a"][-1]
    assert scan_a["email_number"] == 3
    assert scan_a["email_subject"] == "mail 5"

    data_b = env["clients"]["b"].get("/scans").json()
    scan_b = data_b["scans"][0]
    assert scan_b["email_id"] == env["ids"]["b"][-1]
    assert scan_b["email_number"] == 2
    assert scan_b["email_subject"] == "mail 4"


def test_email_detail_carries_number(env):
    email_id = env["ids"]["a"][-1]
    detail = env["clients"]["a"].get(f"/emails/{email_id}").json()
    assert detail["number"] == 3
    # Tenancy still holds: the other account gets 404, not a leaked number.
    assert env["clients"]["b"].get(f"/emails/{email_id}").status_code == 404


def test_single_scan_endpoint_carries_email_number(env):
    data = env["clients"]["a"].get("/scans").json()
    scan_id = data["scans"][0]["id"]
    scan = env["clients"]["a"].get(f"/scans/{scan_id}").json()
    assert scan["email_number"] == 3
