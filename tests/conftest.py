"""Shared test bootstrap.

Settings are lru-cached at first use and every test module imports the
app during collection, so env overrides must happen here — conftest.py
is imported before any test module.
"""

import os

# Trace endpoints queue background IP enrichment by default; unit tests
# run offline against SQLite and must not spawn background sessions
# bound to the real (postgres) SessionLocal. Tests that want the
# behaviour patch `app.api.intel.get_settings`.
os.environ.setdefault("IP_INTEL_AUTO_ENRICH", "false")


# ── Tenancy helpers (P2 row-level isolation) ──────────────────────────
TEST_USER_ID = 10001


def ensure_test_user(session, user_id: int = TEST_USER_ID, role: str = "admin"):
    """Create (once) the user row that get_current_user resolves to in tests."""
    from app.models.user import User

    user = session.get(User, user_id)
    if user is None:
        user = User(
            id=user_id,
            google_sub=f"test-sub-{user_id}",
            email="tester@phishing-guard.test",
            name="Tester",
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


def override_auth(app, user):
    """Make every get_current_user dependency return `user`."""
    from app.dependencies import get_current_user

    app.dependency_overrides[get_current_user] = lambda: user
