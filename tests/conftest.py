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
