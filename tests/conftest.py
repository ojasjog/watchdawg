"""
Safety net: point every module at a throwaway database BEFORE anything imports `config`,
so no test can ever read from or write to your real watchdog.db (which holds lab evidence).
Importing `app` initialises the database at import time, which is how this was caught.
"""

import os
import tempfile

_TEST_DB_DIR = tempfile.mkdtemp(prefix="watchdog-tests-")
os.environ["WATCHDOG_DB"] = os.path.join(_TEST_DB_DIR, "import-time.db")
os.environ.pop("WATCHDOG_PSK", None)          # tests must not depend on the developer's key


def pytest_sessionstart(session):
    import config
    real = str(config.BASE_DIR / "watchdog.db")
    assert os.path.abspath(config.DB_PATH) != os.path.abspath(real), \
        "tests are pointed at the real watchdog.db; refusing to run"
