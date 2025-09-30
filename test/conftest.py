import os
import pytest
import modules.database as database

TEST_DB = "test_privacy_checker.db"

@pytest.fixture(autouse=True)
def setup_and_teardown():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    database.DB_PATH = TEST_DB
    database.init_db()
    yield
    # ensure DB file is closed before removal
    try:
        os.remove(TEST_DB)
    except PermissionError:
        pass
