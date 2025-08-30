import os
import pandas as pd
import pytest
from modules.history_logger import log_scan_history, load_scan_history

HISTORY_FILE = "output/scan_history.csv"

@pytest.fixture(autouse=True)
def cleanup_history():
    """Remove history file before and after tests to isolate runs."""
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    yield
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)

def test_log_and_load_scan_history():
    results = [{"column": "email", "pattern": "email", "matches_found": 2}]
    score = 85
    violations = ["Too many PII fields"]
    source = "test.csv"
    anon_report = {
        "total_pii_values": 2,
        "anonymized_count": 2,
        "anonymization_rate": 100.0,
        "verification_passed": True
    }

    # Log entry
    log_scan_history(results, score, violations, source, anon_report)

    # Load back
    df = load_scan_history()
    assert not df.empty
    assert df.iloc[0]["source"] == "test.csv"
    assert df.iloc[0]["compliance_score"] == 85
    assert "Too many PII fields" in df.iloc[0]["violations"]
    assert df.iloc[0]["anonymization_rate"] == 100.0
