import pandas as pd
import modules.database as database
from modules.pii_detector import detect_sensitive_data

def test_scan_workflow(tmp_path, monkeypatch):
    # Use an isolated test DB
    test_db = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", str(test_db))
    database.init_db()

    # Simulate a dataset
    df = pd.DataFrame({
        "email": ["bob@example.com", "carol@test.org"],
        "phone": ["123-456-7890", "999-888-7777"]
    })

    # Run detection (sanity)
    results = detect_sensitive_data(df)
    assert isinstance(results, list)
    assert any(r["pattern"] == "email" for r in results)

    # Log scan
    anon_report = {
        "total_pii_values": sum(r.get("matches_found", 0) for r in results),
        "anonymized_count": 0,
        "anonymization_rate": 0.0,
        "verification_passed": False
    }
    scan_id = database.log_scan("test.csv", 92.0, "None", anon_report)
    assert isinstance(scan_id, int) and scan_id > 0

    # Log a couple of findings
    for r in results[:2]:
        database.log_finding(scan_id, r.get("column", "unknown"), r.get("pattern", "unknown"), "sample")

    # Log an event
    database.log_event(scan_id, "scan", "Scan completed")

    # Verify
    scans_df = database.fetch_scans()
    assert not scans_df.empty
    row = scans_df.iloc[0]
    assert row["file_name"] == "test.csv"
    assert float(row["score"]) == 92.0
