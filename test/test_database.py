import modules.database as database

def _setup_db(tmp_path, monkeypatch):
    db = tmp_path / "test_privacy_checker.db"
    monkeypatch.setattr(database, "DB_PATH", str(db))
    database.init_db()
    return db

def test_scan_insertion(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    scan_id = database.log_scan("test.csv", 85.5, "No violations", None)
    assert isinstance(scan_id, int) and scan_id > 0

    scans_df = database.fetch_scans()
    assert not scans_df.empty
    assert scans_df.iloc[0]["file_name"] == "test.csv"

def test_finding_insertion(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    scan_id = database.log_scan("file.csv", 90.0, "None", None)
    database.log_finding(scan_id, "email", "email", "alice@example.com")
    rows = database.fetch_findings(scan_id)
    assert len(rows) == 1
    col, ptype, sample = rows[0]
    assert col == "email" and ptype == "email"

def test_event_insertion(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    scan_id = database.log_scan("file.csv", 90.0, "None", None)
    database.log_event(scan_id, "export", "CSV exported")
    rows = database.fetch_events(scan_id)
    assert len(rows) == 1
    etype, desc = rows[0]
    assert etype == "export" and "CSV" in desc
