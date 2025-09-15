from modules.history_logger import log_scan_history, load_scan_history_db

def test_log_and_load_scan_history(tmp_path, monkeypatch):
    # Minimal synthetic results
    results = [
        {"column": "email", "pattern": "email", "matches_found": 2},
        {"column": "phone", "pattern": "phone", "matches_found": 1},
    ]
    score = 85
    violations = ["Too many PII fields"]
    source = "test.csv"

    anon_report = {
        "total_pii_values": 3,
        "anonymized_count": 2,
        "anonymization_rate": 66.7,
        "verification_passed": False,
    }

    # Derive PII type summaries for history
    pii_types_regex = ",".join(sorted({r["pattern"] for r in results}))
    pii_types_nlp = ""  # not using NLP in this unit test

    # The updated signature (pass all required fields)
    log_scan_history(
        results,
        score,
        violations,
        source,
        pii_types_regex=pii_types_regex,
        pii_types_nlp=pii_types_nlp,
        total_pii_values=anon_report["total_pii_values"],
        anonymized_count=anon_report["anonymized_count"],
        anonymization_rate=anon_report["anonymization_rate"],
        verification_passed=anon_report["verification_passed"],
    )

    df = load_scan_history_db()
    assert not df.empty
    assert "source" in df.columns
    assert "compliance_score" in df.columns
    assert "violations" in df.columns
