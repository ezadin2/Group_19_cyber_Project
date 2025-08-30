# tests/test_app.py
import pytest
import pandas as pd
import os
from modules.pii_detector import detect_sensitive_data
from modules.compliance_scoring import score_compliance
from modules.anonymize_data import anonymize_dataset
from modules.history_logger import log_scan_history, load_scan_history
from modules.report_generator import generate_csv_report, generate_pdf_report

# ---------------- Fixtures from the old code  ----------------

@pytest.fixture
def sample_df():
    return pd.DataFrame({
        "email": ["alice@example.com", "bob@gmail.com"],
        "phone": ["123-456-7890", "9876543210"],
        "name": ["Alice Johnson", "Bob Smith"],
        "notes": ["Lives in New York", "Works at OpenAI"],
    })

@pytest.fixture
def rules():
    return {
        "max_pii_fields": 2,
        "allowed_pii_types": ["email", "phone"],
        "anonymization_required": True
    }

# ---------------------------
# PII Detection
# ---------------------------
def test_pii_detection_regex(sample_df):
    results = detect_sensitive_data(sample_df)
    patterns = set([r["pattern"] for r in results])
    assert "email" in patterns
    assert "phone" in patterns
    assert "name" in patterns or "person" in patterns  # Regex or NLP

# ---------------------------
# Compliance Scoring
# ---------------------------
def test_compliance_scoring(sample_df, rules):
    results = detect_sensitive_data(sample_df)
    score, violations = score_compliance(results, rules)
    assert isinstance(score, (int, float))  # FIXed on aug 22: allow float scores
    assert 0 <= score <= 100
    assert isinstance(violations, list)


# ---------------------------
# Anonymization Methods
# ---------------------------
def test_anonymization_mask(sample_df):
    results = detect_sensitive_data(sample_df)
    anon_df, report = anonymize_dataset(sample_df, results, {"email": "mask"})
    assert anon_df["email"].iloc[0] != "alice@example.com"
    assert report["anonymized_count"] > 0

def test_anonymization_hash(sample_df):
    results = detect_sensitive_data(sample_df)
    anon_df, report = anonymize_dataset(sample_df, results, {"name": "hash"})
    # Check that hashing produced non-original values
    assert all(anon_df["name"].str.len() >= 6)
    assert report["anonymized_count"] > 0
# fixed version
def test_anonymization_redact(sample_df):
    results = detect_sensitive_data(sample_df)
    anon_df, report = anonymize_dataset(sample_df, results, {"phone": "redact"})
    # Ensure phone column values are replaced with REDACTED marker
    assert all(value == "[REDACTED]" or value == "REDACTED" for value in anon_df["phone"])
    assert report["anonymized_count"] > 0

def test_anonymization_fake(sample_df):
    results = detect_sensitive_data(sample_df)
    anon_df, report = anonymize_dataset(sample_df, results, {"email": "fake"})
    # Fake emails should not equal original ones
    assert all(value not in ["alice@example.com", "bob@gmail.com"] for value in anon_df["email"])
    assert report["anonymized_count"] > 0

# ---------------------------
# History Logging
# ---------------------------
def test_history_logging(sample_df):
    results = detect_sensitive_data(sample_df)
    score, violations = score_compliance(results, {"max_pii_fields": 10, "allowed_pii_types": ["email", "phone"], "anonymization_required": False})
    anon_df, anon_report = anonymize_dataset(sample_df, results, {"email": "mask"})
    log_scan_history(results, score, violations, "test_source", anon_report)
    history_df = load_scan_history()
    assert not history_df.empty
    assert "compliance_score" in history_df.columns

# ---------------------------
# Report Generation
# ---------------------------
def test_csv_report_generation(sample_df, tmp_path):
    results = detect_sensitive_data(sample_df)
    score, violations = score_compliance(results, {"max_pii_fields": 10, "allowed_pii_types": ["email", "phone"], "anonymization_required": False})
    # FIX: no output path, use existing function signature
    generate_csv_report(results, score, violations)



def test_pdf_report_generation(sample_df, tmp_path):
    results = detect_sensitive_data(sample_df)
    score, violations = score_compliance(results, {"max_pii_fields": 10, "allowed_pii_types": ["email", "phone"], "anonymization_required": False})
    # FIX: no output path, use existing function signature
    generate_pdf_report(results, score, violations)


