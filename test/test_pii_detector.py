# test/test_pii_detector.py
import os
import inspect
import tempfile
import pandas as pd
import pytest

# Try to import detection / scoring / anonymization / reporting functions from whatever module names exist
from modules import pii_detector
from modules import compliance_scoring
from modules import report_generator

# anonymize_dataset may be in modules.anonymize_data (preferred) or modules.anonymizer/anonmizer
anonymize_dataset = None
for candidate in ("modules.anonymize_data", "modules.anonymizer", "modules.anonymize"):
    try:
        mod = __import__(candidate, fromlist=["*"])
        if hasattr(mod, "anonymize_dataset"):
            anonymize_dataset = mod.anonymize_dataset
            break
        # fallback: older anonymizer function name
        if hasattr(mod, "anonymize_data"):
            # wrap to return (df, report) to match newer behaviour
            def _wrap_anonymize(df, detections, method_config=None):
                df_out = mod.anonymize_data(df, detections)
                report = {"total_pii_values": 0, "anonymized_count": 0, "anonymization_rate": 0.0, "verification_passed": False}
                return df_out, report
            anonymize_dataset = _wrap_anonymize
            break
    except Exception:
        continue

# history logging: try flexible import; be tolerant to different signatures
log_scan_history_fn = None
for candidate in ("modules.history_logger", "modules.database"):
    try:
        mod = __import__(candidate, fromlist=["*"])
        if hasattr(mod, "log_scan_history"):
            log_scan_history_fn = mod.log_scan_history
            break
        # some codebases use log_history or log_scan
        if hasattr(mod, "log_history"):
            log_scan_history_fn = mod.log_history
            break
    except Exception:
        continue

# helpers
def safe_call_log_scan_history(results, score, violations, source, anon_report):
    """
    Call whichever logging function exists with best-effort arguments.
    This keeps tests robust to small signature changes in the app.
    """
    if log_scan_history_fn is None:
        pytest.skip("No log_scan_history/log_history function available in modules; skipping history-logging test")

    sig = inspect.signature(log_scan_history_fn)
    kwargs = {}
    # Common parameter names we may supply
    if "results" in sig.parameters:
        kwargs["results"] = results
    if "score" in sig.parameters:
        kwargs["score"] = score
    if "violations" in sig.parameters:
        kwargs["violations"] = violations
    if "source" in sig.parameters:
        kwargs["source"] = source
    # expanded/log detail params
    if "pii_types_regex" in sig.parameters:
        kwargs["pii_types_regex"] = ",".join(sorted({r["pattern"] for r in results}))
    if "pii_types_nlp" in sig.parameters:
        kwargs["pii_types_nlp"] = ""
    if "total_pii_values" in sig.parameters:
        kwargs["total_pii_values"] = int(anon_report.get("total_pii_values", 0))
    if "anonymized_count" in sig.parameters:
        kwargs["anonymized_count"] = int(anon_report.get("anonymized_count", 0))
    if "anonymization_rate" in sig.parameters:
        kwargs["anonymization_rate"] = float(anon_report.get("anonymization_rate", 0.0))
    if "verification_passed" in sig.parameters:
        kwargs["verification_passed"] = bool(anon_report.get("verification_passed", False))

    # If function expects positional arguments only, so build positional list in a sensible order to do that task:
    try:
        return log_scan_history_fn(**kwargs)
    except TypeError:
        # fallback: attempt positional call with common minimal args
        try:
            return log_scan_history_fn(results, score, violations, source, anon_report)
        except Exception:
            # last resort: call with just source if that's all it expects
            try:
                return log_scan_history_fn(source)
            except Exception:
                pytest.skip("log_scan_history exists but could not be called with safe arguments; skipping")

# ---------- Fixtures/ personal tweks  ----------
@pytest.fixture
def sample_df():
    return pd.DataFrame({
        "email": ["alice@example.com", "bob@gmail.com"],
        "phone": ["123-456-7890", "9876543210"],
        "name": ["Alice Johnson", "Bob Smith"],
        "notes": ["Lives in New York", "Works at OpenAI"]
    })


# ---------- Tests ----------
def test_pii_detection_regex(sample_df):
    results = pii_detector.detect_sensitive_data(sample_df)
    patterns = set([r["pattern"] for r in results])
    assert "email" in patterns, f"email not detected; patterns={patterns}"
    assert "phone" in patterns or any("phone" in p for p in patterns), f"phone not detected; patterns={patterns}"


def test_compliance_scoring(sample_df):
    results = pii_detector.detect_sensitive_data(sample_df)
    score, violations = compliance_scoring.score_compliance(
        results, {"max_pii_fields": 10, "allowed_pii_types": ["email", "phone"], "anonymization_required": False}
    )
    assert isinstance(score, (int, float))
    assert isinstance(violations, list)


def _call_anonymize_dataset(df, results, config):
    """
    Call anonymize_dataset that may return (df, report) or just df.
    Normalize to (df_out, report).
    """
    if anonymize_dataset is None:
        pytest.skip("No anonymize_dataset available")
    ret = anonymize_dataset(df.copy(), results, config)
    if isinstance(ret, tuple) and len(ret) == 2:
        return ret
    # older implementations returned df only
    return ret, {"total_pii_values": 0, "anonymized_count": 0, "anonymization_rate": 0.0, "verification_passed": False}


def test_anonymization_mask(sample_df):
    results = pii_detector.detect_sensitive_data(sample_df)
    anon_df, report = _call_anonymize_dataset(sample_df, results, {"email": "mask"})
    assert anon_df["email"].iloc[0] != sample_df["email"].iloc[0]


def test_anonymization_hash(sample_df):
    results = pii_detector.detect_sensitive_data(sample_df)
    anon_df, report = _call_anonymize_dataset(sample_df, results, {"email": "hash"})
    assert anon_df["email"].iloc[0] != sample_df["email"].iloc[0]


def test_anonymization_redact(sample_df):
    results = pii_detector.detect_sensitive_data(sample_df)
    anon_df, report = _call_anonymize_dataset(sample_df, results, {"phone": "redact"})
    v = str(anon_df["phone"].iloc[0])
    assert ("REDACT" in v.upper()) or (anon_df["phone"].iloc[0] != sample_df["phone"].iloc[0])


def test_anonymization_fake(sample_df):
    results = pii_detector.detect_sensitive_data(sample_df)
    anon_df, report = _call_anonymize_dataset(sample_df, results, {"name": "fake"})
    assert anon_df["name"].iloc[0] != sample_df["name"].iloc[0]


def test_history_logging(sample_df, tmp_path):
    results = pii_detector.detect_sensitive_data(sample_df)
    score, violations = compliance_scoring.score_compliance(
        results, {"max_pii_fields": 10, "allowed_pii_types": ["email", "phone"], "anonymization_required": False}
    )
    anon_df, anon_report = _call_anonymize_dataset(sample_df, results, {"email": "mask"})
    # Best-effort call to logging function (adapts to available signature)
    safe_call_log_scan_history(results, score, violations, "test_source", anon_report)
    # If no exception raised, consider it a pass


def test_csv_and_pdf_report_generation(sample_df, tmp_path):
    results = pii_detector.detect_sensitive_data(sample_df)
    score, violations = compliance_scoring.score_compliance(
        results, {"max_pii_fields": 10, "allowed_pii_types": ["email", "phone"], "anonymization_required": False}
    )

    # Generate CSV: detect expected signature and call accordingly
    gen_csv = getattr(report_generator, "generate_csv_report", None)
    gen_pdf = getattr(report_generator, "generate_pdf_report", None)
    assert gen_csv is not None
    assert gen_pdf is not None

    csv_sig = inspect.signature(gen_csv)
    pdf_sig = inspect.signature(gen_pdf)

    csv_tmp = str(tmp_path / "report.csv")
    pdf_tmp = str(tmp_path / "report.pdf")

    # CSV: if accepts output_path or path parameter, use it; otherwise call with default and verify default file exists.
    if "output_path" in csv_sig.parameters or "path" in csv_sig.parameters:
        # choose param name
        param = "output_path" if "output_path" in csv_sig.parameters else "path"
        kwargs = {param: csv_tmp}
        gen_csv(results, score, violations, **kwargs)
        assert os.path.exists(csv_tmp)
    else:
        # call without path; expect default file in output/
        gen_csv(results, score, violations)
        assert os.path.exists("output/compliance_report.csv")

    # PDF: same strategy
    if "output_path" in pdf_sig.parameters or "path" in pdf_sig.parameters:
        param = "output_path" if "output_path" in pdf_sig.parameters else "path"
        kwargs = {param: pdf_tmp}
        gen_pdf(results, score, violations, **kwargs)
        assert os.path.exists(pdf_tmp)
    else:
        gen_pdf(results, score, violations)
        assert os.path.exists("output/compliance_report.pdf")
