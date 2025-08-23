# modules/history_logger.py
import os
import pandas as pd
from datetime import datetime

HISTORY_FILE = "output/scan_history.csv"

def _ensure_output_dir():
    os.makedirs("output", exist_ok=True)

def log_scan_history(results, score, violations, source, anon_report=None):
    """
    Append a scan record to output/scan_history.csv

    Parameters:
      - results: list of detection dicts (each: {'column','pattern','matches_found'})
      - score: numeric compliance score
      - violations: list (or other) of violation strings
      - source: string (uploaded filename or table name)
      - anon_report: dict from anonymize_dataset with keys:
            total_pii_values, anonymized_count, anonymization_rate, verification_passed
    """
    _ensure_output_dir()

    # Normalize inputs
    if isinstance(violations, (list, tuple, set)):
        violations_str = "; ".join([str(v) for v in violations]) if violations else "None"
    else:
        violations_str = str(violations) if violations not in (None, float("nan")) else "None"

    # extract pii types
    pii_types = sorted(set([r.get("pattern") for r in results])) if results else []
    pii_types_str = ", ".join([str(p) for p in pii_types]) if pii_types else "None"

    # anonymization stats
    total_pii_values = int(anon_report.get("total_pii_values", 0)) if isinstance(anon_report, dict) else 0
    anonymized_count = int(anon_report.get("anonymized_count", 0)) if isinstance(anon_report, dict) else 0
    anonymization_rate = float(anon_report.get("anonymization_rate", 0.0)) if isinstance(anon_report, dict) else 0.0
    verification_passed = bool(anon_report.get("verification_passed", False)) if isinstance(anon_report, dict) else False

    new_entry = {
        "timestamp": datetime.now().isoformat(timespec='seconds'),
        "source": source,
        "compliance_score": score,
        "violations": violations_str,
        "pii_types": pii_types_str,
        "total_pii_values": total_pii_values,
        "anonymized_count": anonymized_count,
        "anonymization_rate": anonymization_rate,
        "verification_passed": verification_passed
    }

    # Append or create CSV
    if os.path.exists(HISTORY_FILE):
        try:
            df = pd.read_csv(HISTORY_FILE)
        except Exception:
            df = pd.DataFrame()
        df = pd.concat([df, pd.DataFrame([new_entry])], ignore_index=True)
    else:
        df = pd.DataFrame([new_entry])

    df.to_csv(HISTORY_FILE, index=False)

def load_scan_history():
    """Return dataframe of history; returns empty dataframe if none."""
    if os.path.exists(HISTORY_FILE):
        try:
            return pd.read_csv(HISTORY_FILE)
        except Exception:
            return pd.DataFrame(columns=[
                "timestamp","source","compliance_score","violations","pii_types",
                "total_pii_values","anonymized_count","anonymization_rate","verification_passed"
            ])
    else:
        return pd.DataFrame(columns=[
            "timestamp","source","compliance_score","violations","pii_types",
            "total_pii_values","anonymized_count","anonymization_rate","verification_passed"
        ])
