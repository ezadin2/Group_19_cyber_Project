# modules/anonymize_data.py

"""
Advanced anonymization utilities:
- mask, hash, redact, fake, pseudonymize
- context-aware masking for emails and phones
- deterministic pseudonymization with optional persistent mapping
- anonymization reporting for dashboard statistics
"""

import hashlib
import pandas as pd
import os
import json
from typing import List, Dict, Any

# Where to persist the deterministic mapping (optional)
ANON_MAP_PATH = "output/anonymization_map.json"


def _ensure_output_dir():
    os.makedirs("output", exist_ok=True)


def _det_hash(val: Any, salt: str = "privacy_checker_salt") -> str:
    """Return deterministic short hex for a value + salt."""
    h = hashlib.sha256(f"{val}|{salt}".encode("utf-8")).hexdigest()
    return h[:12]


def _load_map() -> Dict[str, str]:
    _ensure_output_dir()
    if os.path.exists(ANON_MAP_PATH):
        try:
            with open(ANON_MAP_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_map(mapping: Dict[str, str]):
    _ensure_output_dir()
    with open(ANON_MAP_PATH, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=False)


# ---------- Primitive transformations ----------
def mask_value_series(series: pd.Series, keep_last: int = 0) -> pd.Series:
    """Replace value content with '*' leaving last keep_last characters."""
    def mask_one(x):
        x = "" if pd.isna(x) else str(x)
        if keep_last > 0 and len(x) > keep_last:
            return "*" * (len(x) - keep_last) + x[-keep_last:]
        return "*" * len(x) if x else x
    return series.astype(str).apply(mask_one)


def hash_value_series(series: pd.Series, length: int = 10) -> pd.Series:
    def h(x):
        if pd.isna(x) or str(x) == "nan":
            return x
        return hashlib.sha256(str(x).encode()).hexdigest()[:length]
    return series.apply(h)


def redact_series(series: pd.Series, token: str = "REDACTED") -> pd.Series:
    return series.apply(lambda x: token if pd.notna(x) and str(x) != "nan" else x)


# ---------- Context-aware transformations ----------
def mask_email_series(series: pd.Series, keep_domain: bool = True, keep_local_chars: int = 1) -> pd.Series:
    def mask_email(e):
        if pd.isna(e) or "@" not in str(e):
            return e
        local, domain = str(e).split("@", 1)
        if keep_domain:
            keep = local[:keep_local_chars] if keep_local_chars > 0 else ""
            return f"{keep}{'*' * max(len(local) - len(keep), 1)}@{domain}"
        else:
            return f"{'*' * max(len(local), 3)}@{domain}"
    return series.apply(mask_email)


def mask_phone_series(series: pd.Series, keep_last: int = 3) -> pd.Series:
    """Keep country code if present, mask middle digits, keep last keep_last digits."""
    def mask_phone(p):
        if pd.isna(p):
            return p
        s = str(p)
        digits = "".join(ch for ch in s if ch.isdigit())
        if len(digits) <= keep_last:
            return "*" * len(digits)
        masked = "*" * (len(digits) - keep_last) + digits[-keep_last:]
        return ("+" + masked) if s.strip().startswith("+") else masked
    return series.apply(mask_phone)


# ---------- Deterministic pseudonymization ----------
def pseudonymize_series(series: pd.Series, prefix: str = "USER", persist_map: bool = True) -> pd.Series:
    """
    Replace values with deterministic pseudonyms like USER_<shorthash>.
    If persist_map True, mapping is saved to ANON_MAP_PATH and reused.
    """
    mapping = _load_map() if persist_map else {}
    updated = False

    def pseudo(x):
        nonlocal updated
        if pd.isna(x):
            return x
        key = f"{prefix}|{x}"
        if key in mapping:
            return mapping[key]
        short = _det_hash(x)
        value = f"{prefix}_{short}"
        mapping[key] = value
        updated = True
        return value

    result = series.apply(lambda x: pseudo(x) if pd.notna(x) and str(x) != "nan" else x)

    if persist_map and updated:
        _save_map(mapping)

    return result


# ---------- Fake (template) generators ----------
def fake_email_series(series: pd.Series, domain_default: str = "example.com") -> pd.Series:
    def fake(e):
        if pd.isna(e):
            return e
        return f"user{_det_hash(e)[:6]}@{domain_default}"
    return series.apply(fake)


def fake_phone_series(series: pd.Series, country_prefix: str = "+251") -> pd.Series:
    def fake(p):
        if pd.isna(p):
            return p
        return f"{country_prefix}{_det_hash(p)[-9:]}"
    return series.apply(fake)


# ---------- High-level orchestrator ----------
def anonymize_dataset(df: pd.DataFrame, detections: List[Dict[str, Any]], method_config: Dict[str, str] = None,
                      persist_map: bool = True):
    """
    Returns:
        anonymized_df, anon_report
        anon_report = {
            "total_pii_values": int,
            "anonymized_count": int,
            "anonymization_rate": float,
            "verification_passed": bool
        }
    """
    if method_config is None:
        method_config = {}

    df_out = df.copy()
    total_pii_values = 0
    anonymized_count = 0

    # Group detections by column
    col_map = {}
    for d in detections:
        col = d.get("column")
        pattern = d.get("pattern")
        if col not in df_out.columns:
            continue
        col_map.setdefault(col, set()).add(pattern)

    for col, patterns in col_map.items():
        # Preferred pattern
        chosen_pattern = None
        for p in ("email", "phone", "national_id", "name"):
            if p in patterns:
                chosen_pattern = p
                break
        if chosen_pattern is None:
            chosen_pattern = next(iter(patterns))

        method = method_config.get(chosen_pattern, None)
        if method is None:
            if chosen_pattern == "email":
                method = "mask"
            elif chosen_pattern == "phone":
                method = "mask"
            elif chosen_pattern == "national_id":
                method = "hash"
            else:
                method = "redact"

        series = df_out[col]
        original_values = series.copy()

        # Count PII before
        pii_values_here = original_values[original_values.notna() & (original_values.astype(str) != "nan")].shape[0]
        total_pii_values += pii_values_here

        # Apply anonymization
        if method == "mask":
            if chosen_pattern == "email":
                df_out[col] = mask_email_series(series, keep_domain=True, keep_local_chars=1)
            elif chosen_pattern == "phone":
                df_out[col] = mask_phone_series(series, keep_last=3)
            else:
                df_out[col] = mask_value_series(series, keep_last=0)
        elif method == "hash":
            df_out[col] = hash_value_series(series, length=12)
        elif method == "redact":
            df_out[col] = redact_series(series, token="REDACTED")
        elif method == "fake":
            if chosen_pattern == "email":
                df_out[col] = fake_email_series(series)
            elif chosen_pattern == "phone":
                df_out[col] = fake_phone_series(series)
            else:
                df_out[col] = pseudonymize_series(series, prefix="FAKE", persist_map=persist_map)
        elif method in ("pseudonymize", "pseudo"):
            df_out[col] = pseudonymize_series(series, prefix="USER", persist_map=persist_map)
        else:
            df_out[col] = redact_series(series, token="REDACTED")

        # Count anonymized changes
        changed_count = (df_out[col] != original_values).sum()
        anonymized_count += changed_count

    # Prepare report
    anon_report = {
        "total_pii_values": total_pii_values,
        "anonymized_count": anonymized_count,
        "anonymization_rate": (anonymized_count / total_pii_values * 100) if total_pii_values else 0,
        "verification_passed": anonymized_count == total_pii_values
    }

    return df_out, anon_report
