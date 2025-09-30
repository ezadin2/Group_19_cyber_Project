import pandas as pd
from modules.anonymize_data import anonymize_dataset

def test_anonymize_with_mask():
    df = pd.DataFrame({"email": ["test@example.com"]})
    results = [{"column": "email", "pattern": "email", "matches_found": 1}]
    anon_df, report = anonymize_dataset(df, results, {"email": "mask"})
    assert anon_df["email"].iloc[0] != "test@example.com"
    assert report["anonymized_count"] == 1

def test_anonymize_with_unknown_method():
    df = pd.DataFrame({"phone": ["1234567890"]})
    results = [{"column": "phone", "pattern": "phone", "matches_found": 1}]
    # Unknown method should not break, fallback expected
    anon_df, report = anonymize_dataset(df, results, {"phone": "unknown"})
    assert "123" not in anon_df["phone"].iloc[0]  # Should be modified somehow

def test_anonymize_empty_dataframe():
    df = pd.DataFrame(columns=["email"])
    results = []
    anon_df, report = anonymize_dataset(df, results, {})
    assert anon_df.empty
    assert report["total_pii_values"] == 0
    assert report["anonymized_count"] == 0
