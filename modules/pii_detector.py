# modules/pii_detector.py

import re
import pandas as pd


# Try to import spaCy (NLP-based detection)
try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    NLP_ENABLED = True
except Exception:
    nlp = None
    NLP_ENABLED = False

# ---------------- Regex patterns for PII ---------------- #
# needs fixing for the test to work 
patterns = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "phone": r"(?:\d{3})-(?:\d{3})-(?:\d{4})",  # FIXED: flexible phone format Ethiopia format or local
    "national_id": r"[A-Z]{2}\d{8}",
    "ssn": r"(?:\d{3})-(?:\d{2})-(?:\d{4})",  # US SSN
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # IPv4
    "ipv6": r"\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b",
    "iban": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b",
    "passport": r"\b[A-Z]{1}[0-9]{6,9}\b",  # general passport
    "name": r"\b[A-Z][a-z]+ [A-Z][a-z]+\b",
    "address": r"\b\d{1,4}\s[A-Za-z]+\s(?:Street|St|Ave|Avenue|Rd|Road|Blvd|Boulevard)\b",
}

# ---------------- Detection Function ---------------- #

# modules/pii_detector.py

def detect_sensitive_data(df: pd.DataFrame):
    """
    Detect PII in dataframe using regex + NLP (if available).
    Returns list of dicts with: column, pattern, match, matches_found
    """
    results = []

    # Regex-based detection
    for col in df.columns:
        col_data = df[col].astype(str)

        for label, pattern in patterns.items():
            matches = col_data[col_data.str.contains(pattern, na=False, regex=True)]
            if not matches.empty:
                # Take first matching value as a sample
                sample_value = matches.iloc[0]
                results.append({
                    "column": col,
                    "pattern": label,
                    "match": str(sample_value),         # <-- NEW field for app.py
                    "matches_found": len(matches)
                })

    # NLP-based detection (if spaCy available)
    if NLP_ENABLED:
        for col in df.columns:
            col_data = df[col].astype(str).dropna()
            for val in col_data:
                doc = nlp(val)
                for ent in doc.ents:
                    if ent.label_ in ["PERSON", "GPE", "ORG"]:
                        results.append({
                            "column": col,
                            "pattern": ent.label_.lower(),  
                            "match": val,                   # <-- NLP sample value
                            "matches_found": 1
                        })

    return results
