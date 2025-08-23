# modules/pii_detector.py
import re

# Define regex patterns for various PII types
patterns = {
    'email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    'phone': r'\+251[0-9]{9}',  # Ethiopian phone format
    'national_id': r'[A-Z]{2}[0-9]{8}',
    'SSN': r'\b\d{3}-\d{2}-\d{4}\b',  # Matches 123-45-6789
    'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',  # Matches CC numbers with spaces or dashes
    'Name': r'\b[A-Z][a-z]+ [A-Z][a-z]+\b',  # Matches First Last
}

def detect_sensitive_data(df):
    results = []
    for col in df.columns:
        col_data = df[col].astype(str)

        for label, pattern in patterns.items():
            matches = col_data[col_data.str.contains(pattern, case=False, regex=True, na=False)]
            if not matches.empty:
                results.append({
                    'column': col,
                    'pattern': label,
                    'matches_found': len(matches)
                })

    return results
