# modules/anonymizer.py

import pandas as pd
import re

def anonymize_column(series, pattern_type):
    if pattern_type == "email":
        return series.apply(lambda x: re.sub(r'[^@]+', '*', str(x), 1))
    elif pattern_type == "phone":
        return series.apply(lambda x: re.sub(r'\\d', '*', str(x)))
    elif pattern_type == "name":
        return series.apply(lambda x: "REDACTED")
    elif pattern_type == "national_id":
        return series.apply(lambda x: "ID-XXXXXX")
    else:
        return series

def anonymize_data(df, detections):
    df_copy = df.copy()
    for item in detections:
        col = item['column']
        pattern = item['pattern']
        df_copy[col] = anonymize_column(df_copy[col], pattern)
    return df_copy
