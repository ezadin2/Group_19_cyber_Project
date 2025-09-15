import os
import pandas as pd
import sqlite3
from datetime import datetime

HISTORY_FILE = "output/scan_history.csv"
DB_FILE = "output/scan_history.db"

# ---------------------------
# Database helpers
# ---------------------------
def _get_db_connection():
    os.makedirs("output", exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    return conn

def _ensure_db_schema():
    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        compliance_score REAL,
        violations TEXT,
        pii_types_all TEXT,
        pii_types_regex TEXT,
        pii_types_nlp TEXT,
        total_pii_values INTEGER,
        anonymized_count INTEGER,
        anonymization_rate REAL,
        verification_passed INTEGER
    )
    """)
    conn.commit()
    conn.close()

# ---------------------------
# Main logging function
# ---------------------------
def log_scan_history(source, compliance_score, violations,
                     pii_types_all, pii_types_regex, pii_types_nlp,
                     total_pii_values, anonymized_count,
                     anonymization_rate, verification_passed):
    os.makedirs("output", exist_ok=True)

    # Build entry dict
    new_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "compliance_score": compliance_score,
        "violations": violations,
        "pii_types_all": pii_types_all,
        "pii_types_regex": pii_types_regex,
        "pii_types_nlp": pii_types_nlp,
        "total_pii_values": total_pii_values,
        "anonymized_count": anonymized_count,
        "anonymization_rate": anonymization_rate,
        "verification_passed": verification_passed,
    }

    # --- Save to CSV (legacy support) ---
    if os.path.exists(HISTORY_FILE):
        df = pd.read_csv(HISTORY_FILE)
        df = pd.concat([df, pd.DataFrame([new_entry])], ignore_index=True)
    else:
        df = pd.DataFrame([new_entry])
    df.to_csv(HISTORY_FILE, index=False)

    # --- Save to SQLite DB (new scalable way) ---
    _ensure_db_schema()
    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history 
        (timestamp, source, compliance_score, violations,
         pii_types_all, pii_types_regex, pii_types_nlp,
         total_pii_values, anonymized_count, anonymization_rate, verification_passed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        new_entry["timestamp"],
        new_entry["source"],
        new_entry["compliance_score"],
        new_entry["violations"],
        new_entry["pii_types_all"],
        new_entry["pii_types_regex"],
        new_entry["pii_types_nlp"],
        new_entry["total_pii_values"],
        new_entry["anonymized_count"],
        new_entry["anonymization_rate"],
        int(new_entry["verification_passed"])
    ))
    conn.commit()
    conn.close()

# ---------------------------
# Load history functions
# ---------------------------
def load_scan_history():
    """Load history from CSV (legacy)."""
    if os.path.exists(HISTORY_FILE):
        return pd.read_csv(HISTORY_FILE)
    return pd.DataFrame()

def load_scan_history_db():
    """Load history from SQLite DB (recommended)."""
    _ensure_db_schema()
    conn = _get_db_connection()
    try:
        df = pd.read_sql_query("SELECT * FROM scan_history ORDER BY timestamp DESC", conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df
