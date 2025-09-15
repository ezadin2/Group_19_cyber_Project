# modules/database.py
import sqlite3
import os
from datetime import datetime
import pandas as pd

# Default DB file (can be overridden by tests or other code)
DB_PATH = "privacy_checker.db"

# ---------------------------
# Helpers
# ---------------------------
def _ensure_db_dir():
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)

def _get_db_connection():
    """Return a sqlite3 connection; ensure the folder exists first."""
    _ensure_db_dir()
    # use default timeout so quick concurrent attempts don't immediately fail
    conn = sqlite3.connect(DB_PATH, timeout=30)
    return conn

# ---------------------------
# Schema / Init
# ---------------------------
def init_db():
    """Create required tables if they don't exist."""
    conn = _get_db_connection()
    cur = conn.cursor()

    # scans: summary of each scan
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        file_name TEXT,
        score REAL,
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

    # findings: per-scan PII findings
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        column_name TEXT,
        pii_type TEXT,
        sample_value TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )
    """)

    # events: generic scan-related events (anonymization, exports, etc.)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        event_type TEXT,
        description TEXT,
        timestamp TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )
    """)

    # history: simplified timeline entries for dashboards/timeline view
    cur.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        event TEXT,
        timestamp TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )
    """)

    conn.commit()
    conn.close()

# ---------------------------
# Logging functions
# ---------------------------
def log_scan(file_name, score, violations, anon_report=None,
             pii_types_all=None, pii_types_regex=None, pii_types_nlp=None):
    """
    Insert a new scan record and return scan_id.

    Parameters:
      - file_name: str
      - score: float or int
      - violations: str or list -> stored as string
      - anon_report: optional dict with keys total_pii_values, anonymized_count, anonymization_rate, verification_passed
      - pii_types_*: optional strings summarizing PII types
    """
    conn = _get_db_connection()
    cur = conn.cursor()

    # normalize violations to string
    if isinstance(violations, (list, tuple, set)):
        violations_str = "; ".join([str(v) for v in violations]) if violations else ""
    else:
        violations_str = str(violations) if violations is not None else ""

    # prepare anonymization stats
    total_pii_values = None
    anonymized_count = None
    anonymization_rate = None
    verification_passed = None

    if isinstance(anon_report, dict):
        total_pii_values = int(anon_report.get("total_pii_values", 0))
        anonymized_count = int(anon_report.get("anonymized_count", 0))
        anonymization_rate = float(anon_report.get("anonymization_rate", 0.0))
        verification_passed = 1 if anon_report.get("verification_passed", False) else 0

    timestamp = datetime.now().isoformat()

    cur.execute("""
        INSERT INTO scans (timestamp, file_name, score, violations,
                           pii_types_all, pii_types_regex, pii_types_nlp,
                           total_pii_values, anonymized_count, anonymization_rate, verification_passed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        file_name,
        float(score) if score is not None else None,
        violations_str,
        pii_types_all,
        pii_types_regex,
        pii_types_nlp,
        total_pii_values,
        anonymized_count,
        anonymization_rate,
        verification_passed
    ))

    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def log_finding(scan_id, column_name, pii_type, sample_value):
    """Insert a PII finding row linked to a scan."""
    conn = _get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO findings (scan_id, column_name, pii_type, sample_value)
        VALUES (?, ?, ?, ?)
    """, (scan_id, column_name, pii_type, str(sample_value)))
    conn.commit()
    conn.close()

def log_event(scan_id, event_type, description):
    """Insert an event row (e.g., anonymization performed, exported report)."""
    conn = _get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events (scan_id, event_type, description, timestamp)
        VALUES (?, ?, ?, ?)
    """, (scan_id, event_type, description, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def log_history(scan_id, event, **kwargs):
    """
    Add a timeline/history entry for a scan.
    Accepts extra kwargs but they are optional and ignored (keeps call-sites simple).
    Example usage:
        log_history(scan_id, "Scan completed")
    """
    conn = _get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO history (scan_id, event, timestamp)
        VALUES (?, ?, ?)
    """, (scan_id, event, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# ---------------------------
# Fetching functions
# ---------------------------
def fetch_scans():
    """Return a pandas DataFrame with all scans ordered by timestamp desc."""
    init_db()  # ensure schema exists
    conn = _get_db_connection()
    try:
        df = pd.read_sql_query("SELECT * FROM scans ORDER BY timestamp DESC", conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df

def fetch_findings(scan_id):
    """Return a list of findings (column_name, pii_type, sample_value) for a scan."""
    conn = _get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT column_name, pii_type, sample_value FROM findings WHERE scan_id = ?", (scan_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def fetch_events(scan_id):
    """Return list of events for a scan."""
    conn = _get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT event_type, description, timestamp FROM events WHERE scan_id = ? ORDER BY timestamp DESC", (scan_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def fetch_history():
    """
    Return a pandas DataFrame of history items joined with scan source (if available).
    Columns: history.id, history.scan_id, history.event, history.timestamp, scans.file_name (source)
    """
    init_db()
    conn = _get_db_connection()
    try:
        q = """
        SELECT h.id, h.scan_id, h.event, h.timestamp,
               s.file_name as source, s.score, s.violations
        FROM history h
        LEFT JOIN scans s ON h.scan_id = s.id
        ORDER BY h.timestamp DESC
        """
        df = pd.read_sql_query(q, conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df
