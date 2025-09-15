import sqlite3
import pandas as pd

DB_PATH = "privacy_checker.db"
 # this function is used to chake the integrity of the data base 
 
def show_table(table_name):
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
        print(f"\n--- {table_name} ---")
        print(df.head(10))  # show first 10 rows
    except Exception as e:
        print(f"Error reading {table_name}: {e}")
    finally:
        conn.close()

for table in ["scans", "findings", "events", "history"]:
    show_table(table)
