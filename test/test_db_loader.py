import sqlite3
import pandas as pd
import pytest
from modules.db_loader import list_tables, load_sqlite_table

@pytest.fixture
def temp_db(tmp_path):
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com')")
    cur.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@example.com')")
    conn.commit()
    conn.close()
    return str(db_path)

def test_list_tables(temp_db):
    tables = list_tables(temp_db)
    assert "users" in tables

def test_load_sqlite_table(temp_db):
    df = load_sqlite_table(temp_db, "users")
    assert isinstance(df, pd.DataFrame)
    assert "name" in df.columns
    assert df.shape[0] == 2
