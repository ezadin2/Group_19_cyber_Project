import pandas as pd
import pytest
from modules.file_loader import load_data

def test_load_csv(tmp_path):
    file_path = tmp_path / "test.csv"
    pd.DataFrame({"name": ["Alice", "Bob"], "age": [30, 40]}).to_csv(file_path, index=False)
    df = load_data(str(file_path))
    assert not df.empty
    assert "name" in df.columns

def test_load_excel(tmp_path):
    file_path = tmp_path / "test.xlsx"
    pd.DataFrame({"city": ["NY", "LA"], "zip": [10001, 90001]}).to_excel(file_path, index=False)
    df = load_data(str(file_path))
    assert not df.empty
    assert "city" in df.columns
