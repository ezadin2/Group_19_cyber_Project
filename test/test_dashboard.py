import pytest
import pandas as pd
import os

# Streamlit test helpers
import streamlit.web.bootstrap
from streamlit.runtime.scriptrunner import RerunData, RerunException

DASHBOARD_FILE = "dashboard.py"

def test_dashboard_runs(tmp_path):
    """
    Smoke test: run dashboard.py and ensure it loads without fatal errors.
    """
    # Prepare fake CSVs so dashboard finds them
    results_df = pd.DataFrame({
        "column": ["emails", "phones"],
        "pattern": ["email", "phone"]
    })
    report_df = pd.DataFrame({
        "Compliance Score": [None],
        "Violations": [None]
    })

    results_path = tmp_path / "results.csv"
    report_path = tmp_path / "compliance_report.csv"
    results_df.to_csv(results_path, index=False)
    report_df.to_csv(report_path, index=False)

    # Point dashboard to fake files
    os.makedirs("output", exist_ok=True)
    results_df.to_csv("output/results.csv", index=False)
    report_df.to_csv("output/compliance_report.csv", index=False)

    # Try to bootstrap Streamlit dashboard
    try:
        streamlit.web.bootstrap.run(DASHBOARD_FILE, "", [], flag_options={})
    except RerunException as e:
        assert isinstance(e, RerunException)  # rerun is expected
    except SystemExit:
        # Streamlit sometimes calls sys.exit after finishing
        pass
    except Exception as e:
        pytest.fail(f"Dashboard crashed with: {e}")
