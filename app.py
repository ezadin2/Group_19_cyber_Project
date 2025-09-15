# app.py
import streamlit as st
import pandas as pd
import os
import logging
import plotly.express as px
import json


from collections import Counter
from modules.file_loader import load_data
from modules.pii_detector import detect_sensitive_data
from modules.compliance_scoring import score_compliance
from modules.anonymize_data import anonymize_dataset
from modules.report_generator import generate_pdf_report, generate_csv_report
from modules.db_loader import load_sqlite_table, list_tables
from modules.database import init_db, log_scan, log_finding, log_history
from modules.database import fetch_scans, fetch_history
from modules.history_logger import load_scan_history_db

# Initialize DB on startup
init_db()



# Configure logging and page
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
st.set_page_config(page_title="🔐 Data Privacy Compliance Checker", layout="wide")

# UI Title
st.title("🔐 Data Privacy Compliance Checker")
st.write("Upload a dataset or SQL database, scan for sensitive data, check compliance, anonymize, and export reports.")

# Navigation
st.sidebar.title("📌 Navigation")
page = st.sidebar.radio("Go to", ["🔍 Privacy Scanner", "📊 Compliance Summary Dashboard"])

# Dashboard page 
if page == "📊 Compliance Summary Dashboard":
    st.title("📊 Compliance Summary Dashboard")

    scans_df = fetch_scans()
    history_df = fetch_history()

    if scans_df.empty and history_df.empty:
        st.info("No scans or history have been logged yet.")
    else:
        # ---- Tabs ----
        tabs = st.tabs(["📁 Scan Records", "🕒 Event History"])

        # ===============================
        # TAB 1: SCANS
        # ===============================
        with tabs[0]:
            if scans_df.empty:
                st.info("No scans have been logged yet.")
            else:
                scans_df["timestamp"] = pd.to_datetime(scans_df["timestamp"], errors="coerce")

                # Sidebar filters
                st.sidebar.subheader("📂 Scan Filters")
                source_options = ["All"] + sorted(scans_df["file_name"].dropna().unique().tolist())
                source_filter = st.sidebar.selectbox("Select Source", options=source_options)
                date_min = scans_df["timestamp"].min().date()
                date_max = scans_df["timestamp"].max().date()
                date_range = st.sidebar.date_input("Select Date Range", value=(date_min, date_max))

                filtered_df = scans_df.copy()
                if source_filter != "All":
                    filtered_df = filtered_df[filtered_df["file_name"] == source_filter]
                if isinstance(date_range, (list, tuple)) and len(date_range) == 2:
                    start_date, end_date = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
                    filtered_df = filtered_df[(filtered_df["timestamp"] >= start_date) & (filtered_df["timestamp"] <= end_date)]

                st.subheader("📁 Filtered Scan Records")
                st.dataframe(filtered_df, use_container_width=True)

                if not filtered_df.empty:
                    # Compliance Score Trend
                    st.subheader("📈 Compliance Score Trend")
                    score_fig = px.line(filtered_df, x="timestamp", y="score", markers=True,
                                        title="Compliance Score Over Time")
                    st.plotly_chart(score_fig, use_container_width=True)

                    # PII Types
                    st.subheader("📊 Most Common PII Types")
                    if "pii_types_all" in filtered_df.columns:
                        filtered_df["pii_types_all"] = filtered_df["pii_types_all"].fillna("None").astype(str)
                        all_types = filtered_df["pii_types_all"].str.split(", ")
                        flat_types = pd.Series([
                            pii for sublist in all_types for pii in sublist if pii and pii != "None"
                        ])
                        if not flat_types.empty:
                            type_counts = flat_types.value_counts().reset_index()
                            type_counts.columns = ["PII Type", "Count"]
                            pii_fig = px.bar(type_counts, x="PII Type", y="Count",
                                             title="Most Frequently Detected PII Types")
                            st.plotly_chart(pii_fig, use_container_width=True)
                        else:
                            st.info("No PII detected in the selected scans.")

                    # Violations
                    st.subheader("⚠️ Violation Frequencies")
                    if "violations" in filtered_df.columns:
                        filtered_df["violations"] = filtered_df["violations"].fillna("None").astype(str)
                        all_vios = filtered_df["violations"].str.split(r"[;,]")
                        flat_vios = pd.Series([
                            v.strip() for sublist in all_vios for v in sublist if v and v.strip() not in ["", "None"]
                        ])
                        flat_vios = flat_vios.replace({
                            r"Too many PII types.*": "Too many PII types",
                            r"Disallowed PII type.*": "Disallowed PII type"
                        }, regex=True)
                        if not flat_vios.empty:
                            vio_counts = flat_vios.value_counts().reset_index()
                            vio_counts.columns = ["Violation", "Count"]
                            vio_fig = px.bar(vio_counts, x="Violation", y="Count",
                                             title="Frequent Compliance Violations")
                            st.plotly_chart(vio_fig, use_container_width=True)
                        else:
                            st.info("No violations recorded for the selected scans.")

                    # Anonymization Rate
                    if "anonymization_rate" in filtered_df.columns:
                        st.subheader("🔒 Anonymization Rate Over Time")
                        anon_fig = px.line(filtered_df, x="timestamp", y="anonymization_rate", markers=True,
                                           title="Anonymization Rate (%)")
                        st.plotly_chart(anon_fig, use_container_width=True)

        # ===============================
        # TAB 2: HISTORY
        # ===============================
        with tabs[1]:
            if history_df.empty:
                st.info("No event history recorded yet.")
            else:
                history_df["timestamp"] = pd.to_datetime(history_df["timestamp"], errors="coerce")
                st.subheader("🕒 Event History")
                st.dataframe(history_df, use_container_width=True)

                history_counts = history_df["event"].value_counts().reset_index()
                history_counts.columns = ["Event", "Count"]
                hist_fig = px.bar(history_counts, x="Event", y="Count",
                                  title="Most Common Events")
                st.plotly_chart(hist_fig, use_container_width=True)


# Privacy Scanner page
if page == "🔍 Privacy Scanner":
    st.title("🔍 Privacy Scanner")
    # Sidebar - Rule configuration
    st.sidebar.header("🧾 Rule Configuration")
    rule_file = st.sidebar.file_uploader("Upload custom rules.json", type=["json"])
    if rule_file:
        rules = json.load(rule_file)
        st.sidebar.success("✅ Custom rules loaded.")
    else:
        rules = {
            "max_pii_fields": 2,
            "allowed_pii_types": ["email", "phone"],
            "anonymization_required": False
        }
        st.sidebar.info("Using default rules.")

    # Rule editor (inline)
    st.sidebar.markdown("### ✏️ Edit Rules")
    rules["max_pii_fields"] = st.sidebar.number_input("Max PII Fields Allowed", min_value=1, value=rules.get("max_pii_fields", 2))
    allowed_types_input = st.sidebar.text_input("Allowed PII Types (comma-separated)", ", ".join(rules.get("allowed_pii_types", [])))
    rules["allowed_pii_types"] = [item.strip() for item in allowed_types_input.split(",") if item.strip()]
    rules["anonymization_required"] = st.sidebar.checkbox("Anonymization Required", value=rules.get("anonymization_required", False))

    # Anonymization settings
    st.sidebar.header("🔐 Anonymization Settings")
    anon_method_default = st.sidebar.selectbox("Default Anonymization Method", ["mask", "hash", "redact", "fake"])

    # Data sources
    st.sidebar.header("🗃 Data Source")
    sql_file = st.sidebar.file_uploader("Upload SQLite .db file", type=["db"])
    uploaded_file = st.file_uploader("Upload CSV / Excel file", type=["csv", "xlsx"])

    df = None
    table_selected = None
    if sql_file:
        os.makedirs("temp", exist_ok=True)
        db_path = os.path.join("temp", sql_file.name)
        with open(db_path, "wb") as f:
            f.write(sql_file.getbuffer())
        tables = list_tables(db_path)
        table_selected = st.selectbox("Choose a table to scan", tables)
        if st.button("📱 Load SQL Table"):
            df = load_sqlite_table(db_path, table_selected)
            st.success(f"Loaded table: {table_selected}")
            st.dataframe(df.head(), use_container_width=True)

    if uploaded_file:
        os.makedirs("temp", exist_ok=True)
        temp_path = os.path.join("temp", uploaded_file.name)
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        df = load_data(temp_path)
        st.subheader("📈 Data Preview")
        st.dataframe(df.head(), use_container_width=True)

    # Run scan
    if st.button("🔍 Run Privacy Scan"):
        if df is None or df.empty:
            st.warning("⚠️ Please upload a dataset or load a table before scanning.")
        else:
            with st.spinner("Scanning for PII..."):
                results = detect_sensitive_data(df)

                # Compute compliance score & violations
                score, violations = score_compliance(results, rules)

                # Separate Regex vs NLP detections
                regex_results = [r for r in results if r["pattern"] in [
                    "email", "phone", "national_id", "ssn", "credit_card",
                    "ip_address", "ipv6", "iban", "passport", "name", "address"
                ]]
                nlp_results = [r for r in results if r["pattern"] in ["person", "gpe", "org"]]


                # Show overview charts (Regex only, since NLP usually finds single values)
                if regex_results:
                    pattern_counts = Counter([r['pattern'] for r in regex_results])
                    chart_df = pd.DataFrame({
                        'PII Type': list(pattern_counts.keys()),
                        'Count': list(pattern_counts.values())
    })
                st.subheader("📈 Regex-based PII Detection Overview")
                col1, col2 = st.columns(2)
                with col1:
                    bar_fig = px.bar(chart_df, x="PII Type", y="Count",
                                     title="Detected PII by Type (Regex)", color="PII Type")
                    st.plotly_chart(bar_fig, use_container_width=True, key="scan_pii_bar")
                with col2:
                    pie_fig = px.pie(chart_df, names="PII Type", values="Count",
                                     title="PII Distribution (Regex)")
                    st.plotly_chart(pie_fig, use_container_width=True, key="scan_pii_pie")


                          # --- Show Results ---
                st.subheader("🔎 PII Detection Results")
                if results:
                    st.success(f"✅ Found {len(results)} sensitive fields.")
                # Show Regex results
                if regex_results:
                    st.markdown("### 🔍 Regex Detections")
                    st.dataframe(pd.DataFrame(regex_results), use_container_width=True)
                # Show NLP results
                if nlp_results:
                    st.markdown("### 🧠 NLP Detections (spaCy)")
                    st.dataframe(pd.DataFrame(nlp_results), use_container_width=True)
                else:
                    st.success("🎉 No sensitive data found!")


                st.subheader("📋 Compliance Score")
                st.metric("Score", f"{score}%")
                if violations:
                    st.warning("⚠️ Violations Found:")
                    for v in violations:
                        st.markdown(f"- **{v}**")
                else:
                    st.success("All compliance checks passed ✅")

                # --- Per-PII anonymization method selection ---
                st.subheader("🛠 Anonymization Method Per PII Type")
                method_config = {}
                pii_types_set = set([r['pattern'] for r in results]) if results else set()
                for pattern in pii_types_set:
                    # default to sidebar setting if user didn't choose per-type
                    default_choice = anon_method_default
                    method = st.selectbox(f"Method for {pattern}", ["mask", "hash", "redact", "fake"], index=["mask","hash","redact","fake"].index(default_choice), key=f"method_{pattern}")
                    method_config[pattern] = method

                # Run anonymization (expects anonymize_dataset to return (df, report))
                st.subheader("🕶 Anonymized Dataset")
                try:
                    anonymized_df, anon_report = anonymize_dataset(df.copy(), results, method_config)
                except Exception as e:
                    st.error(f"Anonymization failed: {e}")
                    anonymized_df = df.copy()
                    anon_report = {"total_pii_values": 0, "anonymized_count": 0, "anonymization_rate": 0.0, "verification_passed": False}

                st.dataframe(anonymized_df.head(), use_container_width=True)

                # Show anonymization stats
                st.subheader("📊 Anonymization Statistics")
                st.metric("Total PII Values Detected", anon_report.get("total_pii_values", 0))
                st.metric("Total Anonymized", anon_report.get("anonymized_count", 0))
                st.metric("Anonymization Rate", f"{anon_report.get('anonymization_rate', 0.0):.1f}%")
                if anon_report.get("verification_passed", False):
                    st.success("✅ Verification Passed: All detected PII was anonymized.")
                else:
                    st.warning("⚠️ Verification: Some detected PII may remain. Please review anonymization settings.")

                # Save anonymized file and reports
                os.makedirs("output", exist_ok=True)
                anon_path = "output/anonymized_data.csv"
                anonymized_df.to_csv(anon_path, index=False)
                generate_pdf_report(results, score, violations)
                generate_csv_report(results, score, violations)

                # Log history (include anonymization stats)
                # determine source name
                if uploaded_file:
                    source_name = uploaded_file.name
                elif sql_file and table_selected:
                    source_name = table_selected
                else:
                    source_name = "unknown"
                scan_id = log_scan(source_name, score, violations, anon_report)
                for r in regex_results + nlp_results:
                    log_finding(scan_id, r.get("column", "unknown"), r.get("pattern", "unknown"), r.get("match", r.get("value", "N/A")))
                log_history(scan_id, "Scan completed")


                # Download buttons
                with open("output/compliance_report.pdf", "rb") as f:
                    st.download_button("📄 Download PDF Report", f, file_name="compliance_report.pdf")
                with open("output/compliance_report.csv", "rb") as f:
                    st.download_button("📈 Download CSV Report", f, file_name="compliance_report.csv")
                with open(anon_path, "rb") as f:
                    st.download_button("🕶 Download Anonymized Data", f, file_name="anonymized_data.csv")
