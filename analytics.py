# analytics.py
import streamlit as st
import pandas as pd
import plotly.express as px
from modules.database import fetch_scans, fetch_history

# ---------------------------------------
# Page Config
# ---------------------------------------
st.set_page_config(page_title="📊 Advanced Analytics", layout="wide")
st.title("📊 Advanced Analytics Dashboard")
st.write("Explore historical compliance trends, PII insights, and anonymization effectiveness.")

# ---------------------------------------
# Fetch Data
# ---------------------------------------
scans_df = fetch_scans()
history_df = fetch_history()

if scans_df.empty and history_df.empty:
    st.warning("❌ No scans have been logged yet. Run `app.py` to record scans.")
    st.stop()

# ---------------------------------------
# Sidebar Filters
# ---------------------------------------
st.sidebar.header("📂 Filters")

# Date filter (history table is richer, fallback to scans_df if empty)
if not history_df.empty:
    min_date = pd.to_datetime(history_df["timestamp"]).min().date()
    max_date = pd.to_datetime(history_df["timestamp"]).max().date()
else:
    min_date = pd.to_datetime(scans_df["timestamp"]).min().date()
    max_date = pd.to_datetime(scans_df["timestamp"]).max().date()

date_range = st.sidebar.date_input("Select Date Range", value=(min_date, max_date))

# Filter Data
def apply_filters(df, date_range):
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        start_date, end_date = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
        df = df[(df["timestamp"] >= start_date) & (df["timestamp"] <= end_date)]
    return df

scans_df = apply_filters(scans_df, date_range)
history_df = apply_filters(history_df, date_range)

# ---------------------------------------
# Compliance Score Trend
# ---------------------------------------
if not scans_df.empty:
    st.subheader("📈 Compliance Score Trend")
    score_fig = px.line(
        scans_df,
        x="timestamp",
        y="score",
        markers=True,
        title="Compliance Score Over Time"
    )
    st.plotly_chart(score_fig, use_container_width=True)

# ---------------------------------------
# Most Common PII Types
# ---------------------------------------
if "pii_types_all" in history_df.columns and not history_df.empty:
    st.subheader("🔎 Most Common PII Types")
    all_types = history_df["pii_types_all"].dropna().astype(str).str.split(",")
    flat_types = pd.Series([t.strip() for sublist in all_types for t in sublist if t.strip() != ""])
    if not flat_types.empty:
        type_counts = flat_types.value_counts().reset_index()
        type_counts.columns = ["PII Type", "Count"]
        pii_fig = px.bar(type_counts, x="PII Type", y="Count", title="Most Frequently Detected PII Types")
        st.plotly_chart(pii_fig, use_container_width=True)
    else:
        st.info("No PII types detected in the selected scans.")

# ---------------------------------------
# Violation Frequencies
# ---------------------------------------
if "violations" in scans_df.columns and not scans_df.empty:
    st.subheader("⚠️ Violation Frequencies")
    vio_series = scans_df["violations"].dropna().astype(str).str.split(",")
    flat_vios = pd.Series([v.strip() for sublist in vio_series for v in sublist if v.strip() != ""])
    if not flat_vios.empty:
        vio_counts = flat_vios.value_counts().reset_index()
        vio_counts.columns = ["Violation", "Count"]
        vio_fig = px.bar(vio_counts, x="Violation", y="Count", title="Frequent Compliance Violations")
        st.plotly_chart(vio_fig, use_container_width=True)
    else:
        st.info("No violations recorded for the selected scans.")

# ---------------------------------------
# Anonymization Rate Trend
# ---------------------------------------
if "anonymization_rate" in scans_df.columns and not scans_df.empty:
    st.subheader("🔒 Anonymization Rate Over Time")
    anon_fig = px.line(
        scans_df,
        x="timestamp",
        y="anonymization_rate",
        markers=True,
        title="Anonymization Rate (%)"
    )
    st.plotly_chart(anon_fig, use_container_width=True)

# ---------------------------------------
# Full Scan History
# ---------------------------------------
st.subheader("📂 Scan History Table")
if not scans_df.empty:
    st.dataframe(scans_df, use_container_width=True)
else:
    st.info("No scan history available in the selected range.")
