# dashboard.py

import streamlit as st
import pandas as pd
import os
import plotly.express as px
from modules.database import fetch_scans, fetch_history

# Page config
st.set_page_config(page_title="📊 Privacy Compliance Dashboard", layout="wide")

st.title("🛡 Privacy Compliance Dashboard")

# ==============================
# 🔎 Global Filters (Sidebar)
# ==============================
st.sidebar.header("📂 Global Filters")

# Default paths (CSV-based fallback)
results_path = "output/results.csv"
report_path = "output/compliance_report.csv"

# Load database history to get global date range
try:
    history_df_full = fetch_history()
    scans_df_full = fetch_scans()
except Exception:
    history_df_full = pd.DataFrame()
    scans_df_full = pd.DataFrame()

# Decide global min/max date
if not history_df_full.empty:
    min_date = pd.to_datetime(history_df_full["timestamp"]).min().date()
    max_date = pd.to_datetime(history_df_full["timestamp"]).max().date()
elif not scans_df_full.empty:
    min_date = pd.to_datetime(scans_df_full["timestamp"]).min().date()
    max_date = pd.to_datetime(scans_df_full["timestamp"]).max().date()
else:
    min_date = pd.to_datetime("2025-01-01").date()
    max_date = pd.to_datetime("today").date()

# Sidebar filter
date_range = st.sidebar.date_input("Select Date Range", value=(min_date, max_date))

def apply_filters(df, date_range):
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        start_date, end_date = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
        df = df[(df["timestamp"] >= start_date) & (df["timestamp"] <= end_date)]
    return df

# Apply global filters
scans_df = apply_filters(scans_df_full, date_range)
history_df = apply_filters(history_df_full, date_range)

# ==============================
# Tabs: Summary + Analytics
# ==============================
tab1, tab2 = st.tabs(["📊 Compliance Summary", "📈 Advanced Analytics"])

# ==============================
# 📊 Compliance Summary (Tab 1)
# ==============================
with tab1:
    st.header("📊 Compliance Summary")

    if not os.path.exists(results_path) or not os.path.exists(report_path):
        st.warning("❌ No scan results found. Please run a scan first using `app.py`.")
    else:
        # Load CSV fallback results
        results_df = pd.read_csv(results_path)
        report_df = pd.read_csv(report_path)

        # Extract compliance score + violations
        score = None
        violations = []
        for i in range(len(report_df)):
            row_values = report_df.iloc[i].values
            if "Compliance Score" in str(row_values):
                try:
                    next_row = report_df.iloc[i + 1].values
                    score = float(next_row[0])
                except (IndexError, ValueError):
                    score = None
            elif "Violations" in str(row_values):
                for j in range(i + 1, len(report_df)):
                    violation = report_df.iloc[j].values[0]
                    if pd.notnull(violation) and violation != "None":
                        violations.append(violation)
                break

        # --- Metrics Layout ---
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="🛡 Compliance Score", value=f"{score}%" if score else "N/A")
        with col2:
            st.metric(label="📂 PII Columns", value=results_df['column'].nunique())
        with col3:
            st.metric(label="⚠️ Violations", value=len(violations))

        # Bar Chart: PII Types Detected
        st.subheader("📊 Detected PII by Type")
        bar_fig = px.bar(
            results_df.groupby("pattern").size().reset_index(name="Count"),
            x="pattern", y="Count", color="pattern",
            title="Number of Detected PII Patterns"
        )
        st.plotly_chart(bar_fig, use_container_width=True)

        # Pie Chart: PII Distribution
        st.subheader("🥧 PII Distribution by Type")
        pie_fig = px.pie(
            results_df, names="pattern", title="Distribution of PII Types"
        )
        st.plotly_chart(pie_fig, use_container_width=True)

        # Table: Detailed Violations
        if violations:
            st.subheader("🚫 Detected Violations")
            st.write(pd.DataFrame(violations, columns=["Violation Message"]))
        else:
            st.success("✅ No violations found!")

        # Optional: Raw Results
        with st.expander("📄 Show Raw Detection Results"):
            st.dataframe(results_df, use_container_width=True)

# ==============================
# 🔍 Scan Comparison View
# ==============================
st.subheader("🔍 Compare Two Scans")

if scans_df.empty:
    st.info("No scans available for comparison yet.")
else:
    scan_options = scans_df["id"].astype(str) + " | " + scans_df["timestamp"].astype(str)
    scan1 = st.selectbox("Select First Scan", scan_options, key="scan1")
    scan2 = st.selectbox("Select Second Scan", scan_options, key="scan2")

    if scan1 and scan2 and scan1 != scan2:
        id1, id2 = scan1.split(" | ")[0], scan2.split(" | ")[0]
        scan1_data = scans_df[scans_df["id"] == int(id1)].iloc[0]
        scan2_data = scans_df[scans_df["id"] == int(id2)].iloc[0]

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Compliance Score", f"{scan1_data['score']}%")
            st.metric("Violations", scan1_data["violations"])
            st.metric("Anon. Rate", f"{scan1_data.get('anonymization_rate', 'N/A')}%")
        with col2:
            st.metric("Compliance Score", f"{scan2_data['score']}%")
            st.metric("Violations", scan2_data["violations"])
            st.metric("Anon. Rate", f"{scan2_data.get('anonymization_rate', 'N/A')}%")

        # Differences
        st.subheader("📉 Changes")
        diff_score = scan2_data["score"] - scan1_data["score"]
        diff_vio = scan2_data["violations"] - scan1_data["violations"]
        diff_anon = scan2_data.get("anonymization_rate", 0) - scan1_data.get("anonymization_rate", 0)

        st.write(f"Compliance Score Change: {'🟢' if diff_score > 0 else '🔴'} {diff_score:+.2f}%")
        st.write(f"Violations Change: {'🟢' if diff_vio < 0 else '🔴'} {diff_vio:+}")
        st.write(f"Anonymization Rate Change: {'🟢' if diff_anon > 0 else '🔴'} {diff_anon:+.2f}%")

# ==============================
# 📈 Advanced Analytics (Tab 2)
# ==============================
with tab2:
    st.header("📈 Advanced Analytics")

    if scans_df.empty and history_df.empty:
        st.warning("❌ No database scan history available.")
    else:
        # Compliance Score Trend
        if not scans_df.empty:
            st.subheader("📈 Compliance Score Trend")
            score_fig = px.line(scans_df, x="timestamp", y="score", markers=True, title="Compliance Score Over Time")
            st.plotly_chart(score_fig, use_container_width=True)

        # Most Common PII Types
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

        # Violation Frequencies
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

        # Anonymization Rate Trend
        if "anonymization_rate" in scans_df.columns and not scans_df.empty:
            st.subheader("🔒 Anonymization Rate Over Time")
            anon_fig = px.line(scans_df, x="timestamp", y="anonymization_rate", markers=True, title="Anonymization Rate (%)")
            st.plotly_chart(anon_fig, use_container_width=True)

        # Full Scan History Table
        st.subheader("📂 Scan History Table")
        st.dataframe(scans_df, use_container_width=True)



# ==============================
# 📤 Export & Reporting Section

# ==============================
st.header("📤 Export & Reporting")

if not scans_df.empty:
    st.subheader("⬇️ Export Scan Data")
    export_choice = st.radio(
        "Choose export format:",
        ["CSV", "Excel", "PDF"],
        horizontal=True,
        key="export_choice"
    )

    if st.button("Export Now"):
        if export_choice == "CSV":
            export_path = "output/exported_scans.csv"
            scans_df.to_csv(export_path, index=False)
            st.success(f"✅ Exported scans to {export_path}")

        elif export_choice == "Excel":
            export_path = "output/exported_scans.xlsx"
            scans_df.to_excel(export_path, index=False)
            st.success(f"✅ Exported scans to {export_path}")

        elif export_choice == "PDF":
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            import matplotlib.pyplot as plt

            export_path = "output/compliance_report.pdf"
            doc = SimpleDocTemplate(export_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            # Title
            story.append(Paragraph("📊 Privacy Compliance Report", styles['Title']))
            story.append(Spacer(1, 20))

            # Summary
            if "score" in scans_df.columns:
                latest_score = scans_df.iloc[0]["score"]
                story.append(Paragraph(f"<b>Latest Compliance Score:</b> {latest_score}%", styles['Normal']))
            story.append(Spacer(1, 12))

            # Table
            table_data = [scans_df.columns.tolist()] + scans_df.head(10).values.tolist()
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ]))
            story.append(table)
            story.append(Spacer(1, 20))

            # ==============================
            # 📊 Add Charts into PDF
            # ==============================
            def save_chart(fig, filename):
                fig.savefig(filename, format="png", bbox_inches="tight")
                plt.close(fig)
                story.append(Image(filename, width=400, height=250))
                story.append(Spacer(1, 12))

            # Compliance Score Trend
            if "score" in scans_df.columns:
                fig, ax = plt.subplots()
                scans_df.plot(x="timestamp", y="score", ax=ax, marker="o", title="Compliance Score Over Time")
                save_chart(fig, "output/score_trend.png")

            # PII Types Distribution
            if "pattern" in scans_df.columns:
                fig, ax = plt.subplots()
                scans_df["pattern"].value_counts().plot(kind="bar", ax=ax, title="Detected PII Types")
                save_chart(fig, "output/pii_bar.png")

            # Violations
            if "violations" in scans_df.columns:
                fig, ax = plt.subplots()
                scans_df["violations"].astype(str).value_counts().plot(kind="bar", ax=ax, title="Violation Frequencies")
                save_chart(fig, "output/violations_bar.png")

            # Anonymization Rate Trend
            if "anonymization_rate" in scans_df.columns:
                fig, ax = plt.subplots()
                scans_df.plot(x="timestamp", y="anonymization_rate", ax=ax, marker="o", title="Anonymization Rate (%)")
                save_chart(fig, "output/anonymization_trend.png")

            # Build PDF
            doc.build(story)
            st.success(f"✅ Exported full compliance report to {export_path}")

else:
    st.info("No scan data available for export.")
