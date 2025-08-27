# modules/report_generator.py

from fpdf import FPDF
import csv
import os
from datetime import datetime

def generate_csv_report(results, score, violations):
    os.makedirs("output", exist_ok=True)
    with open("output/compliance_report.csv", mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Column", "Pattern", "Matches Found"])
        for row in results:
            writer.writerow([row["column"], row["pattern"], row["matches_found"]])

        writer.writerow([])
        writer.writerow(["Compliance Score", score])
        writer.writerow([])

        writer.writerow(["Violations"])
        if violations:
            for v in violations:
                writer.writerow([v])
        else:
            writer.writerow(["None"])

def generate_pdf_report(results, score, violations):
    os.makedirs("output", exist_ok=True)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(200, 10, txt="Data Privacy Compliance Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Generated: {timestamp}", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="PII Detection Summary", ln=True)
    pdf.set_font("Arial", size=12)
    for row in results:
        pdf.cell(200, 10, txt=f"- {row['column']} matched {row['pattern']} ({row['matches_found']}x)", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Compliance Score", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"{score}%", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Violations", ln=True)
    pdf.set_font("Arial", size=12)
    if violations:
        for v in violations:
            pdf.cell(200, 10, txt=f"- {v}", ln=True)
    else:
        pdf.cell(200, 10, txt="None ", ln=True)

    pdf.output("output/compliance_report.pdf")
