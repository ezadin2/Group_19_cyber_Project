# privacy_checker/main.py (cleaned and fixed)

import os
import csv
import json
from modules.file_loader import load_data
from modules.pii_detector import detect_sensitive_data
from modules.compliance_scoring import score_compliance
from modules.report_generator import generate_pdf_report, generate_csv_report
from modules.anonymize_data import anonymize_dataset
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def save_results(results, output_path="output/results.csv"):
    os.makedirs("output", exist_ok=True)
    with open(output_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["column", "pattern", "matches_found"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

def load_rules(path="config/rules.json"):
    with open(path, "r") as file:
        return json.load(file)

def main():
    path = "data/sample_data.csv"
    logging.info(f"Scanning file: {path}")

    df = load_data(path)
    rules = load_rules()

    # Detect PII
    results = detect_sensitive_data(df)
    pii_columns = list(set([r["column"] for r in results]))

    # Anonymization
    if rules.get("anonymization_required", False):
        df = anonymize_dataset(df.copy(), pii_columns, method="mask")
        df.to_csv("output/anonymized_data.csv", index=False)
        logging.info("Anonymized dataset saved to output/anonymized_data.csv")

    # Compliance scoring
    score, violations = score_compliance(results, rules)
    logging.info(f"Compliance Score: {score}%")
    if violations:
        logging.warning("Violations found:")
        for v in violations:
            logging.warning(f" - {v}")
    else:
        logging.info("All checks passed ✅")

    # Save detection results
    if results:
        logging.info("Sensitive data found:")
        for r in results:
            logging.info(f" - {r['column']} matches {r['pattern']} ({r['matches_found']})")
        save_results(results)
        logging.info("Results saved to output/results.csv")
    else:
        logging.info("No sensitive data found. ✅")

    # Generate reports
    generate_csv_report(results, score, violations)
    generate_pdf_report(results, score, violations)
    logging.info("PDF and CSV reports saved to output/")

if __name__ == "__main__":
    main()
