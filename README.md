# 🔐 Data Privacy Compliance Checker

A **Streamlit-based tool** for scanning datasets or SQL tables for **PII (Personally Identifiable Information)**, checking **compliance rules**, applying **anonymization techniques**, and generating **reports** with full scan history tracking.

## ✨ Features

* 📂 **Data Input**

  * Upload CSV / Excel files
  * Upload and scan SQLite databases

* 🔍 **PII Detection**

  * Regex-based detection (email, phone, credit card, SSN, IP, passport, name, address, etc.)
  * NLP-based detection (person, organization, location using spaCy)

* 📋 **Compliance Scoring**

  * Define rules (`max_pii_fields`, allowed PII types, anonymization required)
  * Automatic compliance check with score & violations

* 🛡 **Anonymization**

  * Multiple methods: `mask`, `hash`, `redact`, `fake`, `pseudonymize`
  * Per-PII type method selection
  * Verification of anonymization success

* 📊 **Compliance Summary Dashboard**

  * Scan history viewer (date & source filters)
  * Compliance score trends
  * Most frequent PII types
  * Violation frequencies
  * Anonymization rate over time

* 📑 **Reporting & Export**

  * PDF & CSV compliance reports
  * Save anonymized datasets
  * Scan history stored in `output/scan_history.csv`

---

🧠 How It Works

1, Upload your dataset via web UI or CLI.

2, The tool scans all columns and rows for patterns matching PII.

3, It generates:

    A compliance score

    Risk rating (Low, Medium, High)

    A PDF/CSV report of issues

Optional: Automatically anonymize/mask detected fields.


---


## 📦 Technologies Used

| Component      | Tool/Library           |
|----------------|------------------------|
| Language       | Python 3.x             |
| Data Handling  | Pandas, OpenPyXL       |
| PII Detection  | Regex                  |
| UI Dashboard   | Streamlit              |
| Reports        | FPDF                   |
| File Formats   | CSV, XLSX, sql light   |             |
| PII Detection & NLP |  spaCy (for named entity recognition), regex (for pattern-based PII detection) |
| Visualization  | matplotlib / seaborn / plotly (for graphs, compliance summaries, trends)  |
| Anonymization  |  Custom anonymization functions (masking, pseudonymization, or hashing)  |
|Security/Validation | Custom logic for compliance scoring, audit logging, and error handling |
---


## 📦 Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/JULIASIV/privacy-checker.git
   cd privacy-checker
   ```

2. Create a virtual environment and install dependencies:

   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/Mac
   venv\Scripts\activate      # Windows

   pip install -r requirements.txt
   ```

3. Run the app:
  - for it to run you must be in the directry of the folder/ project in your terminalbash or git - bash

   ```bash/ terminal
   streamlit run app.py
```
  - or use this if you have multiple version of python
   ```
   python3 -m streamlit run app.py
   ```

---

## 📂 Project Structure

```
privacy_checker/
│── app.py                     # Main Streamlit application
│
├── modules/
│   ├── anonymize_data.py      # Advanced anonymization functions
│   ├── pii_detector.py        # Regex + NLP PII detection
│   ├── compliance_scoring.py  # Compliance scoring & rule checks
│   ├── history_logger.py      # Logs scan history
│   ├── report_generator.py    # PDF & CSV reporting
│   ├── db_loader.py           # SQLite loader
│   └── file_loader.py         # CSV/Excel loader
│
├── output/                    # Reports & scan history
│   ├── anonymized_data.csv
│   ├── compliance_report.pdf
│   ├── compliance_report.csv
│   └── scan_history.csv
│
└── requirements.txt           # Python dependencies
│
│──dashboard.py
│
│──check_setup.py
│
│──temp/       # contains temporary files which have been scanned 
│
│──config/     # Configuration files and rules configuration in .json file format
│
│──main.py     # cli work format in terminal or bash
│
│──readme.md
│
│──histry/      # contains scan history in cvs format 
│
│──test/
│
│── data/  # contains sample datas to test the app

```

--- requirements

this libreries are required for this project to work sucsessfully

plotly
sqlite3
modules
openpyxlythis   ththis z'
pandas
matlib
os
csv
json
logging
hashlib
streamlit
plotly.express
fpdf
re
date
faker
xlsxwriter
matplotlib
collections
spacy


## ⚙️ Usage

1. Go to **Privacy Scanner**:

   * Upload a dataset (CSV/Excel/SQLite).
   * Run a scan to detect PII.
   * View compliance score & violations.
   * Choose anonymization methods per PII type.
   * Download anonymized dataset + compliance reports.

2. Go to **Compliance Summary Dashboard**:

   * View scan history.
   * Analyze compliance score trends.
   * Check most common PII types.
   * Review frequent violations.
   * Track anonymization success over time.

---

## how to test the program without running the program it self

you can run the test_pii_detector.py  function which is locates in the test folder test/

Option 1: Run tests from project root

```
cd test
python3 test_pii_detector.py
```

Option 2: Run tests from test directory

```
cd C:\Users\tb124\downloads\privacy_checker
python3 -m pytest tests/
```

---
## 📊 Example Output

* **Detection Results**: List of sensitive columns and detected patterns.
* **Compliance Report**: PDF + CSV with score & violations.
* **Anonymized Dataset**: Downloadable CSV with masked/hashed/faked values.
* **Dashboard**: Visual trends for compliance & anonymization across multiple scans.

---
## 🛣️ Roadmap (Planned Features)

 *Regex-based PII detection
 **Advanced NLP** for contextual PII detection
 * Support for **Excel export** of scan history
 * Custom rule editor in-app
 * Severity levels for PII violations (High/Medium/Low)
 * Smart compliance summaries
 *Compliance score + report
 *NLP-based PII detection
 *API integration
 *Multi-language support

📃 License
this was made by
1.Abenezer Markos
2.Ezadin Badiru
3.Kaleab
4.William
5.Maranatha

MIT License. You are free to use and modify.

```
this project is still being devloped so stay tuned for futer updated and news...
```







