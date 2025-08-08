# 🛡️ Data Privacy Compliance Checker

**Automated tool for detecting and reporting potential data privacy violations in structured datasets.**  
Designed to support organizations in complying with GDPR, local Ethiopian privacy laws, and general data protection principles.

---

## 🚀 Features

 📂 Load CSV or Excel files
 🔍 Detect Personally Identifiable Information (PII):
  - Names, emails, phone numbers, national IDs, IPs, and more
 
 📊 Generate compliance score and risk rating
 
 📝 Export professional PDF/CSV compliance reports
 
 🌐 Streamlit-based web dashboard (lightweight and responsive)
 
 🔐 Optional anonymization of sensitive fields

---

## 📦 Technologies Used

| Component      | Tool/Library           |
|----------------|------------------------|
| Language       | Python 3.x             |
| Data Handling  | Pandas, OpenPyXL       |
| PII Detection  | Regex                  |
| UI Dashboard   | Streamlit              |
| Reports        | FPDF                   |
| File Formats   | CSV, XLSX              |

---

## 🧪 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/ezadin2/Group_19_cyber_Project.git
cd privacy-compliance-checker


Install Requirements

    bash
pip install -r requirements.txt

Run the Application

    bash
streamlit run main.py
or
python3 -m streamlit run app.py

🧠 How It Works

1, Upload your dataset via web UI or CLI.

2, The tool scans all columns and rows for patterns matching PII.

3, It generates:

    A compliance score

    Risk rating (Low, Medium, High)

    A PDF/CSV report of issues

Optional: Automatically anonymize/mask detected fields.



📁 Folder Structure

privacy_checker/
│
├── data/                 # Sample datasets
├── modules/              # Code modules
│   ├── file_loader.py
│   ├── pii_detector.py
│   ├── compliance_scoring.py
│   ├── report_generator.py
├── main.py               # Main entry point
├── requirements.txt
└── README.md


🛣️ Roadmap (Planned Features)
 Regex-based PII detection

 Compliance score + report

 Data anonymization engine

 NLP-based PII detection

 API integration

 Scan history & dashboard analytics

 Multi-language support

📃 License
this was made by
1.Abenezer Markos
2.Ezadin Badiru
3.Kaleab
4.William
5.Maranatha

MIT License. You are free to use and modify.






