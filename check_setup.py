import os
import importlib.util
import subprocess
import sys

REQUIRED_FOLDERS = ['modules', 'data', 'output', 'temp', 'test', 'config', 'history', 'logs']
REQUIRED_MODULES = [
    'file_loader', 'pii_detector', 'compliance_scoring',
    'report_generator', 'anonymize_data', 'db_loader',
    'nlp_detector', 'rule_editor', 'compliance_advisor'  # Added new planned modules
]

# Updated package list with new dependencies for advanced features
EXTERNAL_PACKAGES = [
    'streamlit', 'pandas', 'fpdf', 'plotly', 'openpyxl',
    'faker', 'xlsxwriter', 'matplotlib', 'spacy', 'cryptography',
    'sqlalchemy', 'numpy', 'scikit-learn', 'seaborn', 'pillow',
    'python-docx', 'phonenumbers', 'names-dataset'  # Added new dependencies
]
STANDARD_MODULES = [
    'sqlite3', 'csv', 'json', 'logging', 'hashlib', 'hmac',
    're', 'datetime', 'collections', 'uuid', 'secrets', 'ipaddress'
]

def check_folders():
    print(" Checking required folders...")
    for folder in REQUIRED_FOLDERS:
        if not os.path.isdir(folder):
            print(f" ❌ Folder missing: {folder}")
        else:
            print(f" ✅ Folder exists: {folder}")
    print()

def check_modules():
    print(" Checking module files in 'modules/'...")
    for mod in REQUIRED_MODULES:
        path = os.path.join("modules", f"{mod}.py")
        if not os.path.isfile(path):
            print(f" ❌ Missing module: {path}")
        else:
            print(f" ✅ Found module: {path}")
    print()

def check_packages():
    print(" Checking required Python packages...")
    for pkg in EXTERNAL_PACKAGES:
        if importlib.util.find_spec(pkg) is None:
            print(f" ❌ Missing package: {pkg}")
        else:
            print(f" ✅ Package available: {pkg}")

    # Standard modules (just confirm import works)
    for mod in STANDARD_MODULES:
        try:
            __import__(mod)
            print(f" ✅ Standard module available: {mod}")
        except ImportError:
            print(f" ❌ Standard module missing (unexpected): {mod}")
    print()

def check_requirements_file():
    print(" Checking requirements.txt...")
    if not os.path.isfile("requirements.txt"):
        print(" ❌ requirements.txt not found.")
    else:
        print(" ✅ requirements.txt found.")
        # Check if requirements are installed
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "check", "-r", "requirements.txt"])
            print(" ✅ All requirements are compatible.")
        except subprocess.CalledProcessError:
            print(" ⚠️ Some requirements may have compatibility issues.")
    print()

def check_test_files():
    print(" Checking test folder...")
    if not os.path.isdir("test"):
        print(" ❌ test folder not found.")
    else:
        test_files = [f for f in os.listdir("test") if f.startswith("test_") and f.endswith(".py")]
        if test_files:
            print(f" ✅ Found test files: {', '.join(test_files)}")
        else:
            print(" ⚠️ No test files found in /test")
    print()

def check_spacy_model():
    print(" Checking SpaCy language model (for NLP detection)...")
    try:
        import spacy
        try:
            # Try to load the English model
            nlp = spacy.load("en_core_web_sm")
            print(" ✅ SpaCy model 'en_core_web_sm' found.")
        except OSError:
            print(" ⚠️ SpaCy model not downloaded. Run: python -m spacy download en_core_web_sm")
    except ImportError:
        print(" ❌ SpaCy not installed.")
    print()

def check_config_files():
    print(" Checking configuration files...")
    config_files = ['config/config.ini', 'config/pii_patterns.json', 'config/compliance_rules.json']
    for config_file in config_files:
        if not os.path.isfile(config_file):
            print(f" ⚠️ Configuration file missing: {config_file}")
        else:
            print(f" ✅ Configuration file found: {config_file}")
    print()

def run_all_checks():
    print("\n🔍 Running project setup checks...\n")
    check_folders()
    check_modules()
    check_packages()
    check_requirements_file()
    check_test_files()
    check_spacy_model()
    check_config_files()
    print(" ✅ Setup check complete.\n")
    print(" If you see ❌ errors, please fix them before running the app.")
    print(" ⚠️  Warnings indicate recommended but not strictly required components.")

if __name__ == "__main__":
    run_all_checks()