# test_pii_detector.py

import unittest
import pandas as pd
import sys
import os
from modules.pii_detector import detect_sensitive_data

#Add the modules directory to the Python path
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__), '../modules')))

class TestPIIDetector(unittest.TestCase):
    def test_detect_email_and_phone(self):
        data = {
            'email': ['test@example.com'],
            'phone': ['+251912345678'],
            'note': ['nothing here']
        }
        df = pd.DataFrame(data)
        results = detect_sensitive_data(df)
        patterns_found = [res['pattern'] for res in results]
        self.assertIn('email', patterns_found)
        self.assertIn('phone', patterns_found)

if __name__ == '__main__':
    unittest.main()
