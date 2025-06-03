import unittest
from src.scan.util import filter_severity, sanitize_input, count_gpt_tokens, get_severity
import pandas as pd

class TestScanUtil(unittest.TestCase):
    def test_filter_severity(self):
        df = pd.DataFrame({"Severity": ["HIGH", "LOW", "CRITICAL", "MEDIUM", "HIGH"]})
        filtered = filter_severity(df, ["HIGH", "CRITICAL"], min_count=2)
        self.assertIsNotNone(filtered)
        self.assertTrue(all(filtered["Severity"].isin(["HIGH", "CRITICAL"])))

    def test_sanitize_input(self):
        text = "{test}%value%"
        sanitized = sanitize_input(text)
        self.assertNotIn("{", sanitized)
        self.assertNotIn("%", sanitized)

    def test_count_gpt_tokens(self):
        text = "hello world"
        tokens = count_gpt_tokens(text)
        self.assertIsInstance(tokens, int)
        self.assertGreater(tokens, 0)

    def test_get_severity(self):
        self.assertEqual(get_severity("HIGH"), ["HIGH", "CRITICAL"])
        self.assertEqual(get_severity("LOW"), ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertEqual(get_severity("UNKNOWN"), ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

if __name__ == "__main__":
    unittest.main()
