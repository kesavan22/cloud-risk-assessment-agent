import unittest
from src.scan.aws import process_aws_scan

class TestAWSFunctions(unittest.TestCase):
    def test_process_aws_scan_empty(self):
        report = {"Results": []}
        df = process_aws_scan(report)
        self.assertTrue(df.empty)

    def test_process_aws_scan_basic(self):
        report = {"Results": [{"Misconfigurations": [{"ID": "1", "AVDID": "AVD-1", "Title": "Test", "Description": "desc", "Resolution": "fix", "Severity": "HIGH", "Message": "msg", "CauseMetadata": {"Resource": "res1"}}]}]}
        df = process_aws_scan(report)
        self.assertFalse(df.empty)
        self.assertIn("resource_name", df.columns)

if __name__ == "__main__":
    unittest.main()
