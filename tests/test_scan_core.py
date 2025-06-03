import unittest
import os
import json
from src.scan import filesystem, image, aws, kubernetes

class TestFilesystemScan(unittest.TestCase):
    def test_scan_filesystem_invalid_path(self):
        result = filesystem.scan_filesystem(path="/invalid/path")
        self.assertFalse(result)

    def test_get_severity(self):
        self.assertEqual(filesystem.get_severity("HIGH"), ["HIGH", "CRITICAL"])
        self.assertEqual(filesystem.get_severity("LOW"), ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertIn("HIGH", filesystem.get_severity("MEDIUM"))

class TestImageScan(unittest.TestCase):
    def test_scan_image_invalid_path(self):
        result = image.scan_image(image_path="/invalid/image")
        self.assertFalse(result)

    def test_get_severity(self):
        self.assertEqual(image.get_severity("HIGH"), ["HIGH", "CRITICAL"])
        self.assertEqual(image.get_severity("LOW"), ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

class TestAWSScan(unittest.TestCase):
    def test_process_aws_scan_empty(self):
        report = {"Results": []}
        df = aws.process_aws_scan(report)
        self.assertTrue(df.empty)

class TestKubernetesScan(unittest.TestCase):
    def test_count_key_value_in_list_compact(self):
        dicts = [{"a": 1}, {"a": 2}, {"a": 1}]
        count = kubernetes.count_key_value_in_list_compact(dicts, "a", 1)
        self.assertEqual(count, 2)

if __name__ == "__main__":
    unittest.main()
