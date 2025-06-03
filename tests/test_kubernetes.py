import unittest
import yaml
from src.scan.kubernetes import count_key_value_in_list_compact, k8s_all_resource_misconfigure

class TestKubernetesFunctions(unittest.TestCase):
    def test_count_key_value_in_list_compact(self):
        dicts = [{"a": 1}, {"a": 2}, {"a": 1}]
        count = count_key_value_in_list_compact(dicts, "a", 1)
        self.assertEqual(count, 2)

    def test_k8s_all_resource_misconfigure_empty(self):
        report = {"ClusterName": "test", "Resources": []}
        result = k8s_all_resource_misconfigure(report)
        self.assertIn("Cluster_Name: test", result)

    def test_k8s_all_resource_misconfigure_with_resources(self):
        report = {
            "ClusterName": "test",
            "Resources": [
                {
                    "Kind": "Deployment",
                    "Name": "api-gateway",
                    "Results": [
                        {
                            "Misconfigurations": [
                                {
                                    "AVDID": "AVD-KSV-0001",
                                    "Title": "Test Misconfig",
                                    "Description": "desc",
                                    "Resolution": "fix",
                                    "Severity": "HIGH"
                                },
                                {
                                    "AVDID": "AVD-KSV-0002",
                                    "Title": "Test Misconfig 2",
                                    "Description": "desc2",
                                    "Resolution": "fix2",
                                    "Severity": "LOW"
                                }
                            ]
                        }
                    ]
                },
                {
                    "Kind": "Pod",
                    "Name": "worker",
                    "Results": [
                        {
                            "Misconfigurations": [
                                {
                                    "AVDID": "AVD-KSV-0001",
                                    "Title": "Test Misconfig",
                                    "Description": "desc",
                                    "Resolution": "fix",
                                    "Severity": "HIGH"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        result = k8s_all_resource_misconfigure(report)
        self.assertIn("Cluster_Name: test", result)
        self.assertIn("AVD-KSV-0001", result)
        self.assertIn("Test Misconfig", result)
        self.assertIn("Resources", result)
        # Check that resource count is correct (should be 2 for AVD-KSV-0001)
        parsed = list(yaml.safe_load_all(result))
        found = False
        for item in parsed:
            if isinstance(item, dict) and item.get("ID") == "AVD-KSV-0001":
                self.assertEqual(item["Resources"], 2)
                found = True
        self.assertTrue(found)

if __name__ == "__main__":
    unittest.main()
