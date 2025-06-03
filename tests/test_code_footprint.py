import unittest
from src.scan.filesystem import code_footprint

class TestCodeFootprint(unittest.TestCase):
    def test_code_footprint_invalid_format(self):
        report = {"Results": []}
        with self.assertRaises(ValueError):
            code_footprint(report, output_format="invalid")

    def test_code_footprint_table(self):
        report = {"Results": []}
        result = code_footprint(report, output_format="table")
        self.assertIsInstance(result, str)

    def test_code_footprint_dataframe(self):
        report = {"Results": []}
        result = code_footprint(report, output_format="dataframe")
        self.assertTrue(hasattr(result, 'columns'))

if __name__ == "__main__":
    unittest.main()
