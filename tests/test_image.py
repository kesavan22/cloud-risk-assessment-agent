import unittest
from src.scan.image import container_footprint

class TestImageFunctions(unittest.TestCase):
    def test_container_footprint_invalid_format(self):
        report = {"Results": []}
        with self.assertRaises(ValueError):
            container_footprint(report, output_format="invalid")

    def test_container_footprint_table(self):
        report = {"Results": []}
        result = container_footprint(report, output_format="table")
        self.assertIsInstance(result, str)

    def test_container_footprint_dataframe(self):
        report = {"Results": []}
        result = container_footprint(report, output_format="dataframe")
        self.assertTrue(hasattr(result, 'columns'))

if __name__ == "__main__":
    unittest.main()
