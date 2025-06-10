import unittest
from unittest.mock import patch, MagicMock
import argparse
from src.scan.scan_resource import arg_parse, SR

class TestScanResource(unittest.TestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--scan-config-path", type=str, default="/tmp/tmcybertron/agent.yaml", help="Path to the scan configuration file.")

    @patch('src.scan.scan_resource.get_scan_config')
    @patch.object(SR, 'scan')
    def test_main_function(self, mock_scan, mock_get_scan_config):
        # Mock the configurations to be returned by get_scan_config
        mock_get_scan_config.return_value = {'resource_type': 'example_type'}

        # Mock the scan method
        mock_scan.return_value = None

        # Run the main functionality with arguments
        with patch('argparse.ArgumentParser.parse_args', return_value=self.parser.parse_args(['--scan-config-path', '/path/to/config.yaml'])):
            args = arg_parse()

        # Check if the scan method was called with correct parameters
        SR.scan.assert_called_with(resource_type='example_type', config_path='/path/to/config.yaml')

        # Ensure the get_scan_config was called
        mock_get_scan_config.assert_called_with('/path/to/config.yaml')

if __name__ == '__main__':
    unittest.main()
