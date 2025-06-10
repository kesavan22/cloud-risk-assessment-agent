import unittest
from unittest.mock import patch, MagicMock
from src.scan.scan_resource import arg_parse, SR

class TestScanResource(unittest.TestCase):
    @patch('src.scan.scan_resource.get_scan_config')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(scan_config_path='test_path.yaml'))
    def test_arg_parse(self, mock_args, mock_get_scan_config):
        args = arg_parse()
        self.assertEqual(args.scan_config_path, 'test_path.yaml')

    @patch.object(SR, 'scan')
    @patch('src.scan.scan_resource.get_scan_config', return_value={'mock_type': None})
    def test_scan_execution(self, mock_get_scan_config, mock_scan):
        args = argparse.Namespace(scan_config_path='test_path.yaml')
        scan_config = mock_get_scan_config(args.scan_config_path)
        for scan_type, _ in scan_config.items():
            SR.scan(resource_type=scan_type, config_path=args.scan_config_path)
        
        mock_scan.assert_called_once_with(resource_type='mock_type', config_path='test_path.yaml')

if __name__ == '__main__':
    unittest.main()