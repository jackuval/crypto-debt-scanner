import unittest
import os
import json
import sys
import re
import argparse
from io import StringIO
import tempfile
import shutil
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import scanner

class TestCryptoDebtScannerV8(unittest.TestCase):

    def setUp(self):
        self.base_test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.base_test_dir)

    def _create_test_file(self, content, filename="test.py", subdir=None):
        test_dir = self.base_test_dir
        if subdir:
            test_dir = os.path.join(self.base_test_dir, subdir)
            if not os.path.exists(test_dir):
                os.mkdir(test_dir)
        file_path = os.path.join(test_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)
        return file_path

    def run_scanner(self, cli_args):
        with patch.object(sys, 'argv', ['scanner.py'] + cli_args):
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                scanner.main()
                return mock_stdout.getvalue()

    def test_ignore_comments(self):
        patterns = scanner.load_patterns(argparse.Namespace(patterns=None, no_default_patterns=False))
        file_path = self._create_test_file("hashlib.md5() # cryptoscan-ignore")
        self.assertEqual(len(scanner.scan_file(file_path, patterns)), 0)
        file_path_2 = self._create_test_file("hashlib.md5() # cryptoscan-ignore: \\bMD5\\b")
        self.assertEqual(len(scanner.scan_file(file_path_2, patterns)), 0)
        file_path_3 = self._create_test_file("hashlib.md5() # cryptoscan-ignore: \\bSHA1\\b")
        self.assertEqual(len(scanner.scan_file(file_path_3, patterns)), 1)

    def test_no_default_patterns_flag(self):
        scan_dir = os.path.join(self.base_test_dir, 'src')
        os.mkdir(scan_dir)
        self._create_test_file("hashlib.md5()", subdir='src')
        custom_patterns = { "Custom": [{"pattern": "custom_func", "description": "c", "severity": "Low"}] }
        patterns_path = self._create_test_file(json.dumps(custom_patterns), "custom.json")
        self._create_test_file("custom_func()", subdir='src', filename="custom.py")
        output = self.run_scanner([scan_dir, '--patterns', patterns_path, '--no-default-patterns', '--format', 'json'])
        result = json.loads(output)
        self.assertEqual(result['summary']['total_issues'], 1)
        self.assertEqual(result['findings'][0]['pattern'], "custom_func")

    def test_merge_patterns(self):
        scan_dir = os.path.join(self.base_test_dir, 'src')
        os.mkdir(scan_dir)
        self._create_test_file("hashlib.md5()", subdir='src')
        custom_patterns = { "Custom": [{"pattern": "custom_func", "description": "c", "severity": "Low"}] }
        patterns_path = self._create_test_file(json.dumps(custom_patterns), "custom.json")
        self._create_test_file("custom_func()", subdir='src', filename="custom.py")
        output = self.run_scanner([scan_dir, '--patterns', patterns_path, '--format', 'json'])
        result = json.loads(output)
        self.assertEqual(result['summary']['total_issues'], 2)

if __name__ == '__main__':
    unittest.main()
