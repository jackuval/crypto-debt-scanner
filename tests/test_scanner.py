import unittest
import os
import json
import sys
import re
from io import StringIO
import tempfile
import shutil
from unittest.mock import patch

# This is a hack to import the scanner module from the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import scanner

class TestCryptoDebtScanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.patterns = scanner.load_patterns(scanner.DEFAULT_PATTERNS_FILE)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _create_test_file(self, content, filename="test.py"):
        file_path = os.path.join(self.test_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)
        return file_path

    def test_scan_file_md5_case_insensitivity(self):
        file_path = self._create_test_file("import hashlib\\nhash = hashlib.md5()")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['pattern'], "\\bMD5\\b")

    def test_scan_file_strcpy_in_c_file(self):
        c_code = 'int main() { strcpy(buffer, "hello"); }'
        file_path = self._create_test_file(c_code, filename="test.c")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 1, "Failed to find strcpy")
        self.assertEqual(findings[0]['pattern'], "\\bstrcpy\\s*\\(")

    @patch('sys.stdout', new_callable=StringIO)
    def test_json_output_format(self, mock_stdout):
        self._create_test_file("hash = hashlib.md5()")
        with patch.object(sys, 'argv', ['scanner.py', self.test_dir, '--format', 'json']):
            scanner.main()
        output = json.loads(mock_stdout.getvalue())
        self.assertEqual(output['summary']['total_issues'], 1)
        self.assertEqual(output['findings'][0]['severity'], 'High')

    @patch('sys.stdout', new_callable=StringIO)
    def test_severity_filtering(self, mock_stdout):
        self._create_test_file("hash = hashlib.md5()\\nval = random()") # High and Medium
        with patch.object(sys, 'argv', ['scanner.py', self.test_dir, '--format', 'json', '--min-severity', 'High']):
            scanner.main()
        output = json.loads(mock_stdout.getvalue())
        self.assertEqual(output['summary']['total_issues'], 1)
        self.assertEqual(output['findings'][0]['severity'], 'High')

    @patch('sys.stdout', new_callable=StringIO)
    def test_include_filtering(self, mock_stdout):
        self._create_test_file("hash = hashlib.md5()", "test.py")
        self._create_test_file("strcpy(dest, src)", "test.c")
        with patch.object(sys, 'argv', ['scanner.py', self.test_dir, '--format', 'json', '--include', '.py']):
            scanner.main()
        output = json.loads(mock_stdout.getvalue())
        self.assertEqual(output['summary']['total_issues'], 1)
        self.assertEqual(output['findings'][0]['file'].endswith('.py'), True)

    @patch('sys.stdout', new_callable=StringIO)
    def test_exclude_filtering(self, mock_stdout):
        self._create_test_file("hash = hashlib.md5()", "test.py")
        self._create_test_file("strcpy(dest, src)", "test.c")
        with patch.object(sys, 'argv', ['scanner.py', self.test_dir, '--format', 'json', '--exclude', '.c']):
            scanner.main()
        output = json.loads(mock_stdout.getvalue())
        self.assertEqual(output['summary']['total_issues'], 1)
        self.assertEqual(output['findings'][0]['file'].endswith('.py'), True)

if __name__ == '__main__':
    unittest.main()
