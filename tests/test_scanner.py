import unittest
import os
import json
import sys
import re
from io import StringIO
import tempfile
import shutil

# This is a hack to import the scanner module from the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import scanner

class TestCryptoDebtScanner(unittest.TestCase):

    def setUp(self):
        """Set up a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()
        self.patterns = scanner.load_patterns(scanner.DEFAULT_PATTERNS_FILE)
        # Fix for the bug I found yesterday - case-insensitivity
        for category in self.patterns:
            for rule in self.patterns[category]:
                try:
                    rule['regex'] = re.compile(rule['pattern'], re.IGNORECASE)
                except re.error:
                    rule['regex'] = None


    def tearDown(self):
        """Remove the temporary directory."""
        shutil.rmtree(self.test_dir)

    def _create_test_file(self, content, filename="test.py"):
        """Helper to create a file with content in the temp directory."""
        file_path = os.path.join(self.test_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)
        return file_path

    def test_scan_file_md5_case_insensitivity(self):
        """Test that the MD5 check is case-insensitive."""
        file_path = self._create_test_file("import hashlib\\nhash = hashlib.md5()")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['pattern'], "\\bMD5\\b")
        self.assertEqual(findings[0]['severity'], "High")

    def test_scan_file_no_findings(self):
        """Test a file with no vulnerabilities."""
        file_path = self._create_test_file("print('This is a safe string.')")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 0)

    def test_scan_file_strcpy_in_c_file(self):
        """Test that strcpy is correctly identified in a .c file."""
        c_code = 'int main() { char buffer[10]; strcpy(buffer, "hello"); return 0; }'
        file_path = self._create_test_file(c_code, filename="test.c")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 1, "Failed to find strcpy in .c file")
        self.assertEqual(findings[0]['pattern'], "\\bstrcpy\\s*\\(")
        self.assertEqual(findings[0]['category'], "Unsafe Functions (C/C++)")

    def test_json_output(self):
        """Test the JSON output format."""
        file_path = self._create_test_file("import hashlib\\nhash = hashlib.md5()")
        all_findings = scanner.scan_file(file_path, self.patterns)

        captured_output = StringIO()
        sys.stdout = captured_output
        scanner.print_json_report(all_findings)
        sys.stdout = sys.__stdout__

        output = json.loads(captured_output.getvalue())
        self.assertEqual(output['summary']['total_issues'], 1)
        self.assertEqual(output['summary']['severities']['High'], 1)
        self.assertEqual(output['findings'][0]['pattern'], "\\bMD5\\b")

    def test_text_output(self):
        """Test the text output format."""
        file_path = self._create_test_file("import hashlib\\nhash = hashlib.md5()")
        all_findings = scanner.scan_file(file_path, self.patterns)

        captured_output = StringIO()
        sys.stdout = captured_output
        scanner.print_text_report(all_findings)
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        self.assertIn("--- Crypto-Debt Scanner Report", output)
        self.assertIn("Severity: High", output)
        self.assertIn("Pattern:     /\\bMD5\\b/", output)
        self.assertIn("Total issues found: 1", output)

if __name__ == '__main__':
    unittest.main()
