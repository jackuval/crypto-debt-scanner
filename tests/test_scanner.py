import unittest
import os
import json
import sys
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

    def tearDown(self):
        """Remove the temporary directory."""
        shutil.rmtree(self.test_dir)

    def _create_test_file(self, content, filename="test.py"):
        """Helper to create a file with content in the temp directory."""
        file_path = os.path.join(self.test_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)
        return file_path

    def test_scan_file_md5(self):
        """Test that MD5 is correctly identified."""
        file_path = self._create_test_file("import hashlib\\nhash = hashlib.md5()")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['pattern'], "\\bMD5\\b")
        self.assertEqual(findings[0]['severity'], "High")

    def test_scan_file_no_findings(self):
        """Test a file with no vulnerabilities."""
        file_path = self._create_test_file("print('Hello, world!')")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 0)

    def test_scan_file_strcpy(self):
        """Test that strcpy is correctly identified."""
        file_path = self._create_test_file("#include <string.h>\\nstrcpy(dest, src);")
        findings = scanner.scan_file(file_path, self.patterns)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['pattern'], "\\bstrcpy\\s*\\(")

    def test_json_output(self):
        """Test the JSON output format."""
        file_path = self._create_test_file("import hashlib\\nhash = hashlib.md5()")

        # Redirect stdout to capture the output
        captured_output = StringIO()
        sys.stdout = captured_output

        all_findings = scanner.scan_file(file_path, self.patterns)
        scanner.print_json_report(all_findings)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = json.loads(captured_output.getvalue())
        self.assertEqual(output['summary']['total_issues'], 1)
        self.assertEqual(output['summary']['severities']['High'], 1)
        self.assertEqual(output['findings'][0]['pattern'], "\\bMD5\\b")

    def test_text_output(self):
        """Test the text output format."""
        file_path = self._create_test_file("import hashlib\\nhash = hashlib.md5()")

        captured_output = StringIO()
        sys.stdout = captured_output

        all_findings = scanner.scan_file(file_path, self.patterns)
        scanner.print_text_report(all_findings)

        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        self.assertIn("--- Crypto-Debt Scanner Report (v0.4.0) ---", output)
        self.assertIn("Severity: High", output)
        self.assertIn("Pattern:     /\\bMD5\\b/", output)
        self.assertIn("Total issues found: 1", output)

if __name__ == '__main__':
    unittest.main()
