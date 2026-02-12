import os
import argparse
import json
import re
import sys
import ast

DEFAULT_PATTERNS_FILE = os.path.join(os.path.dirname(__file__), 'patterns.json')

# --- Pattern Loading ---
def load_patterns(patterns_file):
    """Loads and compiles vulnerability patterns from a JSON file."""
    try:
        with open(patterns_file, 'r') as f:
            patterns = json.load(f)
            # Pre-compile regex patterns for efficiency
            for category, rules in patterns.get("RegexPatterns", {}).items():
                for rule in rules:
                    try:
                        rule['regex'] = re.compile(rule['pattern'], re.IGNORECASE)
                    except re.error as e:
                        print(f"Warning: Invalid regex for pattern '{rule['pattern']}': {e}", file=sys.stderr)
                        rule['regex'] = None
            return patterns
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading patterns file '{patterns_file}': {e}", file=sys.stderr)
        return None

# --- Scanners ---
class AstScanner(ast.NodeVisitor):
    """AST visitor to find vulnerable function calls in Python code."""
    def __init__(self, file_path, ast_patterns):
        self.findings = []
        self.file_path = file_path
        self.ast_patterns = ast_patterns

    def visit_Call(self, node):
        func_name = ''
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        for rule in self.ast_patterns:
            if func_name.lower() == rule['function_name'].lower():
                self.findings.append({
                    "file": self.file_path, "line": node.lineno, "pattern": func_name,
                    "description": rule['description'], "severity": rule.get('severity', 'N/A'),
                    "category": "Python AST"
                })
        self.generic_visit(node)

def scan_file_ast(file_path, patterns):
    """Scans a Python file using Abstract Syntax Trees for high-accuracy findings."""
    findings = []
    ast_patterns = patterns.get("PythonAstPatterns", [])
    if not ast_patterns:
        return findings

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
            tree = ast.parse(source, filename=file_path)
            visitor = AstScanner(file_path, ast_patterns)
            visitor.visit(tree)
            findings.extend(visitor.findings)
    except (SyntaxError, UnicodeDecodeError):
        # If the file isn't valid Python, fall back to regex scanning
        findings.extend(scan_file_regex(file_path, patterns))
    except Exception as e:
        print(f"Warning: Could not perform AST scan on {file_path}: {e}", file=sys.stderr)
    return findings

def scan_file_regex(file_path, patterns):
    """Scans a non-Python file for vulnerable patterns using regex."""
    findings = []
    regex_patterns = patterns.get("RegexPatterns", {})
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                for category, rules in regex_patterns.items():
                    for rule in rules:
                        if rule.get('regex') and rule['regex'].search(line):
                            findings.append({
                                "file": file_path, "line": i, "pattern": rule['pattern'],
                                "description": rule['description'], "severity": rule.get('severity', 'N/A'),
                                "category": category
                            })
    except Exception:
        pass
    return findings

# --- Reporting ---
def print_text_report(all_findings):
    """Prints a human-readable text report to stdout."""
    print("--- Crypto-Debt Scanner Report (v1.1.0) ---")
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "N/A": 3}
    sorted_findings = sorted(all_findings, key=lambda x: (severity_order.get(x['severity'], 99), x['file'], x['line']))

    for finding in sorted_findings:
        print(f"\n[!] Severity: {finding['severity']} | Category: {finding['category']}")
        print(f"  Description: {finding['description']}")
        print(f"  Pattern:     '{finding['pattern']}'")
        print(f"  Location:    {finding['file']}:{finding['line']}")

    print(f"\n--- End of Report ---")
    print(f"Total issues found: {len(all_findings)}")

def print_json_report(all_findings):
    """Prints a machine-readable JSON report to stdout."""
    report = {
        "summary": {
            "total_issues": len(all_findings),
            "severities": {
                "High": sum(1 for f in all_findings if f['severity'] == 'High'),
                "Medium": sum(1 for f in all_findings if f['severity'] == 'Medium'),
                "Low": sum(1 for f in all_findings if f['severity'] == 'Low']),
            }
        },
        "findings": all_findings
    }
    print(json.dumps(report, indent=2))

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Scan a codebase for outdated cryptographic patterns.")
    parser.add_argument("directory", help="The directory to scan.")
    parser.add_argument("--patterns", default=DEFAULT_PATTERNS_FILE, help=f"Path to a custom patterns JSON file.")
    parser.add_argument("--format", choices=['text', 'json'], default='text', help="The output format.")
    parser.add_argument("--min-severity", choices=['High', 'Medium', 'Low'], default='Low', help="Minimum severity to report.")
    parser.add_argument("--include", nargs='*', help="File extensions to include (e.g., .py .js).")
    parser.add_argument("--exclude", nargs='*', help="File extensions to exclude (e.g., .md .txt).")
    args = parser.parse_args()

    patterns = load_patterns(args.patterns)
    if not patterns:
        sys.exit(1)

    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found at '{args.directory}'", file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for root, dirs, files in os.walk(args.directory):
        dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__']]
        for file in files:
            if args.include and not any(file.endswith(ext) for ext in args.include):
                continue
            if args.exclude and any(file.endswith(ext) for ext in args.exclude):
                continue

            file_path = os.path.join(root, file)
            findings = []
            if file.endswith('.py'):
                findings = scan_file_ast(file_path, patterns)
            else:
                findings.extend(scan_file_regex(file_path, patterns))

            if findings:
                all_findings.extend(findings)

    severity_map = {'High': 0, 'Medium': 1, 'Low': 2}
    min_severity_level = severity_map.get(args.min_severity, 2)
    filtered_findings = [f for f in all_findings if severity_map.get(f['severity'], 99) <= min_severity_level]

    if not filtered_findings:
        if args.format == 'text':
            print("Scan complete. No matching issues found.")
        elif args.format == 'json':
            print_json_report([])
        return

    if args.format == 'text':
        print_text_report(filtered_findings)
    elif args.format == 'json':
        print_json_report(filtered_findings)

if __name__ == "__main__":
    main()
