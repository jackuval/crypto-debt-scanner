import os
import argparse
import json
import re
import sys
from copy import deepcopy

DEFAULT_PATTERNS_FILE = os.path.join(os.path.dirname(__file__), 'patterns.json')

def load_patterns(args):
    final_patterns = {}
    if not args.no_default_patterns:
        try:
            with open(DEFAULT_PATTERNS_FILE, 'r') as f:
                final_patterns = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load default patterns file: {e}", file=sys.stderr)

    if args.patterns:
        try:
            with open(args.patterns, 'r') as f:
                custom_patterns = json.load(f)
                if args.no_default_patterns:
                    final_patterns = custom_patterns
                else:
                    for category, rules in custom_patterns.items():
                        if category not in final_patterns:
                            final_patterns[category] = []
                        final_patterns[category].extend(rules)
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error: Could not load custom patterns file '{args.patterns}': {e}", file=sys.stderr)
            return None

    for category, rules in final_patterns.items():
        for rule in rules:
            try:
                rule['regex'] = re.compile(rule['pattern'], re.IGNORECASE)
            except re.error as e:
                print(f"Warning: Invalid regex for pattern '{rule['pattern']}': {e}", file=sys.stderr)
                rule['regex'] = None
    return final_patterns

def scan_file(file_path, patterns):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                for category, rules in patterns.items():
                    for rule in rules:
                        if rule.get('regex') and rule['regex'].search(line):
                            ignore_pattern_specific = f"cryptoscan-ignore: {re.escape(rule['pattern'])}"
                            if re.search(ignore_pattern_specific, line, re.IGNORECASE):
                                continue
                            if "cryptoscan-ignore" in line and ":" not in line.split("cryptoscan-ignore",1)[1]:
                                continue
                            findings.append({
                                "file": file_path, "line": i + 1, "pattern": rule['pattern'],
                                "description": rule['description'], "severity": rule.get('severity', 'N/A'),
                                "category": category
                            })
    except Exception:
        pass
    return findings

def print_text_report(all_findings):
    print("--- Crypto-Debt Scanner Report (v0.8.0) ---")
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "N/A": 3}
    sorted_findings = sorted(all_findings, key=lambda x: (severity_order.get(x['severity'], 99), x['file'], x['line']))
    for finding in sorted_findings:
        print(f"\n[!] Severity: {finding['severity']} | Category: {finding['category']}")
        print(f"  Description: {finding['description']}")
        print(f"  Pattern:     /{finding['pattern']}/")
        print(f"  Location:    {finding['file']}:{finding['line']}")
    print(f"\n--- End of Report ---\nTotal issues found: {len(all_findings)}")

def print_json_report(all_findings):
    report = {
        "summary": { "total_issues": len(all_findings),
                     "severities": {
                         "High": sum(1 for f in all_findings if f['severity'] == 'High'),
                         "Medium": sum(1 for f in all_findings if f['severity'] == 'Medium'),
                         "Low": sum(1 for f in all_findings if f['severity'] == 'Low'),
                         "N/A": sum(1 for f in all_findings if f['severity'] == 'N/A')}},
        "findings": all_findings}
    print(json.dumps(report, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Scan a codebase for outdated cryptographic patterns.")
    parser.add_argument("directory", help="The directory to scan.")
    parser.add_argument("--patterns", help="Path to a custom vulnerability patterns JSON file.")
    parser.add_argument("--no-default-patterns", action='store_true', help="Only use patterns from the custom file.")
    parser.add_argument("--format", choices=['text', 'json'], default='text', help="The output format.")
    parser.add_argument("--min-severity", choices=['High', 'Medium', 'Low'], default='Low', help="Minimum severity to report.")
    parser.add_argument("--include", nargs='*', help="File extensions to include.")
    parser.add_argument("--exclude", nargs='*', help="File extensions to exclude.")
    args = parser.parse_args()

    if args.no_default_patterns and not args.patterns:
        print("Error: --no-default-patterns requires a custom --patterns file.", file=sys.stderr)
        sys.exit(1)

    patterns = load_patterns(args)
    if not patterns:
        sys.exit(1)

    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found at '{args.directory}'", file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for root, dirs, files in os.walk(args.directory):
        dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'venv']]
        for file in files:
            if args.include and not any(file.endswith(ext) for ext in args.include):
                continue
            if args.exclude and any(file.endswith(ext) for ext in args.exclude):
                continue
            file_path = os.path.join(root, file)
            findings = scan_file(file_path, patterns)
            if findings:
                all_findings.extend(findings)

    severity_map = {'High': 0, 'Medium': 1, 'Low': 2}
    min_severity_level = severity_map.get(args.min_severity, 2)
    filtered_findings = [f for f in all_findings if severity_map.get(f.get('severity'), 99) <= min_severity_level]

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
