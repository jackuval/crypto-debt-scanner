import os
import argparse
import json
import re

DEFAULT_PATTERNS_FILE = os.path.join(os.path.dirname(__file__), 'patterns.json')

def load_patterns(patterns_file):
    """Loads and compiles vulnerability patterns from a JSON file."""
    try:
        with open(patterns_file, 'r') as f:
            patterns = json.load(f)
            # Pre-compile regex patterns for efficiency
            for category in patterns:
                for rule in patterns[category]:
                    try:
                        rule['regex'] = re.compile(rule['pattern'])
                    except re.error as e:
                        print(f"Warning: Invalid regex for pattern '{rule['pattern']}': {e}")
                        rule['regex'] = None
            return patterns
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading patterns file '{patterns_file}': {e}")
        return None

def scan_file(file_path, patterns):
    """Scans a single file for vulnerable patterns using regex."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                for category, rules in patterns.items():
                    for rule in rules:
                        if rule.get('regex') and rule['regex'].search(line):
                            findings.append({
                                "file": file_path,
                                "line": i,
                                "pattern": rule['pattern'],
                                "description": rule['description'],
                                "severity": rule.get('severity', 'N/A'),
                                "category": category
                            })
    except Exception as e:
        # Silently ignore files that can't be opened
        pass
    return findings

def main():
    """Main function to parse arguments and orchestrate the scan."""
    parser = argparse.ArgumentParser(description="Scan a codebase for outdated and vulnerable cryptographic patterns using regex.")
    parser.add_argument("directory", help="The directory to scan.")
    parser.add_argument("--patterns", default=DEFAULT_PATTERNS_FILE, help=f"Path to a custom vulnerability patterns JSON file. (default: {DEFAULT_PATTERNS_FILE})")
    args = parser.parse_args()

    patterns = load_patterns(args.patterns)
    if not patterns:
        return

    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found at '{args.directory}'")
        return

    all_findings = []
    for root, _, files in os.walk(args.directory):
        if '.git' in root:
            continue
        for file in files:
            if file.endswith('patterns.json'):
                continue
            file_path = os.path.join(root, file)
            findings = scan_file(file_path, patterns)
            if findings:
                all_findings.extend(findings)

    if not all_findings:
        print("Scan complete. No vulnerable patterns found.")
        return

    print("--- Crypto-Debt Scanner Report (v0.3.0) ---")
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "N/A": 3}
    sorted_findings = sorted(all_findings, key=lambda x: severity_order.get(x['severity'], 99))

    for finding in sorted_findings:
        print(f"\n[!] Severity: {finding['severity']} | Category: {finding['category']}")
        print(f"  Description: {finding['description']}")
        print(f"  Pattern:     /{finding['pattern']}/")
        print(f"  Location:    {finding['file']}:{finding['line']}")

    print(f"\n--- End of Report ---")
    print(f"Total issues found: {len(all_findings)}")


if __name__ == "__main__":
    main()
