import os
import argparse

# In a real tool, this would be a more sophisticated, configurable list.
# For the MVP, we'll hardcode some common, obviously outdated patterns.
VULNERABLE_PATTERNS = {
    "MD5": "MD5 is a broken hash function and should not be used for security purposes.",
    "SHA1": "SHA1 has known collision vulnerabilities and should be replaced with SHA-256 or stronger.",
    "RSA.encrypt": "Raw RSA encryption is insecure without proper padding (e.g., OAEP).",
    "ECB mode": "AES in ECB mode is not semantically secure and leaks pattern information.",
    "strcpy": "strcpy is not buffer-safe and can lead to buffer overflow vulnerabilities.",
    "sprintf": "sprintf is not buffer-safe and can lead to buffer overflow vulnerabilities."
}

def scan_file(file_path):
    """Scans a single file for vulnerable patterns."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                for pattern, description in VULNERABLE_PATTERNS.items():
                    if pattern in line:
                        findings.append({
                            "file": file_path,
                            "line": i,
                            "pattern": pattern,
                            "description": description
                        })
    except Exception as e:
        # Silently ignore files that can't be opened (e.g., binaries)
        pass
    return findings

def main():
    """Main function to parse arguments and orchestrate the scan."""
    parser = argparse.ArgumentParser(description="Scan a codebase for outdated and vulnerable cryptographic patterns.")
    parser.add_argument("directory", help="The directory to scan.")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found at '{args.directory}'")
        return

    all_findings = []
    for root, _, files in os.walk(args.directory):
        for file in files:
            file_path = os.path.join(root, file)
            findings = scan_file(file_path)
            if findings:
                all_findings.extend(findings)

    if not all_findings:
        print("Scan complete. No vulnerable patterns found.")
        return

    print("--- Crypto-Debt Scanner Report ---")
    for finding in all_findings:
        print(f"\n[!] Vulnerable pattern found:")
        print(f"  File:      {finding['file']}")
        print(f"  Line:      {finding['line']}")
        print(f"  Pattern:   '{finding['pattern']}'")
        print(f"  Warning:   {finding['description']}")
    print("\n--- End of Report ---")

if __name__ == "__main__":
    main()
