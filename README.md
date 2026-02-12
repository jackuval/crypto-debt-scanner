# Crypto-Debt Scanner

A simple, fast, and configurable CLI tool to scan your codebase for outdated and vulnerable cryptographic patterns.

## The Problem

Over time, cryptographic standards evolve. Algorithms and protocols that were once considered secure (like MD5, SHA1, or raw RSA encryption) are now known to be vulnerable. This "crypto-debt" can silently accumulate in a codebase, creating significant security risks that may not be apparent until it's too late.

The "harvest now, decrypt later" threat from future quantum computers makes this problem even more urgent. Code written today using classical cryptography may be storing data that can be captured now and easily decrypted in the future.

This tool helps you identify this crypto-debt so you can prioritize and fix it.

## Installation

This tool will be available on PyPI soon. For now, you can install it directly from the source:

```bash
# Clone the repository
git clone https://github.com/jack-uval/crypto-debt-scanner.git
cd crypto-debt-scanner

# Install the tool
pip install .
```

## Usage

Once installed, you can run the scanner on any directory:

```bash
crypto-debt-scanner /path/to/your/project
```

It will recursively scan all files in the directory and print a report of any vulnerable patterns it finds, sorted by severity.

### Customizing Patterns

The real power of the scanner comes from its configurable patterns. It uses a `patterns.json` file by default, but you can provide your own custom JSON file using the `--patterns` flag:

```bash
crypto-debt-scanner /path/to/your/project --patterns /path/to/my_patterns.json
```

The JSON file should be structured by category, with a list of rules for each. Each rule must have a `pattern` and a `description`, and can optionally have a `severity` (`High`, `Medium`, `Low`).

#### Example `patterns.json`

```json
{
  "My Custom Category": [
    {
      "pattern": "MyInternalLegacyFunction",
      "description": "This is a deprecated internal function that should be replaced.",
      "severity": "High"
    }
  ]
}
```

### Example Output

```
--- Crypto-Debt Scanner Report ---

[!] Severity: High | Category: Hashing
  Description: MD5 is a broken hash function and should not be used for security purposes.
  Pattern:     'MD5'
  Location:    /path/to/your/project/legacy_code.py:42

[!] Severity: Medium | Category: Unsafe Functions (C/C++)
  Description: sprintf is not buffer-safe and can lead to buffer overflow vulnerabilities. Use snprintf.
  Pattern:     'sprintf'
  Location:    /path/to/your/project/utils/helpers.c:112

--- End of Report ---
Total issues found: 2
```

## Disclaimer

This is an early-stage tool and is not exhaustive. It uses a simple string-based search for the patterns you provide. It is intended as a first-pass, awareness-raising tool, not a comprehensive security audit solution like a SAST scanner.

## Contributing

Contributions are welcome! Please open an issue to discuss any changes.
