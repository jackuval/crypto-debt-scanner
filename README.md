# Crypto-Debt Scanner

A simple, fast CLI tool to scan your codebase for outdated and vulnerable cryptographic patterns.

## The Problem

Over time, cryptographic standards evolve. Algorithms and protocols that were once considered secure (like MD5, SHA1, or raw RSA encryption) are now known to be vulnerable. This "crypto-debt" can silently accumulate in a codebase, creating significant security risks that may not be apparent until it's too late.

The "harvest now, decrypt later" threat from future quantum computers makes this problem even more urgent. Code written today using classical cryptography may be storing data that can be captured now and easily decrypted in the future.

This tool helps you identify this crypto-debt so you can prioritize and fix it.

## Installation

This tool will be available on PyPI soon. For now, you can install it directly from the source:

```bash
# Clone the repository (once it's public)
# git clone https://github.com/jack-uval/crypto-debt-scanner.git
# cd crypto-debt-scanner

# Install the tool
pip install .
```

## Usage

Once installed, you can run the scanner on any directory:

```bash
crypto-debt-scanner /path/to/your/project
```

It will recursively scan all files in the directory and print a report of any vulnerable patterns it finds, including the file path, line number, and a description of the vulnerability.

### Example Output

```
--- Crypto-Debt Scanner Report ---

[!] Vulnerable pattern found:
  File:      /path/to/your/project/legacy_code.py
  Line:      42
  Pattern:   'MD5'
  Warning:   MD5 is a broken hash function and should not be used for security purposes.

[!] Vulnerable pattern found:
  File:      /path/to/your/project/utils/encryption.py
  Line:      101
  Pattern:   'RSA.encrypt'
  Warning:   Raw RSA encryption is insecure without proper padding (e.g., OAEP).

--- End of Report ---
```

## Disclaimer

This is an MVP tool and is not exhaustive. It uses a simple string-based search for a limited set of common vulnerable patterns. It is intended as a first-pass, awareness-raising tool, not a comprehensive security audit.

## Contributing

Contributions are welcome! Please open an issue to discuss any changes.
