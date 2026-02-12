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

Run the scanner on any directory. You can specify the output format (`text` or `json`) and provide a custom patterns file.

```bash
# Default text output
crypto-debt-scanner /path/to/your/project

# JSON output for machine processing
crypto-debt-scanner /path/to/your/project --format json

# Using a custom patterns file
crypto-debt-scanner /path/to/your/project --patterns /path/to/my_patterns.json
```

### Output Formats

-   `text` (default): A human-readable report printed to the console.
-   `json`: A machine-readable JSON object, ideal for integrating with CI/CD pipelines or other tools.

### Customizing Patterns

The scanner's real power is its configurable patterns. It uses a `patterns.json` file by default, but you can provide your own. The JSON file should be structured by category, with a list of rules for each. Each rule must have a `pattern` (a valid Python regular expression) and a `description`, and can optionally have a `severity` (`High`, `Medium`, `Low`).

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

## Disclaimer

This is an early-stage tool. It uses regular expressions to find patterns and is intended as a first-pass, awareness-raising tool, not a comprehensive security audit solution like a SAST scanner.

## Contributing

Contributions are welcome! Please open an issue to discuss any changes.
