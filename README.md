# Crypto-Debt Scanner

A simple, fast, and configurable CLI tool to scan your codebase for outdated and vulnerable cryptographic patterns.

## The Problem

Over time, cryptographic standards evolve. Algorithms and protocols that were once considered secure (like MD5 or SHA1) are now known to be vulnerable. This "crypto-debt" can silently accumulate in a codebase, creating significant security risks. This tool helps you identify this debt so you can prioritize and fix it.

## Installation

```bash
git clone https://github.com/jack-uval/crypto-debt-scanner.git
cd crypto-debt-scanner
pip install .
```

## Usage

Run the scanner on any directory with various flags to customize the scan and output.

```bash
# Default text output
crypto-debt-scanner /path/to/your/project

# Only show High severity issues
crypto-debt-scanner /path/to/your/project --min-severity High

# Only use a custom patterns file, ignoring defaults
crypto-debt-scanner /path/to/project --patterns custom.json --no-default-patterns
```

### Key Features

-   **Configurable Patterns:** Provide your own JSON file with regex patterns. Use `--no-default-patterns` to scan *only* with your custom rules.
-   **Severity Filtering:** Use `--min-severity [High|Medium|Low]` to focus on the most critical issues.
-   **File Filtering:** Use `--include` and `--exclude` to target specific file extensions.
-   **Whitelist Findings:** Ignore specific findings on a line by adding a comment: `# cryptoscan-ignore` or `# cryptoscan-ignore: <pattern>`.
-   **JSON Output:** Use `--format json` for easy integration with CI/CD pipelines.

## Disclaimer

This is an early-stage tool intended as a first-pass, awareness-raising scanner, not a comprehensive SAST solution.

## Contributing

Contributions are welcome! Please open an issue to discuss any changes.
