# Crypto-Debt Scanner

A simple, fast, and configurable CLI tool to scan your codebase for outdated and vulnerable cryptographic patterns.

## The Problem

Over time, cryptographic standards evolve. Algorithms and protocols that were once considered secure (like MD5 or SHA1) are now known to be vulnerable. This "crypto-debt" can silently accumulate in a codebase, creating significant security risks that may not be apparent until it's too late. This tool helps you identify this debt so you can prioritize and fix it.

## Installation

```bash
# Clone the repository
git clone https://github.com/jack-uval/crypto-debt-scanner.git
cd crypto-debt-scanner

# Install the tool
pip install .
```

## Usage

Run the scanner on any directory with various flags to customize the scan and output.

```bash
# Default text output, shows all severities
crypto-debt-scanner /path/to/your/project

# Only show High severity issues
crypto-debt-scanner /path/to/your/project --min-severity High

# Only scan Python files and output as JSON
crypto-debt-scanner /path/to/your/project --include .py --format json

# Scan all files except Markdown
crypto-debt-scanner /path/to/your/project --exclude .md
```

### Filtering Options

-   `--min-severity [High|Medium|Low]`: Only show findings with the specified severity or higher. Default is `Low`.
-   `--include [.ext1 .ext2]`: Only scan files with these extensions.
-   `--exclude [.ext1 .ext2]`: Exclude files with these extensions from the scan.

### Output Formats

-   `text` (default): A human-readable report printed to the console.
-   `json`: A machine-readable JSON object, ideal for integrating with CI/CD pipelines.

### Customizing Patterns

You can provide your own `patterns.json` file to search for custom patterns. Each rule must have a `pattern` (a valid Python regular expression) and a `description`.

```bash
crypto-debt-scanner /path/to/your/project --patterns /path/to/my_patterns.json
```

## Disclaimer

This is an early-stage tool. It uses regular expressions to find patterns and is intended as a first-pass, awareness-raising tool, not a comprehensive security audit solution like a SAST scanner.

## Contributing

Contributions are welcome! Please open an issue to discuss any changes.
