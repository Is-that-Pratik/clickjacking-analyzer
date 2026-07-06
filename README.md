# Clickjacking-analyzer 🛡️


A standalone, lightweight Python command-line tool to analyze websites for clickjacking vulnerabilities by inspecting HTTP security headers (`X-Frame-Options` and `Content-Security-Policy`).

## Features
- 🔍 Inspects `X-Frame-Options` and `CSP frame-ancestors` directives.
- 🚦 Outputs a clear **VERDICT** (`PROTECTED`, `PARTIALLY PROTECTED`, or `VULNERABLE`).
- 📂 Supports bulk scanning via an input file.
- 🎯 Dynamically generates an HTML Proof-of-Concept (PoC) file to visually confirm the vulnerability.

## Installation

1. Clone the repository and navigate into it:
   ```bash
   git clone https://github.com/Is-that-Pratik/clickjacking-analyzer.git
   cd clickjacking-analyzer
   pip install -r requirements.txt
   

Usage

### Check a single URL:

python3 clickjack_check.py [https://example.com](https://example.com)


### Check a single URL and generate a visual PoC:

python3 clickjack_check.py [https://example.com](https://example.com) --poc


### Bulk scan multiple URLs from a file:

python3 clickjack_check.py -f urls.txt
