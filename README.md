# Password Auditor

![CI - Password Auditor](https://github.com/TsongaKing/password-auditor/actions/workflows/ci.yml/badge.svg)

A professional password strength auditor that checks passwords against known breaches, detects weak patterns, and provides detailed security recommendations.

## Features

- Password strength scoring using zxcvbn (same library used by Dropbox)
- Have I Been Pwned API integration - checks if password appeared in data breaches
- Pattern detection: keyboard walks, dates, repeated characters, common words
- Bulk audit mode - audit multiple passwords from a file
- Rich color-coded console output
- JSON output for integration with other tools

## Quick Start

pip install -r requirements.txt

### Check a single password
python main.py check "yourpassword"

### Check without breach lookup
python main.py check "yourpassword" --no-breach-check

### Bulk audit from file
python main.py audit passwords.txt

### Output as JSON
python main.py check "yourpassword" --json-output

## Pattern Detection

| Pattern | Example |
|---------|---------|
| Keyboard walk | qwerty, 123456, asdfgh |
| Repeated characters | aaa, 111 |
| Contains year | password2024 |
| Contains date | 01012026 |
| Word plus numbers | password123 |
| Common words | admin, password, secret |

## Privacy

The Have I Been Pwned check uses k-anonymity - only the first 5 characters of the SHA1 hash are sent to the API. Your actual password never leaves your machine.

## Project Structure

- main.py - CLI entry point
- src/analyzer.py - Password analysis and breach checking
- src/display.py - Rich console output
- tests/ - Unit tests

## Tech Stack

Python 3.11, zxcvbn, requests, rich, click, GitHub Actions

## Legal

For authorized security assessments and personal use only.
Built by @TsongaKing
