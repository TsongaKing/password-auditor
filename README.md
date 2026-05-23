# Password Auditor

![CI - Password Auditor](https://github.com/TsongaKing/password-auditor/actions/workflows/ci.yml/badge.svg)

A professional password security tool that checks strength, detects weak patterns, checks breach databases, maps to NIST compliance standards, and generates secure passwords and passphrases.

## Features

- Password strength scoring using zxcvbn (same library used by Dropbox)
- Have I Been Pwned API integration with k-anonymity privacy protection
- Pattern detection: keyboard walks, dates, repeated characters, common words
- NIST SP 800-63B compliance mapping
- Secure password and passphrase generator
- Bulk audit mode for multiple passwords
- Rich color-coded console output
- JSON output for pipeline integration
- GitHub Actions CI with automated tests

## Quick Start

pip install -r requirements.txt

### Check a single password
python main.py check "yourpassword"

### Check with NIST compliance report
python main.py check "yourpassword" --compliance

### Check without breach lookup
python main.py check "yourpassword" --no-breach-check

### Bulk audit from file
python main.py audit passwords.txt --compliance

### Generate a secure password
python main.py generate --length 20

### Generate a passphrase (NIST recommended)
python main.py generate --type passphrase --words 5

### Generate multiple passwords
python main.py generate --count 5

## NIST SP 800-63B Compliance

The --compliance flag maps results against NIST SP 800-63B (2025) guidelines:

- Minimum length: 8 characters
- Recommended length: 15+ characters
- Maximum length: 64 characters
- Breach database check required
- Sufficient entropy required

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

The Have I Been Pwned check uses k-anonymity. Only the first 5 characters of the SHA1 hash are sent to the API. Your actual password never leaves your machine.

## Project Structure

- main.py - CLI entry point
- src/analyzer.py - Password analysis and breach checking
- src/display.py - Rich console output
- src/generator.py - Secure password and passphrase generation
- src/compliance.py - NIST SP 800-63B compliance mapping
- tests/ - Unit tests

## Tech Stack

Python 3.11, zxcvbn, requests, rich, click, GitHub Actions

## Legal

For authorized security assessments and personal use only.
Built by @TsongaKing
