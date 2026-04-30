# Phishing Triage Tool

Python script for rapid triage analysis of suspicious `.eml` email files. Designed for SOC L1 analysts as part of the initial investigation workflow.

## Features

- **Spoofing Check** — Compares From vs Return-Path vs Reply-To domains
- **Authentication Verification** — Parses SPF/DKIM/DMARC results from Authentication-Results header
- **Received Chain Analysis** — Traces server hops and extracts IPs with validation (0-255 per octet)
- **URL Extraction** — Extracts and deduplicates links from email body (HTML and plain text)
- **Attachment Hashing** — Detects attachments and generates MD5/SHA256 hashes without execution
- **IOC Collection** — Consolidates IPs, domains, and hashes for threat intel lookups
- **JSON Export** — Full report export for documentation and further analysis

## Requirements

Python 3.x (no external dependencies, uses only standard library)

## Usage

```bash
# Console report
python.exe phishing_triage.py suspicious_email.eml

# Console report + JSON export
python.exe phishing_triage.py suspicious_email.eml -o report.json
```

## Sample Output

```
============================================================
           PHISHING TRIAGE REPORT
============================================================

  [SPOOFING CHECK]
  ✅ MATCH — From: mail.example.com | Return-Path: mail.example.com | Reply-To: example.com

  [AUTHENTICATION]
  spf=pass | dkim=pass | dmarc=pass

  [RECEIVED CHAIN]
  Hop 1: 192.168.1.10
  Hop 2: 129.145.70.192

  [URLs FOUND]
  example.com — 3 URLs
  tracking.example.com — 12 URLs

  Total: 15 unique URLs
  (Use -o to export full URLs to JSON)

  [ATTACHMENTS]
  None

  [IOCs SUMMARY]
  IPs:
    192.168.1.10
    129.145.70.192

  Domains:
    example.com (3)
    tracking.example.com (12)

  Hashes:
    None

============================================================
```

