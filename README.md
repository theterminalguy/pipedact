# pipedact 🍁

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/theterminalguy/pipedact)](https://goreportcard.com/report/github.com/theterminalguy/pipedact)
[![Jurisdiction: CA-PIPEDA](https://img.shields.io/badge/Jurisdiction-CA--PIPEDA%20%7C%20Bill%20C--27-crimson.svg)](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/)

> **Statutory Privacy-as-Code Linter & OPC Schedule 1 Compliance Suite for Canadian Federal & Provincial Privacy Laws.**

`pipedact` is an open-source static analysis engine and compliance auditor built in Go. It enables developers and security engineers to scan codebases, database schemas, and CI/CD pipelines to ensure compliance with Canada's [Personal Information Protection and Electronic Documents Act (PIPEDA)](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/) and the 10 Fair Information Principles (Schedule 1).

---

## 🍁 Features

- **10 Fair Information Principles Technical Gate**: Maps statutory requirements under PIPEDA Schedule 1 to automated code checks, regex heuristics, and AST patterns.
- **Canadian SIN Luhn Algorithm Validator**: Verifies and flags Social Insurance Numbers (SIN) with mod-10 Luhn checksum algorithms to prevent hardcoding and unredacted logging.
- **PII Leakage & Log Sink Detection**: Blocks logging sinks (`console.log`, `logger.*`, `print`, `logging`) from receiving unredacted personal information.
- **Consent Gate Verification**: Flags unconsented third-party marketing and telemetry dispatches.
- **Data Minimization & Limiting Collection**: Detects excessive collection of sensitive identifiers (e.g., provincial health card numbers or SINs during standard consumer authentication).
- **Automated Retention Enforcement**: Ensures database schemas declare purpose tags (`@privacy(purpose: "...")`) and TTL/purge hooks.
- **SARIF & OPC Dossier Export**: Generates SARIF 2.1.0 reports for GitHub Code Scanning and detailed Markdown / JSON compliance dossiers with compliance scoring (0–100%).
- **Automated Remediation (`--fix`)**: Auto-masks PII in logging sinks and inserts affirmative consent guards.

---

## 🚀 Quick Start

### Installation

```bash
# Install with Go
go install github.com/theterminalguy/pipedact@latest

# Or download the pre-compiled binary for your OS
curl -sSL https://raw.githubusercontent.com/theterminalguy/pipedact/main/install.sh | sh
```

### Usage

```bash
# Initialize policy manifest in your project
pipedact init

# Run compliance check across source directory
pipedact check ./src --strict

# Run with automated remediation
pipedact check ./src --fix

# Export full OPC Schedule 1 Compliance Dossier
pipedact dossier --format markdown --out PIPEDA_OPC_SELF_ASSESSMENT_DOSSIER.md

# Validate Canadian SIN
pipedact validate-sin "046-454-286"
```

---

## 📋 The 10 Fair Information Principles Matrix (Schedule 1)

| Principle | Statutory Scope | Automated Technical Gate | Severity |
|:---|:---|:---|:---|
| **1. Accountability** | Privacy Officer designation & 3rd-party transfers | Audits unvetted sub-processor API/SDK calls | `MEDIUM` |
| **2. Identifying Purposes** | Stating collection reason before/at collection | Flags database models lacking `@privacy(purpose)` tags | `HIGH` |
| **3. Consent** | Meaningful consent before processing data | Enforces conditional consent guards on tracking/ads | `HIGH` |
| **4. Limiting Collection** | Collecting only what is necessary (Minimization) | Detects over-collection (e.g. SIN/Health card in registration) | `HIGH` |
| **5. Retention & Disposal** | Retaining personal data only as long as required | Checks for TTL indexes, expiration dates, or purge crons | `MEDIUM` |
| **6. Accuracy** | Ensuring personal data is accurate & complete | Validates input boundary validators & Luhn check for SIN | `LOW` |
| **7. Safeguards** | Preventing loss, theft, unauthorized disclosure | Blocks raw PII flowing to stdout, logs, or unencrypted storage | `CRITICAL` |
| **8. Openness** | Readily accessible privacy policies & practices | Verifies presence of public privacy routes (`/privacy`) | `LOW` |
| **9. Individual Access** | Right to access, verify, and export all personal data | Audits DSR/DSAR user archive export routines | `MEDIUM` |
| **10. Challenging Compliance** | Recourse mechanisms and complaint handling | Verifies privacy dispute intake endpoints/webhooks | `INFO` |

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
