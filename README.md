# pipedact 🍁🛡️

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/theterminalguy/pipedact)](https://goreportcard.com/report/github.com/theterminalguy/pipedact)
[![Jurisdiction: CA-PIPEDA](https://img.shields.io/badge/Jurisdiction-CA--PIPEDA%20%7C%20Bill%20C--27-crimson.svg)](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/)
[![Framework: SOC 2 Type II](https://img.shields.io/badge/Framework-AICPA%20SOC%202%20Type%20II-teal.svg)](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
[![Standard: ISO/IEC 27701](https://img.shields.io/badge/Standard-ISO%2FIEC%2027701%20%7C%20Law%2025-blueviolet.svg)](https://www.iso.org/standard/71670.html)

> **Continuous Privacy-as-Code & Security Compliance Suite for Canadian Federal/Provincial Laws (PIPEDA, Law 25) and AICPA SOC 2 Type II (Trust Services Criteria).**

`pipedact` is an open-source static analysis engine and continuous compliance suite built in Go. It enables developers, security engineers, and compliance teams to scan codebases, database schemas, and CI/CD pipelines to ensure compliance with Canada's [PIPEDA](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/) (10 Fair Information Principles), [AICPA SOC 2 Type II](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) (Common Criteria CC6/CC7 & Privacy Criteria P1–P5), Quebec Law 25, and ISO/IEC 27701.

---

## 🍁 Features & Multi-Framework Gates

- **Multi-Framework Compliance Engine**: Switch seamlessly between statutory privacy regimes and security criteria:
  - `pipeda` — Canadian Federal PIPEDA Schedule 1 (10 Fair Information Principles).
  - `soc2` — AICPA SOC 2 Type II Trust Services Criteria (Common Criteria CC6/CC7 & Privacy Criteria P1-P5).
  - `iso27701` — Privacy Information Management System (PIMS) controls.
  - `law25` — Quebec Law 25 transparency, consent, and confidentiality obligations.
  - `all` — Unified multi-standard audit across all regimes simultaneously.
- **SOC 2 Type II Security & Transmission Controls**:
  - `SOC2-CC6-HARDCODED-SECRET` — Detects exposed API secrets, private keys, and database passwords (CC6.1/CC6.6).
  - `SOC2-CC6-INSECURE-COOKIE` — Verifies transmission safeguards (`secure: true`, `httpOnly: true`) (CC6.6/CC6.7).
  - `SOC2-CC6-WEAK-CRYPTO` — Blocks cryptographically broken hashing primitives like MD5 and SHA-1 (CC6.6).
  - `SOC2-CC6-WILDCARD-CORS` — Enforces strict API origin controls, disallowing wildcard `*` origins (CC6.6).
- **Canadian SIN Luhn Mod-10 Checksum Algorithm**: Validates and flags Canadian Social Insurance Numbers (SIN) with true Luhn checksum verification to prevent hardcoding and unredacted logging.
- **PII Leakage & Log Sink Detection**: Blocks logging sinks (`console.log`, `logger.*`, `print`, `logging`) from receiving unredacted personal identifiers (SINs, emails, phone numbers, health cards).
- **Consent Gate Verification**: Flags unconsented third-party marketing and telemetry dispatches.
- **Data Minimization & Limiting Collection**: Detects excessive collection of sensitive identifiers (e.g., provincial health card numbers during standard consumer authentication).
- **Automated Retention Enforcement**: Ensures database schemas declare purpose tags (`@privacy(purpose: "...")`) and TTL/purge hooks.
- **Audit Evidence & Dossier Export**: Generates SARIF 2.1.0 for GitHub Code Scanning, Markdown compliance dossiers, and auditor evidence packs for external CPA and OPC audits.
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

# Run PIPEDA statutory compliance check
pipedact check ./src --strict

# Run SOC 2 Type II Trust Services Criteria check
pipedact check ./src --framework soc2

# Run unified multi-framework scan (PIPEDA + SOC 2 + ISO 27701 + Law 25)
pipedact check ./src --framework all

# Run with automated remediation (safe autofix for log sinks & consent guards)
pipedact check ./src --fix

# Run with AI semantic privacy analysis (Gemini, OpenAI, Ollama, or built-in statutory reasoner)
pipedact check ./src --ai

# Explain any statutory rule or SOC 2 criterion with legal precedents & compliant code
pipedact explain PIPEDA-7-SAFEGUARD-LOG
pipedact explain SOC2-CC6-HARDCODED-SECRET

# Export official OPC PIPEDA Schedule 1 Compliance Dossier
pipedact dossier --framework pipeda --format markdown --out PIPEDA_OPC_DOSSIER.md

# Export AICPA SOC 2 Type II Auditor Evidence Pack
pipedact dossier --framework soc2 --format markdown --out SOC2_TYPE_II_EVIDENCE_PACK.md

# View technical mapping matrix
pipedact principles --framework pipeda
pipedact principles --framework soc2

# Validate Canadian SIN using Luhn mod-10 algorithm
pipedact validate-sin "046-454-286"
```

---

## 🧪 Sample Code Repository

Want to see `pipedact` in action on a real application with deliberate compliance violations across TypeScript, Python, and Prisma?

👉 **[github.com/theterminalguy/pipedact-sample-app](https://github.com/theterminalguy/pipedact-sample-app)**

---

## 🤖 Hybrid Static + AI Analysis Architecture

`pipedact` uniquely combines **ultra-fast static analysis** (<10ms) with **semantic AI privacy intelligence**:
- **Zero-Egress Statutory Reasoner**: Runs offline by default with built-in Canadian statutory knowledge, AICPA Trust Services Criteria, and OPC investigation precedents (no external network egress or API keys required).
- **Generative AI Providers**: Supports Google Gemini (`GEMINI_API_KEY`), OpenAI (`OPENAI_API_KEY`), and local Ollama (`OLLAMA_HOST`) for deep semantic audits, quasi-identifier linkage analysis, and custom refactoring suggestions.

---

## 📊 Cross-Framework Statutory & Criteria Matrix

`pipedact` unifies compliance criteria across Canadian legislation and international standards:

| Gate ID | PIPEDA Schedule 1 | SOC 2 Type II | ISO/IEC 27701 | Quebec Law 25 | Automated Technical Gate | Severity |
|:---|:---|:---|:---|:---|:---|:---|
| `PIPEDA-1-UNVETTED-SUBPROCESSOR` | Clause 4.1 | CC6.4, CC9.2 | Clause 7.2.6, 7.5.1 | Section 17 | Audits unvetted sub-processor API/SDK calls | `MEDIUM` |
| `PIPEDA-2-PURPOSE-UNTAGGED` | Clause 4.2 | P1.1, P3.1 | Clause 7.2.4 | Section 4 | Flags database models lacking `@privacy(purpose)` tags | `MEDIUM` |
| `PIPEDA-3-OPTIN-MISSING` | Clause 4.3 | P1.1, P2.1, P4.1 | Clause 7.2.1, 7.2.2 | Section 4, 8 | Enforces conditional consent guards on tracking/ads | `HIGH` |
| `PIPEDA-4-OVER-COLLECTION` | Clause 4.4 | P3.1, P3.2 | Clause 7.2.3 | Section 5 | Detects over-collection (e.g. SIN/Health card in registration) | `HIGH` |
| `PIPEDA-5-RETENTION-DISPOSAL` | Clause 4.5 | P4.2, P4.3, CC6.5 | Clause 7.4.1, 7.4.2 | Section 23 | Checks for TTL indexes, expiration dates, or purge crons | `MEDIUM` |
| `PIPEDA-6-ACCURACY-VALIDATION` | Clause 4.6 | P3.2, CC7.1 | Clause 7.2.5 | Section 11 | Validates input boundary validators & Luhn check for SIN | `LOW` |
| `PIPEDA-7-SAFEGUARD-LOG` | Clause 4.7 | CC6.7, P6.1 | Clause 7.2.8, 8.2.1 | Section 10 | Blocks raw PII flowing to stdout, logs, or unencrypted storage | `HIGH` |
| `PIPEDA-7-RAW-SIN` | Clause 4.7 | CC6.1, P3.1 | Clause 7.2.8 | Section 10 | Flags hardcoded Canadian SINs using Luhn mod-10 check | `CRITICAL` |
| `PIPEDA-8-POLICY-ROUTE-MISSING` | Clause 4.8 | P1.1, CC2.1 | Clause 7.3.2 | Section 8 | Verifies presence of public privacy routes (`/privacy`) | `LOW` |
| `PIPEDA-9-INCOMPLETE-DSR` | Clause 4.9 | P5.1, P5.2 | Clause 7.3.1 | Section 27, 28 | Audits DSR/DSAR user archive export routines | `MEDIUM` |
| `PIPEDA-10-RECOURSE-MISSING` | Clause 4.10 | P1.2, CC2.2 | Clause 7.3.3 | Section 29 | Verifies privacy dispute intake endpoints/webhooks | `INFO` |
| `SOC2-CC6-HARDCODED-SECRET` | Clause 4.7 | CC6.1, CC6.6 | Clause 7.2.8 | Section 10 | Detects hardcoded API keys, JWT secrets, passwords | `CRITICAL` |
| `SOC2-CC6-INSECURE-COOKIE` | Clause 4.7 | CC6.6, CC6.7 | Clause 7.2.8 | Section 10 | Enforces secure and httpOnly cookie attributes | `HIGH` |
| `SOC2-CC6-WEAK-CRYPTO` | Clause 4.7 | CC6.6 | Clause 7.2.8 | Section 10 | Flags broken cryptographic hashing (MD5, SHA-1) | `HIGH` |
| `SOC2-CC6-WILDCARD-CORS` | Clause 4.7 | CC6.6 | Clause 7.2.8 | Section 10 | Restricts wildcard Access-Control-Allow-Origin | `MEDIUM` |

---

## 🏛️ Regulatory & Audit FAQ

### Do we need an external CPA to certify us for PIPEDA?
**No.** PIPEDA compliance is governed directly by the Office of the Privacy Commissioner of Canada (OPC). Unlike financial audits, PIPEDA is an ongoing statutory legal obligation. Organizations self-assess their adherence to Schedule 1 principles. `pipedact dossier --framework pipeda` generates the self-assessment dossier recommended by the OPC for formal accountability.

### Do we need an external CPA for SOC 2 Type II?
**Yes.** While PIPEDA does not require a CPA, an official AICPA SOC 2 Type II report **must** be issued by a licensed CPA firm (operating under AICPA SSAE 18 AT-C Section 205). `pipedact check --framework soc2` and `pipedact dossier --framework soc2` generate the continuous automated technical evidence and testing results that CPA auditors review during their 3–12 month observation window.

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
