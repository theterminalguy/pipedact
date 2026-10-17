# Pipedact 🍁🛡️

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/v/release/theterminalguy/pipedact?color=blue)](https://github.com/theterminalguy/pipedact/releases)
[![CI](https://github.com/theterminalguy/pipedact/actions/workflows/ci.yml/badge.svg)](https://github.com/theterminalguy/pipedact/actions/workflows/ci.yml)
[![Compliance Gate](https://github.com/theterminalguy/pipedact/actions/workflows/pipeda.yml/badge.svg)](https://github.com/theterminalguy/pipedact/actions/workflows/pipeda.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/theterminalguy/pipedact)](https://goreportcard.com/report/github.com/theterminalguy/pipedact)

**Privacy and security checks for your codebase.**

An open-source, developer-first static analysis tool that detects privacy risks, insecure patterns, and potential compliance gaps before they reach production.

Built with Canadian privacy requirements in mind, with rules mapped to [PIPEDA](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/), Quebec Law 25, and relevant [AICPA SOC 2](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) Trust Services Criteria.

---

## 1. Quick Start

### Installation

Install via Go:

```bash
go install github.com/theterminalguy/pipedact@latest
```

Or download the pre-compiled binary with SHA-256 checksums from [GitHub Releases](https://github.com/theterminalguy/pipedact/releases).

### Run Your First Scan

```bash
# 1. Initialize configuration in your project root
pipedact init

# 2. Scan your source directory
pipedact check ./src

# 3. Scan with strict exit code (fails CI if high/critical issues exist)
pipedact check ./src --strict
```

---

## 2. Example Output

Pipedact produces actionable terminal output with precise file locations, snippets, and code-level remedies:

```text
  #1 [HIGH] Principle 7: Safeguards (PIPEDA-7-SAFEGUARD-LOG)
     Frameworks: PIPEDA: Schedule 1, Clause 4.7 | SOC 2: CC6.7, P6.1
     src/services/candidates.ts:42
     Personal Information leaking into application logs without sanitization.
     > console.log("Processing candidate:", candidate.email);
     Remedy: Use maskIdentifier() or sha256 pseudonymization before emitting log events.

  #2 [CRITICAL] SOC 2 CC6.1 / Safeguards (SOC2-CC6-HARDCODED-SECRET)
     Frameworks: SOC 2: CC6.1, CC6.6 | PIPEDA: Clause 4.7
     src/config/jwt.ts:8
     Hardcoded credential, private key, or API secret detected in source code.
     > const jwt_secret = "super_production_secret_token_123456789";
     Remedy: Store credentials in environment variables or a dedicated secret vault.

─────────────────────────────────────────────────────────────────────────────
PIPEDA Technical Score: 85% — Substantial Compliance (Action Needed)
Total Violations: 2 | Gate Status: FAIL (Exit 1)
```

> [!NOTE]
> Findings indicate potential technical risks and engineering anti-patterns. They assist developers in mitigating risks before deployment and do not constitute formal legal certification.

Reproduce and test real findings against our companion vulnerable app:  
👉 **[github.com/theterminalguy/pipedact-sample-app](https://github.com/theterminalguy/pipedact-sample-app)**

---

## 3. What Pipedact Detects

Pipedact inspects source code, database models, and API configurations across 15 rules:

| Category | Checks Implemented | Purpose / Rationale |
|:---|:---|:---|
| **Logging Sinks** | `PIPEDA-7-SAFEGUARD-LOG` | Prevents unredacted PII (emails, SINs, phone numbers) from reaching log aggregators |
| **Canadian SINs** | `PIPEDA-7-RAW-SIN` | Flags hardcoded Canadian Social Insurance Numbers using federal mod-10 Luhn validation |
| **Input Accuracy** | `PIPEDA-6-ACCURACY-VALIDATION` | Checks that Canadian SIN input handlers execute Luhn mod-10 validation |
| **Consent Gating** | `PIPEDA-3-OPTIN-MISSING` | Ensures third-party analytics/ad calls are enclosed in conditional consent checks |
| **Data Minimization**| `PIPEDA-4-OVER-COLLECTION` | Detects collection of provincial health card numbers in non-health auth payloads |
| **Schema Retention** | `PIPEDA-5-RETENTION-DISPOSAL` | Verifies database models declare TTL, expiration timestamps, or purge hooks |
| **Schema Purpose** | `PIPEDA-2-PURPOSE-UNTAGGED` | *Engineering convention*: Enforces `@privacy(purpose: "...")` tags on sensitive columns |
| **Sub-processors** | `PIPEDA-1-UNVETTED-SUBPROCESSOR`| Flags outbound data dispatch to unvetted third-party metrics and ad brokers |
| **Access Rights** | `PIPEDA-9-INCOMPLETE-DSR` | Audits Data Subject Access Request export routines for missing table joins |
| **Openness** | `PIPEDA-8-POLICY-ROUTE-MISSING`| Verifies presence of public privacy route (`/privacy`) on routers |
| **Secrets in Code**| `SOC2-CC6-HARDCODED-SECRET` | Flags committed API tokens, JWT secrets, and database passwords |
| **Cookie Flags** | `SOC2-CC6-INSECURE-COOKIE` | Ensures cookies are emitted with `secure: true` and `httpOnly: true` |
| **Weak Crypto** | `SOC2-CC6-WEAK-CRYPTO` | Detects deprecated and broken hashing functions (MD5, SHA-1) |
| **CORS Boundaries**| `SOC2-CC6-WILDCARD-CORS` | Disallows permissive wildcard `origin: '*'` configurations on API endpoints |

*Detailed rule definitions, code examples, and limitations are documented in [`docs/RULES.md`](docs/RULES.md).*

---

## 4. Supported Languages and File Formats

| Language / File Format | Extension | Status | Tested Checks |
|:---|:---|:---|:---|
| **TypeScript / JavaScript** | `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs` | **Stable** | Log sinks, consent guards, cookie options, CORS, crypto, secrets |
| **Python** | `.py` | **Stable** | Standard `logging`, hashlib weak crypto, unvetted HTTP dispatches |
| **Prisma Schemas** | `.prisma` | **Stable** | Model retention hooks (`expiresAt`, `autoPurge`), purpose attributes |
| **SQL Schemas** | `.sql` | **Stable** | Sensitive column classification, retention annotations |
| **Go** | `.go` | **Stable** | Logger calls, crypto/md5, crypto/sha1, hardcoded secrets |
| **Configuration / Secrets** | `.env*`, `.yaml`, `.yml`, `.json` | **Stable** | Hardcoded secrets, API tokens, dispute URLs |
| **GraphQL** | `.graphql`, `.gql` | *Beta* | Schema field classifications |

---

## 5. Framework Mappings & Limitations

Pipedact maps its technical checks to multiple privacy and security frameworks:

- **PIPEDA (Canada Federal)**: Aligned with the 10 Fair Information Principles in Schedule 1.
- **Quebec Law 25**: Cross-mapped for consent, de-identification in logs, and third-party transfer checks.
- **AICPA SOC 2**: Mapped to selected technical criteria under Security (`CC6.1`, `CC6.6`, `CC6.7`) and Privacy (`P1.1`–`P5.1`).
- **ISO/IEC 27701**: Cross-mapped to relevant privacy information management controls.

```bash
# Target specific framework rules
pipedact check ./src --framework pipeda
pipedact check ./src --framework soc2
pipedact check ./src --framework all
```

> [!IMPORTANT]
> **Static Analysis Coverage Boundary**: Static analysis evaluates source code patterns at a single point in time. It cannot verify operational controls such as signed vendor agreements, employee access controls, physical security, or SOC 2 operating effectiveness across an audit period.  
> Read the complete analysis boundary in [`docs/COVERAGE.md`](docs/COVERAGE.md).

---

## 6. Configuration (`.pipedactrc.yaml`)

Initialize a configuration file with `pipedact init`. Example:

```yaml
version: "1.0"
jurisdiction: "CA-PIPEDA"

# Organization Privacy Officer details (placeholders)
privacy_officer:
  name: "Data Privacy Officer"
  email: "privacy@organization.ca"
  dispute_url: "https://organization.ca/legal/privacy/dispute"

# Database schema checks
schemas:
  enforcePurposeTags: true # Architectural convention for schema field tagging
  allowedPurposes:
    - user_authentication
    - billing_tax_invoicing
    - security_fraud_prevention

# Logging sinks redaction
sinks:
  disallowedLogIdentifiers:
    - canadian_sin
    - credit_card
    - email_address
    - phone_number

# Retention policy baseline (organizational threshold, not a statutory mandate)
retention:
  defaultMaxTtlDays: 730
  requireHardDeleteSchedule: true

ignore:
  - "**/*_test.go"
  - "**/*.spec.ts"
  - "node_modules/**"
  - "dist/**"
```

---

## 7. CI/CD Integration

### GitHub Actions Workflow

Create `.github/workflows/pipedact.yml`:

```yaml
name: Privacy & Security Gate
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Install pipedact
        run: go install github.com/theterminalguy/pipedact@latest
      - name: Run Privacy & Security Checks
        run: pipedact check . --strict --format sarif --out audit.sarif
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: audit.sarif
```

### Exit Codes
- `0`: Clean scan or violations below `--fail-on` threshold.
- `1`: High or Critical violations detected (or any violation when `--strict` is enabled).

---

## 8. AI Analysis & Data Privacy

Pipedact supports optional AI-assisted privacy analysis (`--ai`) to explain findings and detect semantic risks.

### Privacy & Data Egress Guarantees
- **Offline Local Mode (Default)**: By default, Pipedact uses a deterministic statutory reasoner with **zero network egress**. No code leaves your machine.
- **Local LLMs via Ollama**: Set `OLLAMA_HOST` to run open-weights models (e.g. Llama 3) completely on-premise.
- **Commercial Cloud LLMs**: Setting `GEMINI_API_KEY` or `OPENAI_API_KEY` sends only the specific flagged code snippets and rule IDs to the selected provider for refactoring advice. No repository cloning or background indexing occurs.

```bash
# Offline local analysis (zero egress)
pipedact check ./src --ai --ai-provider heuristic

# Local on-premise LLM via Ollama
pipedact check ./src --ai --ai-provider ollama

# Explain a specific rule with legal summaries and compliant examples
pipedact explain PIPEDA-7-SAFEGUARD-LOG
```

---

## 9. Automated Remediation (`--fix` and `--dry-run`)

Pipedact includes a conservative automated patcher:

```bash
# Preview diff without modifying files
pipedact check ./src --dry-run

# Apply safe fixes atomically
pipedact check ./src --fix
```

- **Scope**: Automatically masks or redacts PII in simple application logging statements (e.g. `PIPEDA-7-SAFEGUARD-LOG`).
- **Safety**: `--fix` operates with atomic writes and syntax validation. It never fabricates consent decisions (`optInConfirmed: false` -> `true` is strictly prohibited), never modifies authentication logic, and never claims schema comments implement data deletion.

---

## 10. Reporting

Generate markdown reports for engineering reviews and auditor prep:

```bash
# PIPEDA Schedule 1 technical assessment report
pipedact dossier --framework pipeda --format markdown --out PIPEDA_REPORT.md

# SOC 2 Trust Services Criteria technical findings report
pipedact dossier --framework soc2 --format markdown --out SOC2_REPORT.md
```

---

## Documentation & Policies

- **Rule Inventory & Examples**: [`docs/RULES.md`](docs/RULES.md)
- **Coverage Limitations & Legal Scope**: [`docs/COVERAGE.md`](docs/COVERAGE.md)
- **Security & Vulnerability Disclosure**: [`SECURITY.md`](SECURITY.md)
- **Reference Vulnerable Application**: [theterminalguy/pipedact-sample-app](https://github.com/theterminalguy/pipedact-sample-app)

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
