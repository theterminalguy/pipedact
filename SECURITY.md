# Security Policy

The `pipedact` team takes the security and privacy of developer environments, CI/CD pipelines, and source code repositories seriously. This document outlines our vulnerability reporting process, supported versions, and security design principles.

---

## Supported Versions

Security updates and patches are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability or sensitive privacy issue in `pipedact`, please report it privately. **Do not create a public GitHub issue.**

### Private Reporting Channel

1. **GitHub Security Advisory**: Open a private advisory draft via GitHub at [github.com/theterminalguy/pipedact/security/advisories/new](https://github.com/theterminalguy/pipedact/security/advisories/new).
2. **Email**: If you are unable to use GitHub Security Advisories, send an encrypted or plain report to **`security@pipedact.dev`** (or contact the maintainer directly via GitHub profile).

### What to Include

Please provide as much information as possible to help us reproduce and resolve the issue:
- Tool version (`pipedact --version`) and runtime environment (OS, architecture, Go version).
- A minimal reproducible example or test fixture triggering the behavior.
- Impact assessment (e.g., unintended remote code execution, secret leakage, denial of service during file scanning).
- Any proposed fix or remediation patch.

### Response Timeline

- **Initial Acknowledgment**: Within 48 hours.
- **Triage & Impact Assessment**: Within 5 business days.
- **Remediation & Patch Release**: Typically within 14 business days, coordinated with a public disclosure notice.

---

## Security Architecture & Design Principles

`pipedact` is engineered with the following security guarantees:

1. **Local-First & Zero Egress by Default**:
   - `pipedact check` and `pipedact dossier` operate **100% offline** on local files.
   - No telemetry, analytics, file contents, or diagnostic metrics are transmitted over the network to `pipedact` maintainers or third parties.
2. **Opt-in Generative AI Reasoning**:
   - Generative AI analysis (`--ai`) is strictly opt-in and disabled by default.
   - When enabled, source code excerpts surrounding flagged lines are transmitted only to the user's explicitly configured provider (`GEMINI_API_KEY`, `OPENAI_API_KEY`, or local `OLLAMA_HOST`).
   - The default AI engine is the **offline heuristic reasoner**, which runs deterministically with zero network calls.
3. **Conservative Remediation (`--fix`)**:
   - Automated code fixing is limited to mechanical redactions (e.g., wrapping log variables with `maskIdentifier()`).
   - Automated fixes never alter authorization logic, authentication flows, or business rules.
4. **Supply Chain Integrity**:
   - All official releases include SHA-256 checksums published on GitHub Releases.
