# Compliance & Static Analysis Coverage Limitations

This document provides engineering and compliance teams with a rigorous assessment of what `pipedact`'s static analysis engine can verify, what it cannot verify, and the organizational obligations required for comprehensive compliance.

---

## The Static Analysis Boundary

Static application security testing (SAST) analyzes source code, database schemas, and configuration manifests at compile time or in CI/CD. It operates without executing the software or observing runtime network traffic.

```
┌───────────────────────────────────────────────┐
│              Complete Compliance              │
│                                               │
│   ┌─────────────────────────┐                 │
│   │   Operational & Legal   │                 │
│   │   - Human consent forms │                 │
│   │   - Signed DPAs/BAAs    │                 │
│   │   - Incident response   │                 │
│   │   - CPA Type II audits  │                 │
│   │                         │                 │
│   │   ┌─────────────────┐   │                 │
│   │   │ pipedact Scope  │   │                 │
│   │   │ - Static checks │   │                 │
│   │   │ - Schemas       │   │                 │
│   │   │ - Secrets       │   │                 │
│   │   │ - Log sinks     │   │                 │
│   │   └─────────────────┘   │                 │
│   └─────────────────────────┘                 │
└───────────────────────────────────────────────┘
```

---

## What pipedact Can Verify vs What Requires Operational Action

### 1. Canadian PIPEDA (Schedule 1)

| Principle | Verified by pipedact (Static Code) | Requires External / Operational Action |
|:---|:---|:---|
| **1. Accountability** | Detects unvetted external analytics/broker API calls in code. | Contractual Data Processing Agreements (DPAs) signed with vendors; appointment and governance of Privacy Officer. |
| **2. Identifying Purposes** | Checks that database schemas annotate purpose tags (`@privacy`). | Privacy notices presented to users at point of collection; legal review of stated purposes. |
| **3. Consent** | Ensures tracking SDK calls are guarded by conditional checks. | Ensuring consent language is plain, understandable, and complies with OPC Guidelines for Meaningful Consent. |
| **4. Limiting Collection** | Flags provincial health cards and unvaulted SINs in auth models. | Business process audits to ensure non-code collection (paper, telephone) is minimal. |
| **5. Retention & Disposal** | Checks for expiration timestamps and TTL purge hooks in schemas. | Physical media destruction, database purge cron verification, legal retention schedules. |
| **6. Accuracy** | Validates presence of mod-10 Luhn check on Canadian SIN inputs. | Periodic customer verification routines and data quality audits. |
| **7. Safeguards** | Blocks PII in logs, detects hardcoded secrets, weak crypto, CORS. | Encryption-at-rest keys, employee access controls, penetration testing, physical security. |
| **8. Openness** | Verifies presence of public `/privacy` endpoint in router. | Maintaining an up-to-date, legally accurate privacy policy drafted by legal counsel. |
| **9. Individual Access** | Audits user archive export functions to ensure cross-table joins. | 30-day response SLA enforcement, identity verification before fulfilling DSARs. |
| **10. Challenging Compliance** | Checks configuration for dispute recourse URL. | Operational dispute resolution handling and response to OPC inquiries. |

---

### 2. AICPA SOC 2 Type II

> [!IMPORTANT]
> A SOC 2 Type II examination evaluates the **operating effectiveness** of internal controls over an extended period (typically 3 to 12 months). A static code scanner assesses code artifacts at a single point in time.

- **What pipedact provides for SOC 2**:
  - Automated pre-commit and CI/CD testing for specific technical controls (`CC6.1`, `CC6.6`, `CC6.7`, `P1.1`–`P5.1`).
  - Repeatable, timestamped evidence that source code repositories do not contain plaintext secrets, weak crypto, or unredacted log sinks.
- **What is required for a SOC 2 Type II report**:
  - Engagement of an independent, accredited CPA firm.
  - Auditor sampling across the observation period.
  - Verification of non-code controls (HR policies, background checks, change management tickets, disaster recovery drills).

---

### 3. Quebec Law 25 (Act Respecting the Protection of Personal Information)

- **What pipedact checks**:
  - Automated consent gating before data dispatch.
  - Cross-border / external service provider dispatch endpoints.
  - De-identification and pseudonymization practices in log sinks.
- **What requires organizational process**:
  - Conducting formal Privacy Impact Assessments (PIAs) for cross-border data transfers.
  - Publishing the Privacy Officer's contact details on the organization's public website.
  - 72-hour mandatory breach reporting to the *Commission d'accès à l'information* (CAI).

---

## Summary Disclaimer

`pipedact` is an engineering tool designed to detect privacy and security anti-patterns in source code before deployment. It is not legal software, and running `pipedact` does not replace professional legal counsel, privacy audits, or CPA SOC 2 examinations.
