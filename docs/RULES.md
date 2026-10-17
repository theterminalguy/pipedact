# Rules Reference Guide

This document catalogs every automated rule implemented in `pipedact`. Each entry explains what the rule detects, why it is flagged, sample vulnerable and remediated patterns, regulatory mappings, supported languages, and known limitations.

---

## Rule Inventory

| Rule ID | Category / Principle | Default Severity | Auto-Fix Safe? | Supported Formats |
|:---|:---|:---|:---|:---|
| [`PIPEDA-1-UNVETTED-SUBPROCESSOR`](#pipeda-1-unvetted-subprocessor) | Principle 1: Accountability | `MEDIUM` | No (Manual Review) | `.js`, `.ts`, `.py`, `.go` |
| [`PIPEDA-2-PURPOSE-UNTAGGED`](#pipeda-2-purpose-untagged) | Principle 2: Identifying Purposes | `MEDIUM` | Yes (Safe Tagging) | `.prisma`, `.sql`, models |
| [`PIPEDA-3-OPTIN-MISSING`](#pipeda-3-optin-missing) | Principle 3: Consent | `HIGH` | Yes (Consent Guard) | `.js`, `.ts`, `.py`, `.go` |
| [`PIPEDA-4-OVER-COLLECTION`](#pipeda-4-over-collection) | Principle 4: Limiting Collection | `HIGH` | Yes (Field Removal) | `.js`, `.ts`, `.py`, `.go` |
| [`PIPEDA-5-RETENTION-DISPOSAL`](#pipeda-5-retention-disposal) | Principle 5: Retention & Disposal | `MEDIUM` | Yes (TTL Hook) | `.prisma`, schema models |
| [`PIPEDA-6-ACCURACY-VALIDATION`](#pipeda-6-accuracy-validation) | Principle 6: Accuracy | `LOW` | No (Manual Review) | `.js`, `.ts`, `.go`, `.py` |
| [`PIPEDA-7-SAFEGUARD-LOG`](#pipeda-7-safeguard-log) | Principle 7: Safeguards | `HIGH` | Yes (Masking Call) | `.js`, `.ts`, `.py`, `.go` |
| [`PIPEDA-7-RAW-SIN`](#pipeda-7-raw-sin) | Principle 7: Safeguards (SIN) | `CRITICAL` | No (Manual Vaulting) | All scannable files |
| [`PIPEDA-8-POLICY-ROUTE-MISSING`](#pipeda-8-policy-route-missing) | Principle 8: Openness | `LOW` | No (Manual Review) | Router files (`app.*`, `route.*`) |
| [`PIPEDA-9-INCOMPLETE-DSR`](#pipeda-9-incomplete-dsr) | Principle 9: Individual Access | `MEDIUM` | Yes (Export Bundle) | `.js`, `.ts`, `.py`, `.go` |
| [`PIPEDA-10-RECOURSE-MISSING`](#pipeda-10-recourse-missing) | Principle 10: Challenging Compliance | `INFO` | No (Config Setting) | Project config (`.pipedactrc.yaml`) |
| [`SOC2-CC6-HARDCODED-SECRET`](#soc2-cc6-hardcoded-secret) | Common Criteria CC6.1 / CC6.6 | `CRITICAL` | No (Manual Secret Mgr) | All scannable files |
| [`SOC2-CC6-INSECURE-COOKIE`](#soc2-cc6-insecure-cookie) | Common Criteria CC6.6 / CC6.7 | `HIGH` | No (Manual Review) | `.js`, `.ts`, `.py`, `.go` |
| [`SOC2-CC6-WEAK-CRYPTO`](#soc2-cc6-weak-crypto) | Common Criteria CC6.6 (Crypto) | `HIGH` | No (Manual Upgrade) | `.js`, `.ts`, `.py`, `.go` |
| [`SOC2-CC6-WILDCARD-CORS`](#soc2-CC6-wildcard-cors) | Common Criteria CC6.6 (Boundary) | `MEDIUM` | No (Manual Origin List) | `.js`, `.ts`, `.py`, `.go` |

---

## Detailed Rule Specifications

### `PIPEDA-1-UNVETTED-SUBPROCESSOR`
- **What it detects**: Outbound HTTP requests or SDK dispatches sending customer data to unvetted third-party metrics/broker endpoints.
- **Why it matters**: Under PIPEDA Principle 1 (Clause 4.1.3), organizations must use contractual or other means to provide a comparable level of protection while personal data is being processed by a third party.
- **Framework Mappings**: PIPEDA Clause 4.1; SOC 2 CC6.4, CC9.2; ISO/IEC 27701 Clause 7.2.6; Quebec Law 25 Section 17.
- **Vulnerable Pattern**:
  ```typescript
  fetch("https://unverified-metrics-cdn.com/collect", { method: "POST", body: JSON.stringify(userData) });
  ```
- **Remediated Pattern**:
  ```typescript
  fetch("https://analytics.internal.corporate-proxy.ca/collect", { method: "POST", body: JSON.stringify(userData) });
  ```

---

### `PIPEDA-2-PURPOSE-UNTAGGED`
- **What it detects**: Database schema columns storing sensitive identifiers (e.g. SIN, medical notes, credit cards) without explicit purpose attributes.
- **Nature of Check**: **Engineering Convention**. PIPEDA requires identifying purposes at or before collection; tagging database schemas with `@privacy(purpose: "...")` is an architectural convention enforced by `pipedact` to maintain traceability at the data storage layer.
- **Framework Mappings**: PIPEDA Clause 4.2; SOC 2 P1.1, P3.1; ISO/IEC 27701 Clause 7.2.4; Quebec Law 25 Section 4.
- **Vulnerable Pattern**:
  ```prisma
  model Customer {
    id          String @id
    canadianSIN String
  }
  ```
- **Remediated Pattern**:
  ```prisma
  model Customer {
    id          String @id
    canadianSIN String @privacy(purpose: "tax_invoicing_cra", retention: "7y")
  }
  ```

---

### `PIPEDA-3-OPTIN-MISSING`
- **What it detects**: Outbound marketing/tracking dispatches executed without affirmative consent or with `optInConfirmed: false`.
- **Why it matters**: PIPEDA Principle 3 requires knowledge and consent for the collection, use, or disclosure of personal information, especially for secondary advertising purposes.
- **Framework Mappings**: PIPEDA Clause 4.3; SOC 2 P1.1, P2.1; ISO/IEC 27701 Clause 7.2.1; Quebec Law 25 Section 4, 8.
- **Vulnerable Pattern**:
  ```typescript
  await trackThirdPartyAdConversion({ email, optInConfirmed: false });
  ```
- **Remediated Pattern**:
  ```typescript
  if (hasConsentFor(userConsents, 'marketing_telemetry')) {
    await trackThirdPartyAdConversion({ email, optInConfirmed: true });
  }
  ```

---

### `PIPEDA-4-OVER-COLLECTION`
- **What it detects**: Collection of high-sensitivity government identifiers, specifically provincial health cards, in standard retail/commercial authentication payloads.
- **Why it matters**: Provincial health cards are legally restricted under provincial legislation (e.g., Ontario PHIPA, Alberta HIA) and PIPEDA Principle 4 (Clause 4.4 - Limiting Collection).
- **Framework Mappings**: PIPEDA Clause 4.4; SOC 2 P3.1, P3.2; ISO/IEC 27701 Clause 7.2.3; Quebec Law 25 Section 5.
- **Vulnerable Pattern**:
  ```typescript
  const { email, password, healthCardNumber } = req.body;
  ```
- **Remediated Pattern**:
  ```typescript
  const { email, password } = req.body; // Remove healthCardNumber unless acting as a designated health custodian
  ```

---

### `PIPEDA-5-RETENTION-DISPOSAL`
- **What it detects**: Account or profile database models that lack any declared expiration date, TTL index, or autoPurge schedule.
- **Why it matters**: Principle 5 requires personal information to be retained only as long as necessary.
- **Framework Mappings**: PIPEDA Clause 4.5; SOC 2 P4.2, P4.3, CC6.5; ISO/IEC 27701 Clause 7.4.1; Quebec Law 25 Section 23.
- **Vulnerable Pattern**:
  ```prisma
  model UserAccount {
    id        String   @id
    email     String
    createdAt DateTime @default(now())
  }
  ```
- **Remediated Pattern**:
  ```prisma
  model UserAccount {
    id        String    @id
    email     String
    createdAt DateTime  @default(now())
    expiresAt DateTime? @privacy(autoPurge: true)
  }
  ```

---

### `PIPEDA-6-ACCURACY-VALIDATION`
- **What it detects**: API handlers accepting Canadian Social Insurance Numbers (SIN) without applying mod-10 Luhn checksum validation.
- **Why it matters**: Principle 6 requires personal data used to make decisions about individuals to be accurate and complete.
- **Framework Mappings**: PIPEDA Clause 4.6; SOC 2 P3.2, CC7.1; ISO/IEC 27701 Clause 7.2.5; Quebec Law 25 Section 11.
- **Vulnerable Pattern**:
  ```typescript
  const sin = req.body.sin;
  await saveSIN(sin);
  ```
- **Remediated Pattern**:
  ```typescript
  const sin = req.body.sin;
  if (!isValidCanadianSIN(sin)) {
    return res.status(400).json({ error: "Invalid Canadian SIN" });
  }
  await saveSIN(sin);
  ```

---

### `PIPEDA-7-SAFEGUARD-LOG`
- **What it detects**: Unsanitized Personal Information (SIN, email, phone, passwords, credit cards) passed to logging sinks (`console.log`, `logger.info`, `logging.info`).
- **Why it matters**: Principle 7 requires security safeguards appropriate to data sensitivity. Unredacted logs expose PII to broad internal tooling and log aggregation vendors.
- **Framework Mappings**: PIPEDA Clause 4.7; SOC 2 CC6.7, P6.1; ISO/IEC 27701 Clause 7.2.8; Quebec Law 25 Section 10.
- **Vulnerable Pattern**:
  ```typescript
  logger.info("Subject authenticated:", { email: user.email, sin: user.sin });
  ```
- **Remediated Pattern**:
  ```typescript
  logger.info("Subject authenticated:", { userId: user.id });
  ```

---

### `PIPEDA-7-RAW-SIN`
- **What it detects**: Hardcoded Canadian Social Insurance Numbers in source code, verified using the Canadian federal mod-10 Luhn algorithm.
- **Why it matters**: SINs must never be hardcoded in test fixtures or codebases due to identity fraud and tax privacy exposure.
- **Framework Mappings**: PIPEDA Clause 4.7; SOC 2 CC6.1, P3.1; ISO/IEC 27701 Clause 7.2.8; Quebec Law 25 Section 10.

---

### `PIPEDA-8-POLICY-ROUTE-MISSING`
- **What it detects**: Application routers that expose user registration or authentication endpoints without declaring a public privacy policy route (`/privacy` or `/legal`).
- **Framework Mappings**: PIPEDA Clause 4.8; SOC 2 P1.1, CC2.1; ISO/IEC 27701 Clause 7.3.2; Quebec Law 25 Section 8.

---

### `PIPEDA-9-INCOMPLETE-DSR`
- **What it detects**: Data Subject Access Request (DSAR) export routines that query only a user profile table while omitting billing history, audit logs, or consent records.
- **Framework Mappings**: PIPEDA Clause 4.9; SOC 2 P5.1, P5.2; ISO/IEC 27701 Clause 7.3.1; Quebec Law 25 Section 27, 28.

---

### `PIPEDA-10-RECOURSE-MISSING`
- **What it detects**: Absence of a designated dispute resolution URL or privacy officer intake endpoint in project configuration.
- **Framework Mappings**: PIPEDA Clause 4.10; SOC 2 P1.2, CC2.2; ISO/IEC 27701 Clause 7.3.3; Quebec Law 25 Section 29.

---

### `SOC2-CC6-HARDCODED-SECRET`
- **What it detects**: High-entropy API keys, JWT signing tokens, private keys, or database passwords committed to source files.
- **Framework Mappings**: SOC 2 CC6.1, CC6.6; PIPEDA Clause 4.7; ISO/IEC 27701 Clause 7.2.8; Quebec Law 25 Section 10.

---

### `SOC2-CC6-INSECURE-COOKIE`
- **What it detects**: Cookies transmitted without `secure: true` or `httpOnly: true` attributes.
- **Framework Mappings**: SOC 2 CC6.6, CC6.7; PIPEDA Clause 4.7; ISO/IEC 27701 Clause 7.2.8; Quebec Law 25 Section 10.

---

### `SOC2-CC6-WEAK-CRYPTO`
- **What it detects**: Invocations of cryptographically broken hash algorithms (`MD5`, `SHA-1`) in source code.
- **Framework Mappings**: SOC 2 CC6.6; PIPEDA Clause 4.7; ISO/IEC 27701 Clause 7.2.8; Quebec Law 25 Section 10.

---

### `SOC2-CC6-WILDCARD-CORS`
- **What it detects**: Permissive wildcard `origin: '*'` Cross-Origin Resource Sharing configurations on web routers.
- **Framework Mappings**: SOC 2 CC6.6; PIPEDA Clause 4.7; ISO/IEC 27701 Clause 7.2.8; Quebec Law 25 Section 10.
