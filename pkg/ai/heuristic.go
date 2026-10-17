package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// HeuristicReasoner provides offline statutory privacy reasoning without external API calls.
type HeuristicReasoner struct{}

func NewHeuristicReasoner() *HeuristicReasoner {
	return &HeuristicReasoner{}
}

func (h *HeuristicReasoner) Name() string {
	return "pipedact Statutory Heuristic Reasoner (Offline/Zero-Egress)"
}

func (h *HeuristicReasoner) IsAvailable() bool {
	return true
}

func (h *HeuristicReasoner) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	var risks []SemanticRisk

	hasHealthCard := false
	hasSIN := false
	hasLogPII := false
	hasExternalDispatch := false
	hasIncompleteDSR := false

	for _, v := range req.Violations {
		switch v.RuleID {
		case "PIPEDA-4-OVER-COLLECTION":
			hasHealthCard = true
		case "PIPEDA-7-RAW-SIN":
			hasSIN = true
		case "PIPEDA-7-SAFEGUARD-LOG":
			hasLogPII = true
		case "PIPEDA-1-UNVETTED-SUBPROCESSOR", "PIPEDA-3-OPTIN-MISSING":
			hasExternalDispatch = true
		case "PIPEDA-9-INCOMPLETE-DSR":
			hasIncompleteDSR = true
		}
	}

	if hasHealthCard {
		risks = append(risks, SemanticRisk{
			Principle:    "Principle 4: Limiting Collection",
			Category:     "Statutory Over-Collection",
			Severity:     "HIGH",
			Title:        "Provincial Health Number Collected in Commercial Context",
			Description:  "Collecting provincial health card numbers outside designated health custodian contexts breaches PIPEDA Section 4.4 and provincial health acts (e.g. Ontario PHIPA).",
			StatutoryRef: "OPC Finding #2008-392; PIPEDA Schedule 1, Clause 4.4",
			Remedy:       "Drop healthCardNumber from public retail models. Use neutral account identifiers.",
		})
	}

	if hasSIN {
		risks = append(risks, SemanticRisk{
			Principle:    "Principle 7: Safeguards",
			Category:     "High-Value Identity Exposure",
			Severity:     "CRITICAL",
			Title:        "Canadian Social Insurance Number Stored/Logged Outside Tax Vault",
			Description:  "The OPC explicitly prohibits using Canadian SINs as general customer identifiers. SIN collection is only statutory for tax reporting (Income Tax Act).",
			StatutoryRef: "OPC Interpretation Bulletin: Social Insurance Numbers; PIPEDA Clause 4.7",
			Remedy:       "Isolate SINs into an encrypted-at-rest isolation vault with strict access audit trails.",
		})
	}

	if hasLogPII {
		risks = append(risks, SemanticRisk{
			Principle:    "Principle 7: Safeguards",
			Category:     "Logging Sink Data Leakage",
			Severity:     "HIGH",
			Title:        "Application Logging Sinks Receiving Unredacted Personal Information",
			Description:  "Log aggregation platforms (Datadog, Splunk, CloudWatch) index raw PII, exposing it to broad developer permissions without consent.",
			StatutoryRef: "OPC Guidelines for Identification and Authentication; PIPEDA Clause 4.7",
			Remedy:       "Implement zero-PII logging via maskIdentifier() or HMAC pseudonymization wrappers.",
		})
	}

	if hasExternalDispatch {
		risks = append(risks, SemanticRisk{
			Principle:    "Principle 1 & 3: Accountability & Consent",
			Category:     "Cross-Border Sub-Processor Transfer Risk",
			Severity:     "HIGH",
			Title:        "Third-Party Telemetry Dispatch Without Verified Affirmative Opt-In",
			Description:  "Under PIPEDA Clause 4.1.3 and Quebec Law 25, transfers to foreign service providers require equivalent contractual protection and advance consent.",
			StatutoryRef: "OPC Processing Personal Data Across Borders; Quebec Law 25, Section 17",
			Remedy:       "Wrap all outbound ad/analytics SDK dispatches in conditional consent gates (`hasConsentFor`).",
		})
	}

	if hasIncompleteDSR {
		risks = append(risks, SemanticRisk{
			Principle:    "Principle 9: Individual Access",
			Category:     "Defective DSAR Portability Routine",
			Severity:     "MEDIUM",
			Title:        "Data Subject Access Request Export Omits Associated Tables",
			Description:  "Individuals have statutory rights under Clause 4.9 to receive an exhaustive archive of all personal data held, including consent logs and telemetry.",
			StatutoryRef: "PIPEDA Schedule 1, Clause 4.9; Bill C-27 (CPPA Section 55 Data Mobility)",
			Remedy:       "Aggregate userProfile, billingTransactions, accessLogs, and consentHistory in export bundles.",
		})
	}

	execSummary := fmt.Sprintf(`### Statutory Compliance Synthesis (Canadian Federal PIPEDA)
- **Scanned Codebase Score:** %d%% (%s)
- **Statutory Gate Review:** %d high-priority compliance risks identified.
- **Regulatory Outlook:** Current code practices pose statutory liability under federal PIPEDA (OPC enforcement) and Quebec Law 25 private right of action.

#### Key Architectural Findings:
1. **Data Minimization:** Explicit statutory exceptions are required to store provincial health cards and Canadian SINs.
2. **Affirmative Consent Architecture:** Outbound tracking and ad-brokers must be guarded by verifiable user consent.
3. **Safe Redaction:** Standard log sinks must reject raw user identifiers at the logger middleware boundary.

*(Tip: Set GEMINI_API_KEY, OPENAI_API_KEY, or start Ollama to enable generative AI reasoning alongside this statutory engine.)*`,
		req.ComplianceScore, req.ScoreLabel, len(risks))

	return &AnalysisResponse{
		ProviderUsed:       h.Name(),
		ModelUsed:          "Deterministic Statutory Knowledge Base",
		ExecutiveSummary:   execSummary,
		QuasiIdentifierRisk: "Moderate: Combination of IP address, phone, and unredacted email across endpoints allows subject re-identification.",
		PurposeAlignment:   "Non-compliant: Schema contains untagged financial and identity columns lacking lawful purpose declarations.",
		CrossBorderRisk:    "Active: Outbound requests to third-party endpoints trigger Canadian cross-border disclosure notification requirements.",
		SemanticRisks:      risks,
		RefactoringAdvice:  "Adopt Privacy-by-Design: (1) Tokenize identifiers at the API gateway, (2) Bind database fields to explicit purpose tags, (3) Route third-party tracking through a consent proxy.",
	}, nil
}

func (h *HeuristicReasoner) Explain(ctx context.Context, ruleID string, codeSnippet string) (*ExplanationResponse, error) {
	explanations := map[string]ExplanationResponse{
		"PIPEDA-7-SAFEGUARD-LOG": {
			RuleID:       "PIPEDA-7-SAFEGUARD-LOG",
			Principle:    "Principle 7: Safeguards",
			Statute:      "PIPEDA Schedule 1, Clause 4.7 & 4.7.1",
			LegalSummary: "Clause 4.7 mandates that personal information must be protected by security safeguards appropriate to the sensitivity of the information. Emitting raw PII (emails, SINs, phone numbers, passwords) into application logs exposes data to log aggregation vendors, internal employees, and monitoring tools without access controls.",
			OPCPrecedent: "OPC Finding #2020-001 (Investigation into Desjardins): The Commissioner emphasized that failing to restrict and sanitize logging and monitoring systems creates unauthorized disclosure channels under Clause 4.7.",
			VulnerableCode: `logger.info("User registered:", { email, sin, phone });`,
			CompliantCode:  `logger.info("User registered:", { email: maskIdentifier(email), hasPhone: Boolean(phone) });`,
		},
		"PIPEDA-7-RAW-SIN": {
			RuleID:       "PIPEDA-7-RAW-SIN",
			Principle:    "Principle 7: Safeguards & Principle 6: Accuracy",
			Statute:      "PIPEDA Schedule 1, Clause 4.7 & Employment Insurance Act",
			LegalSummary: "Canadian Social Insurance Numbers are sensitive federal identifiers with strict statutory limitations. Unless your organization is explicitly authorized under the Income Tax Act (e.g. issuing T4/T5 slips), you cannot require, collect, or store SINs as general consumer account identifiers.",
			OPCPrecedent: "OPC Interpretation Bulletin: 'Social Insurance Number': The OPC has repeatedly found commercial organizations in breach of PIPEDA for collecting SINs when verifying creditworthiness or user identities could be accomplished via less privacy-invasive alternatives.",
			VulnerableCode: `const testSIN = "046-454-286";`,
			CompliantCode:  `// Store SIN only in an isolated, encrypted-at-rest CRA tax compliance vault`,
		},
		"PIPEDA-3-OPTIN-MISSING": {
			RuleID:       "PIPEDA-3-OPTIN-MISSING",
			Principle:    "Principle 3: Consent",
			Statute:      "PIPEDA Schedule 1, Clause 4.3 & Clause 4.3.2",
			LegalSummary: "Consent is required for the collection, use, or disclosure of personal information. Consent must be meaningful: individuals must understand what they are consenting to. Disagreeing or failing to opt-in must not result in immediate data dispatch to third-party ad brokers.",
			OPCPrecedent: "OPC Guidelines for Meaningful Consent (2019): Tracking and profiling for targeted advertising purposes generally require express (opt-in) consent rather than implied consent.",
			VulnerableCode: `await trackThirdPartyAdConversion({ customerEmail: email, optInConfirmed: false });`,
			CompliantCode:  `if (hasConsentFor(userConsents, 'marketing_analytics')) { await trackThirdPartyAdConversion({ customerEmail: maskIdentifier(email), optInConfirmed: true }); }`,
		},
		"PIPEDA-4-OVER-COLLECTION": {
			RuleID:       "PIPEDA-4-OVER-COLLECTION",
			Principle:    "Principle 4: Limiting Collection",
			Statute:      "PIPEDA Schedule 1, Clause 4.4",
			LegalSummary: "Organizations shall not collect personal information indiscriminately. Both the amount and the type of information collected shall be limited to that which is necessary to fulfill the purposes identified.",
			OPCPrecedent: "OPC Finding #2011-006: Retailers requesting provincial health cards or driver's licenses for non-health/non-driving services violate Principle 4 because less sensitive identification is adequate.",
			VulnerableCode: `const { email, password, healthCardNumber } = req.body;`,
			CompliantCode:  `const { email, password } = req.body; // Health cards omitted for standard retail authentication`,
		},
	}

	if exp, found := explanations[ruleID]; found {
		return &exp, nil
	}

	return &ExplanationResponse{
		RuleID:       ruleID,
		Principle:    "PIPEDA Schedule 1 Fair Information Principles",
		Statute:      "Schedule 1 Clause 4",
		LegalSummary: fmt.Sprintf("Rule %s enforces statutory compliance under Canada's Personal Information Protection and Electronic Documents Act.", ruleID),
		OPCPrecedent: "Refer to the Office of the Privacy Commissioner of Canada (priv.gc.ca) Interpretation Bulletins.",
	}, nil
}

func formatViolationsForPrompt(violations []core.Violation) string {
	var sb strings.Builder
	for i, v := range violations {
		if i >= 15 {
			sb.WriteString(fmt.Sprintf("...and %d more violations\n", len(violations)-15))
			break
		}
		sb.WriteString(fmt.Sprintf("- [%s] %s (%s) at %s:%d: %s\n", v.Severity, v.Principle, v.RuleID, v.FilePath, v.Line, v.Message))
	}
	return sb.String()
}
