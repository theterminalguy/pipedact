package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
	"github.com/theterminalguy/pipedact/pkg/luhn"
)

// ============================================================================
// Principle 7: Safeguards - Logging Sinks
// ============================================================================

type RuleSafeguardLog struct{}

func (r *RuleSafeguardLog) ID() string             { return "PIPEDA-7-SAFEGUARD-LOG" }
func (r *RuleSafeguardLog) PrincipleID() int       { return 7 }
func (r *RuleSafeguardLog) Principle() string     { return "Principle 7: Safeguards" }
func (r *RuleSafeguardLog) Severity() core.Severity { return core.SeverityHigh }
func (r *RuleSafeguardLog) Description() string {
	return "Personal Information leaking into application logs without sanitization."
}
func (r *RuleSafeguardLog) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.7",
		core.FrameworkSOC2:     "CC6.7, P6.1",
		core.FrameworkISO27701: "Clause 7.2.8, 8.2.1",
		core.FrameworkLaw25:    "Section 10",
	}
}

var logSinkRegex = regexp.MustCompile(`(?i)(logger|console|print|logging)\s*(\.|\().*(sin|email|phone|password|healthCard|creditCard)`)
var logSinkStartRegex = regexp.MustCompile(`(?i)(logger|console|print|logging)\s*(\.|\()`)
var piiWordRegex = regexp.MustCompile(`(?i)\b(sin|email|phone|phoneNumber|password|healthCard|creditCard)\b`)

func (r *RuleSafeguardLog) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i := 0; i < len(ctx.Lines); i++ {
		if ctx.IsCommentLine(i) {
			continue
		}
		line := ctx.Lines[i]
		code := ctx.GetCodeLine(i)
		trimmed := strings.TrimSpace(line)

		// Single line match
		if logSinkRegex.MatchString(code) {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceHigh,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Use maskIdentifier() or sha256 pseudonymization before emitting log events.",
				CanAutoFix:        true,
				FrameworkMappings: r.Frameworks(),
			})
			continue
		}

		// Multiline log call detection: if line starts a log call, check following lines within the statement
		if logSinkStartRegex.MatchString(code) {
			var blockLines []string
			blockLines = append(blockLines, code)
			foundPII := false
			foundLine := i + 1

			depth := strings.Count(code, "(") - strings.Count(code, ")")
			for j := i + 1; j < len(ctx.Lines) && j < i+12; j++ {
				if ctx.IsCommentLine(j) {
					continue
				}
				subCode := ctx.GetCodeLine(j)
				blockLines = append(blockLines, subCode)
				depth += strings.Count(subCode, "(") - strings.Count(subCode, ")")

				if piiWordRegex.MatchString(subCode) && !strings.Contains(subCode, "maskIdentifier") && !strings.Contains(subCode, "hash") {
					foundPII = true
					foundLine = j + 1
				}

				if depth <= 0 || strings.Contains(subCode, ");") || strings.Contains(subCode, "}") && depth <= 0 {
					break
				}
			}

			if foundPII {
				violations = append(violations, core.Violation{
					RuleID:            r.ID(),
					PrincipleID:       r.PrincipleID(),
					Principle:         r.Principle(),
					Severity:          sev,
					Confidence:        core.ConfidenceHigh,
					FilePath:          ctx.FilePath,
					Line:              foundLine,
					LineText:          strings.TrimSpace(ctx.Lines[foundLine-1]),
					Message:           r.Description(),
					Remediation:       "Use maskIdentifier() or sha256 pseudonymization before emitting log events.",
					CanAutoFix:        true,
					FrameworkMappings: r.Frameworks(),
				})
			}
		}
	}
	return violations
}

// ============================================================================
// Principle 7 & 6: Safeguards & Accuracy - Hardcoded Canadian SIN
// ============================================================================

type RuleRawSIN struct{}

func (r *RuleRawSIN) ID() string             { return "PIPEDA-7-RAW-SIN" }
func (r *RuleRawSIN) PrincipleID() int       { return 7 }
func (r *RuleRawSIN) Principle() string     { return "Principle 7: Safeguards (SIN)" }
func (r *RuleRawSIN) Severity() core.Severity { return core.SeverityCritical }
func (r *RuleRawSIN) Description() string {
	return "Hardcoded Canadian Social Insurance Number (SIN) detected."
}
func (r *RuleRawSIN) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.7",
		core.FrameworkSOC2:     "CC6.1, P3.1, P6.1",
		core.FrameworkISO27701: "Clause 7.2.8",
		core.FrameworkLaw25:    "Section 10",
	}
}

var sinExtractor = regexp.MustCompile(`\b\d{3}[-\s]\d{3}[-\s]\d{3}\b`)

func maskSIN(sin string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(sin, "")
	if len(digits) >= 3 {
		return fmt.Sprintf("***-***-%s", digits[len(digits)-3:])
	}
	return "***-***-***"
}

func redactSINLine(line string) string {
	return sinExtractor.ReplaceAllString(line, "***-***-***")
}

func (r *RuleRawSIN) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		matches := sinExtractor.FindAllString(code, -1)
		for _, m := range matches {
			isLuhnValid := luhn.IsValidCanadianSIN(m)
			masked := maskSIN(m)
			msg := fmt.Sprintf("Hardcoded Canadian Social Insurance Number pattern (%s) detected.", masked)
			if isLuhnValid {
				msg += " [Luhn Check Passed: Valid format; does not confirm government issuance]"
			}
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceHigh,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          redactSINLine(trimmed),
				Message:           msg,
				Remediation:       "Never hardcode real or valid test SINs. Store in dedicated vault with encryption-at-rest.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// Principle 3: Consent - Opt-in & Third-Party Dispatch
// ============================================================================

type RuleConsentOptIn struct{}

func (r *RuleConsentOptIn) ID() string             { return "PIPEDA-3-OPTIN-MISSING" }
func (r *RuleConsentOptIn) PrincipleID() int       { return 3 }
func (r *RuleConsentOptIn) Principle() string     { return "Principle 3: Consent" }
func (r *RuleConsentOptIn) Severity() core.Severity { return core.SeverityHigh }
func (r *RuleConsentOptIn) Description() string {
	return "Outbound tracking fired with unverified or false user opt-in."
}
func (r *RuleConsentOptIn) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.3",
		core.FrameworkSOC2:     "P1.1, P2.1, P4.1",
		core.FrameworkISO27701: "Clause 7.2.1, 7.2.2",
		core.FrameworkLaw25:    "Section 4, Section 8",
	}
}

var optInFalseRegex = regexp.MustCompile(`(?i)optInConfirmed\s*:\s*false`)
var thirdPartyAdRegex = regexp.MustCompile(`(?i)(trackThirdPartyAdConversion|sendMarketingTelemetry|trackAdConversion)`)

func isGuardedByConsentLocally(ctx *core.FileContext, targetIdx int) bool {
	start := targetIdx - 15
	if start < 0 {
		start = 0
	}
	for k := start; k < targetIdx; k++ {
		if ctx.IsCommentLine(k) {
			continue
		}
		l := ctx.GetCodeLine(k)
		if strings.Contains(l, "hasConsentFor") || strings.Contains(l, "verify_consent") || strings.Contains(l, "consentGuard") || strings.Contains(l, "checkConsent") {
			return true
		}
	}
	return false
}

func (r *RuleConsentOptIn) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		if optInFalseRegex.MatchString(code) {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceHigh,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           "Outbound tracking fired with unverified or false user opt-in (`optInConfirmed: false`).",
				Remediation:       "Enclose tracking call in conditional consent guard: `if (hasConsentFor(...))` and ensure opt-in is verified.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		} else if thirdPartyAdRegex.MatchString(code) {
			if !isGuardedByConsentLocally(ctx, i) {
				violations = append(violations, core.Violation{
					RuleID:            r.ID(),
					PrincipleID:       r.PrincipleID(),
					Principle:         r.Principle(),
					Severity:          sev,
					Confidence:        core.ConfidenceHigh,
					FilePath:          ctx.FilePath,
					Line:              i + 1,
					LineText:          trimmed,
					Message:           "Third-party tracking call executed without affirmative consent check in enclosing block.",
					Remediation:       "Enclose tracking call in conditional consent guard: `if (hasConsentFor(...))`.",
					CanAutoFix:        false,
					FrameworkMappings: r.Frameworks(),
				})
			}
		}
	}
	return violations
}

// ============================================================================
// Principle 4: Limiting Collection - Over-Collection & Minimization
// ============================================================================

type RuleOverCollection struct{}

func (r *RuleOverCollection) ID() string             { return "PIPEDA-4-OVER-COLLECTION" }
func (r *RuleOverCollection) PrincipleID() int       { return 4 }
func (r *RuleOverCollection) Principle() string     { return "Principle 4: Limiting Collection" }
func (r *RuleOverCollection) Severity() core.Severity { return core.SeverityHigh }
func (r *RuleOverCollection) Description() string {
	return "Potential over-collection: Provincial health identifier collected without verified statutory exception under PIPEDA."
}
func (r *RuleOverCollection) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.4",
		core.FrameworkSOC2:     "P3.1, P3.2",
		core.FrameworkISO27701: "Clause 7.2.3",
		core.FrameworkLaw25:    "Section 5",
	}
}

var healthCardRegex = regexp.MustCompile(`(?i)\bhealthCard(Number)?\b`)

func (r *RuleOverCollection) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	// Check if configured schemas explicitly permit health identifiers for authorized purposes
	if cfg != nil {
		for _, p := range cfg.Schemas.AllowedPurposes {
			pLow := strings.ToLower(p)
			if strings.Contains(pLow, "health") || strings.Contains(pLow, "medical") {
				return nil
			}
		}
	}

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		if healthCardRegex.MatchString(code) {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceMedium,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           "Potential over-collection: Provincial health identifier reference detected. Under PIPEDA Principle 4.4, organizations may not collect health identifiers without statutory authorization or direct medical custodian scope.",
				Remediation:       "Remove health identifier from standard retail / auth registration payloads, or configure allowedPurposes in .pipedactrc.yaml if operating under health custodian scope.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// Principle 2: Identifying Purposes - Schema Annotations
// ============================================================================

type RulePurposeUntagged struct{}

func (r *RulePurposeUntagged) ID() string             { return "PIPEDA-2-PURPOSE-UNTAGGED" }
func (r *RulePurposeUntagged) PrincipleID() int       { return 2 }
func (r *RulePurposeUntagged) Principle() string     { return "Principle 2: Identifying Purposes" }
func (r *RulePurposeUntagged) Severity() core.Severity { return core.SeverityMedium }
func (r *RulePurposeUntagged) Description() string {
	return "Database column storing sensitive identifier lacks lawful purpose annotation."
}
func (r *RulePurposeUntagged) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.2",
		core.FrameworkSOC2:     "P1.1, P3.1",
		core.FrameworkISO27701: "Clause 7.2.4",
		core.FrameworkLaw25:    "Section 4",
	}
}

var sensitiveFieldRegex = regexp.MustCompile(`(?i)\b(canadianSIN|sinNumber|socialInsuranceNumber|medicalNotes|creditCardToken|healthData)\b`)

func (r *RulePurposeUntagged) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	// Primarily inspect schema files or model files
	isSchema := ctx.Extension == ".prisma" || ctx.Extension == ".sql" || strings.Contains(ctx.RelativePath, "schema") || strings.Contains(ctx.RelativePath, "model")
	if !isSchema {
		return nil
	}

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		if sensitiveFieldRegex.MatchString(code) && !strings.Contains(code, "@privacy") && !strings.Contains(code, "purpose:") {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceMedium,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Add @privacy(purpose: 'tax_reporting', retention: '7y') attribute.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// Principle 5: Retention & Disposal - TTL & Expiry Hook
// ============================================================================

type RuleRetentionDisposal struct{}

func (r *RuleRetentionDisposal) ID() string             { return "PIPEDA-5-RETENTION-DISPOSAL" }
func (r *RuleRetentionDisposal) PrincipleID() int       { return 5 }
func (r *RuleRetentionDisposal) Principle() string     { return "Principle 5: Retention & Disposal" }
func (r *RuleRetentionDisposal) Severity() core.Severity { return core.SeverityMedium }
func (r *RuleRetentionDisposal) Description() string {
	return "Account model stores permanent user records without declared retention lifespan or deletion schedule."
}
func (r *RuleRetentionDisposal) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.5",
		core.FrameworkSOC2:     "P4.2, P4.3, CC6.5",
		core.FrameworkISO27701: "Clause 7.4.1, 7.4.2",
		core.FrameworkLaw25:    "Section 23",
	}
}

var modelDeclarationRegex = regexp.MustCompile(`(?i)model\s+(User|UserAccount|UserProfile|Account|Customer)\b`)

func (r *RuleRetentionDisposal) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	if ctx.Extension != ".prisma" && !strings.Contains(ctx.RelativePath, "schema") && !strings.Contains(ctx.RelativePath, "model") {
		return nil
	}

	hasAutoPurge := strings.Contains(ctx.Content, "autoPurge") || strings.Contains(ctx.Content, "expiresAt") || strings.Contains(ctx.Content, "ttl")

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		if modelDeclarationRegex.MatchString(code) && !hasAutoPurge {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceMedium,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Define an expiration hook or TTL column: `expiresAt DateTime? @privacy(autoPurge: true)`.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// Principle 9: Individual Access - DSAR Completeness
// ============================================================================

type RuleIncompleteDSR struct{}

func (r *RuleIncompleteDSR) ID() string             { return "PIPEDA-9-INCOMPLETE-DSR" }
func (r *RuleIncompleteDSR) PrincipleID() int       { return 9 }
func (r *RuleIncompleteDSR) Principle() string     { return "Principle 9: Individual Access" }
func (r *RuleIncompleteDSR) Severity() core.Severity { return core.SeverityMedium }
func (r *RuleIncompleteDSR) Description() string {
	return "Data Subject Access Request (DSAR) export omits financial, telemetry, or consent audit trail tables."
}
func (r *RuleIncompleteDSR) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.9",
		core.FrameworkSOC2:     "P5.1, P5.2",
		core.FrameworkISO27701: "Clause 7.3.1",
		core.FrameworkLaw25:    "Section 27, Section 28",
	}
}

var dsrFunctionRegex = regexp.MustCompile(`(?i)(generateUserArchive|exportUserData|generateDsrExport|exportSubjectData)`)

func (r *RuleIncompleteDSR) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	hasFullExport := strings.Contains(ctx.Content, "transactions") && strings.Contains(ctx.Content, "accessLogs")

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		if dsrFunctionRegex.MatchString(code) && !hasFullExport {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceMedium,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Update export handler to bundle billing, consent history, and audit log records.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// Principle 1: Accountability - Unvetted Sub-processors
// ============================================================================

type RuleUnvettedSubprocessor struct{}

func (r *RuleUnvettedSubprocessor) ID() string             { return "PIPEDA-1-UNVETTED-SUBPROCESSOR" }
func (r *RuleUnvettedSubprocessor) PrincipleID() int       { return 1 }
func (r *RuleUnvettedSubprocessor) Principle() string     { return "Principle 1: Accountability" }
func (r *RuleUnvettedSubprocessor) Severity() core.Severity { return core.SeverityMedium }
func (r *RuleUnvettedSubprocessor) Description() string {
	return "External HTTP dispatch sends subject data to unvetted third-party endpoint."
}
func (r *RuleUnvettedSubprocessor) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.1",
		core.FrameworkSOC2:     "CC6.4, CC9.2, P4.1",
		core.FrameworkISO27701: "Clause 7.2.6, 7.5.1",
		core.FrameworkLaw25:    "Section 17",
	}
}

var unvettedDomainRegex = regexp.MustCompile(`(?i)https?://(unverified-metrics|ad-broker|unvetted-analytics|third-party-collector)\.`)

func (r *RuleUnvettedSubprocessor) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		if unvettedDomainRegex.MatchString(code) {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceMedium,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Route through approved internal proxy or obtain contractual PIPEDA Clause 4.1 data processing agreement.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// Principle 6: Accuracy - Validation Hooks
// ============================================================================

type RuleAccuracyValidator struct{}

func (r *RuleAccuracyValidator) ID() string             { return "PIPEDA-6-ACCURACY-VALIDATION" }
func (r *RuleAccuracyValidator) PrincipleID() int       { return 6 }
func (r *RuleAccuracyValidator) Principle() string     { return "Principle 6: Accuracy" }
func (r *RuleAccuracyValidator) Severity() core.Severity { return core.SeverityLow }
func (r *RuleAccuracyValidator) Description() string {
	return "Input handler accepts Canadian SIN without executing Luhn mod-10 validation."
}
func (r *RuleAccuracyValidator) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.6",
		core.FrameworkSOC2:     "P3.2, CC7.1",
		core.FrameworkISO27701: "Clause 7.2.5",
		core.FrameworkLaw25:    "Section 11",
	}
}

var sinInputHandler = regexp.MustCompile(`(?i)(sin|socialInsuranceNumber)\s*:\s*req\.body`)

func (r *RuleAccuracyValidator) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	hasLuhnValidator := strings.Contains(ctx.Content, "isValidCanadianSIN") || strings.Contains(ctx.Content, "sinValidator") || strings.Contains(ctx.Content, "luhn")

	for i, line := range ctx.Lines {
		if ctx.IsCommentLine(i) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		code := ctx.GetCodeLine(i)

		if sinInputHandler.MatchString(code) && !hasLuhnValidator {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceMedium,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Integrate isValidCanadianSIN() Luhn validator on input boundary.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// Principle 8: Openness - Public Privacy Policy Endpoint
// ============================================================================

type RuleOpennessPolicyRoute struct{}

func (r *RuleOpennessPolicyRoute) ID() string             { return "PIPEDA-8-POLICY-ROUTE-MISSING" }
func (r *RuleOpennessPolicyRoute) PrincipleID() int       { return 8 }
func (r *RuleOpennessPolicyRoute) Principle() string     { return "Principle 8: Openness" }
func (r *RuleOpennessPolicyRoute) Severity() core.Severity { return core.SeverityLow }
func (r *RuleOpennessPolicyRoute) Description() string {
	return "Application router defines public user endpoints without declaring a public privacy policy route (/privacy or /legal/privacy)."
}
func (r *RuleOpennessPolicyRoute) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.8",
		core.FrameworkSOC2:     "P1.1, CC2.1",
		core.FrameworkISO27701: "Clause 7.3.2",
		core.FrameworkLaw25:    "Section 8",
	}
}

var routerDeclaration = regexp.MustCompile(`(?i)(app\.use|router\.(get|post)|http\.HandleFunc|r\.GET|engine\.GET)`)

func (r *RuleOpennessPolicyRoute) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	// Only inspect main routing files
	if !strings.Contains(ctx.RelativePath, "route") && !strings.Contains(ctx.RelativePath, "server") && !strings.Contains(ctx.RelativePath, "app.") {
		return nil
	}

	hasAuthRoutes := strings.Contains(ctx.Content, "/auth") || strings.Contains(ctx.Content, "/register") || strings.Contains(ctx.Content, "/user")
	hasPrivacyRoute := strings.Contains(ctx.Content, "/privacy") || strings.Contains(ctx.Content, "/legal")

	if hasAuthRoutes && !hasPrivacyRoute {
		return []core.Violation{
			{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				Confidence:        core.ConfidenceMedium,
				FilePath:          ctx.FilePath,
				Line:              1,
				LineText:          strings.TrimSpace(ctx.Lines[0]),
				Message:           r.Description(),
				Remediation:       "Register a publicly accessible policy handler: router.get('/privacy', servePrivacyPolicy).",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			},
		}
	}
	return nil
}

// ============================================================================
// Principle 10: Challenging Compliance - Dispute Resolution Recourse
// ============================================================================

type RuleChallengingRecourse struct{}

func (r *RuleChallengingRecourse) ID() string             { return "PIPEDA-10-RECOURSE-MISSING" }
func (r *RuleChallengingRecourse) PrincipleID() int       { return 10 }
func (r *RuleChallengingRecourse) Principle() string     { return "Principle 10: Challenging Compliance" }
func (r *RuleChallengingRecourse) Severity() core.Severity { return core.SeverityInfo }
func (r *RuleChallengingRecourse) Description() string {
	return "No statutory dispute recourse endpoint or Privacy Officer contact intake webhook configured."
}
func (r *RuleChallengingRecourse) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkPIPEDA:   "Schedule 1, Clause 4.10",
		core.FrameworkSOC2:     "P1.2, CC2.2",
		core.FrameworkISO27701: "Clause 7.3.3",
		core.FrameworkLaw25:    "Section 29",
	}
}

func (r *RuleChallengingRecourse) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	// Evaluated at project level if config disputeURL is empty
	if cfg != nil && cfg.PrivacyOfficer.DisputeURL == "" {
		return []core.Violation{
			{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          core.SeverityInfo,
				Confidence:        core.ConfidenceLow,
				FilePath:          ctx.FilePath,
				Line:              1,
				LineText:          "",
				Message:           r.Description(),
				Remediation:       "Specify privacy_officer.dispute_url in .pipedactrc.yaml or expose /privacy/dispute endpoint.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			},
		}
	}
	return nil
}
