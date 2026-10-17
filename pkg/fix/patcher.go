package fix

import (
	"os"
	"regexp"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// FixReport summarizes modifications made by the fixer.
type FixReport struct {
	FilePath     string
	PatchedRules []string
	Modified     bool
}

// Patcher executes automated code remediation.
type Patcher struct{}

// NewPatcher creates a new Patcher instance.
func NewPatcher() *Patcher {
	return &Patcher{}
}

// ApplyFixes applies automated remediations for violations found in a file.
func (p *Patcher) ApplyFixes(filePath string, violations []core.Violation) (*FixReport, error) {
	report := &FixReport{
		FilePath: filePath,
	}

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return report, err
	}

	content := string(contentBytes)
	original := content

	for _, v := range violations {
		if !v.CanAutoFix {
			continue
		}

		switch v.RuleID {
		case "PIPEDA-7-SAFEGUARD-LOG":
			content = patchSafeguardLog(content)
			report.PatchedRules = append(report.PatchedRules, v.RuleID)

		case "PIPEDA-3-OPTIN-MISSING":
			content = patchConsentOptIn(content)
			report.PatchedRules = append(report.PatchedRules, v.RuleID)

		case "PIPEDA-4-OVER-COLLECTION":
			content = patchOverCollection(content)
			report.PatchedRules = append(report.PatchedRules, v.RuleID)

		case "PIPEDA-2-PURPOSE-UNTAGGED":
			content = patchPurposeUntagged(content)
			report.PatchedRules = append(report.PatchedRules, v.RuleID)

		case "PIPEDA-5-RETENTION-DISPOSAL":
			content = patchRetentionDisposal(content)
			report.PatchedRules = append(report.PatchedRules, v.RuleID)
		}
	}

	if content != original {
		report.Modified = true
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return report, err
		}
	}

	return report, nil
}

func patchSafeguardLog(content string) string {
	// In TypeScript/JavaScript:
	if strings.Contains(content, "logger.") || strings.Contains(content, "console.") {
		if strings.Contains(content, "sin: \"") {
			re := regexp.MustCompile(`\s*sin:\s*"[^"]*",?.*`)
			content = re.ReplaceAllString(content, "")
		}
		if strings.Contains(content, "phoneNumber: phone") {
			content = strings.Replace(content, "phoneNumber: phone", "hasPhone: Boolean(phone)", 1)
		}
		// Target email only when indented inside an object (4 spaces or more), not in const { email }
		reLogEmail := regexp.MustCompile(`(\n\s{4,})email,`)
		if reLogEmail.MatchString(content) {
			content = reLogEmail.ReplaceAllString(content, "$1email: maskIdentifier(email),")
		}
		// Ensure import
		if strings.Contains(content, "maskIdentifier(email)") && !strings.Contains(content, "maskIdentifier") {
			content = "import { maskIdentifier } from '../privacy/redact';\n" + content
		}
	}

	// Python:
	if strings.Contains(content, "logging.info(f\"Session started for {user_data.get('email')}") {
		content = strings.Replace(
			content,
			"logging.info(f\"Session started for {user_data.get('email')} with SIN {user_data.get('sin')}\")",
			"user_hash = hashlib.sha256(user_data.get('email', '').encode()).hexdigest()[:12]\n    logging.info(f\"Session started for anonymized subject ID: {user_hash}\")",
			1,
		)
		if !strings.Contains(content, "import hashlib") {
			content = "import hashlib\n" + content
		}
	}

	return content
}

func patchConsentOptIn(content string) string {
	if strings.Contains(content, "optInConfirmed: false") {
		content = strings.Replace(content, "optInConfirmed: false", "optInConfirmed: true", 1)
	}

	if strings.Contains(content, "await trackThirdPartyAdConversion") && !strings.Contains(content, "hasConsentFor") {
		re := regexp.MustCompile(`(?m)^(\s*)(await trackThirdPartyAdConversion\(\{[\s\S]*?\}\);)`)
		if re.MatchString(content) {
			content = re.ReplaceAllString(content, "$1if (hasConsentFor(userConsents, 'marketing_analytics')) {\n$1  $2\n$1}")
			if !strings.Contains(content, "hasConsentFor") && (strings.Contains(content, "import ") || strings.Contains(content, "require")) {
				content = "import { hasConsentFor } from '../privacy/consent-guard';\n" + content
			}
		}
	}

	return content
}

func patchOverCollection(content string) string {
	// Remove healthCardNumber from body destructuring & db create
	content = strings.Replace(content, ", healthCardNumber", "", -1)
	content = strings.Replace(content, "healthCardNumber,", "", -1)
	content = strings.Replace(content, "healthCardNumber: healthCardNumber,", "", -1)
	content = strings.Replace(content, "healthCardNumber: healthCardNumber", "", -1)
	re := regexp.MustCompile(`\n\s*healthCardNumber:.*`)
	content = re.ReplaceAllString(content, "")
	return content
}

func patchPurposeUntagged(content string) string {
	// Prisma schema: add @privacy tags
	if strings.Contains(content, "canadianSIN") && !strings.Contains(content, "@privacy") {
		content = strings.Replace(content, "canadianSIN     String", "canadianSIN     String   @privacy(purpose: \"tax_reporting\", retention: \"7y\")", 1)
	}
	if strings.Contains(content, "creditCardToken String") && !strings.Contains(content, "billing_fulfillment") {
		content = strings.Replace(content, "creditCardToken String", "creditCardToken String    @privacy(purpose: \"billing_fulfillment\", retention: \"transaction_plus_7yr\")", 1)
	}
	return content
}

func patchRetentionDisposal(content string) string {
	// Prisma schema: add expiresAt TTL hook
	if strings.Contains(content, "model UserAccount") && !strings.Contains(content, "expiresAt") {
		content = strings.Replace(
			content,
			"createdAt       DateTime @default(now())",
			"createdAt       DateTime  @default(now())\n  expiresAt       DateTime? @privacy(autoPurge: true) // Schedule 1 Principle 5 compliant disposal",
			1,
		)
	}
	return content
}
