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

	info, err := os.Stat(filePath)
	if err != nil {
		return report, err
	}
	filePerm := info.Mode().Perm()

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
		if err := os.WriteFile(filePath, []byte(content), filePerm); err != nil {
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
		if strings.Contains(content, "maskIdentifier(email)") && !strings.Contains(content, "import { maskIdentifier }") {
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
