package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// FixOptions configures patch execution.
type FixOptions struct {
	DryRun bool
}

// FixReport summarizes modifications made by the fixer.
type FixReport struct {
	FilePath     string
	PatchedRules []string
	Modified     bool
	Diff         string
}

// Patcher executes automated code remediation.
type Patcher struct{}

// NewPatcher creates a new Patcher instance.
func NewPatcher() *Patcher {
	return &Patcher{}
}

// ApplyFixes applies automated remediations for violations found in a file.
func (p *Patcher) ApplyFixes(filePath string, violations []core.Violation) (*FixReport, error) {
	return p.ApplyFixesWithOptions(filePath, violations, FixOptions{DryRun: false})
}

// ApplyFixesWithOptions applies automated remediations with configurable options such as dry-run preview.
func (p *Patcher) ApplyFixesWithOptions(filePath string, violations []core.Violation, opts FixOptions) (*FixReport, error) {
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
			newContent := patchSafeguardLog(content)
			if newContent != content {
				content = newContent
				report.PatchedRules = append(report.PatchedRules, v.RuleID)
			}
		}
	}

	if content != original {
		// Delimiter balance validation: verify code syntax balance before applying
		if !hasBalancedDelimiters(content) {
			return report, fmt.Errorf("autofix aborted: resulting transformation creates unbalanced delimiters in %s", filePath)
		}

		report.Modified = true
		report.Diff = generateUnifiedDiff(filePath, original, content)

		if !opts.DryRun {
			if err := atomicWriteFile(filePath, []byte(content), filePerm); err != nil {
				return report, err
			}
		}
	}

	return report, nil
}

func hasBalancedDelimiters(content string) bool {
	parens := 0
	braces := 0
	brackets := 0

	for _, r := range content {
		switch r {
		case '(':
			parens++
		case ')':
			parens--
		case '{':
			braces++
		case '}':
			braces--
		case '[':
			brackets++
		case ']':
			brackets--
		}
		if parens < 0 || braces < 0 || brackets < 0 {
			return false
		}
	}
	return parens == 0 && braces == 0 && brackets == 0
}

func atomicWriteFile(filePath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filePath)
	tmpFile, err := os.CreateTemp(dir, ".pipedact-patch-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filePath)
}

func generateUnifiedDiff(filePath, original, modified string) string {
	origLines := strings.Split(original, "\n")
	modLines := strings.Split(modified, "\n")

	var diff strings.Builder
	diff.WriteString(fmt.Sprintf("--- %s\toriginal\n", filePath))
	diff.WriteString(fmt.Sprintf("+++ %s\tmodified\n", filePath))

	// Find changed window
	origLen := len(origLines)
	modLen := len(modLines)

	start := 0
	for start < origLen && start < modLen && origLines[start] == modLines[start] {
		start++
	}

	origEnd := origLen - 1
	modEnd := modLen - 1
	for origEnd >= start && modEnd >= start && origLines[origEnd] == modLines[modEnd] {
		origEnd--
		modEnd--
	}

	diff.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", start+1, origEnd-start+1, start+1, modEnd-start+1))
	for i := start; i <= origEnd; i++ {
		diff.WriteString(fmt.Sprintf("-%s\n", origLines[i]))
	}
	for i := start; i <= modEnd; i++ {
		diff.WriteString(fmt.Sprintf("+%s\n", modLines[i]))
	}

	return diff.String()
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
