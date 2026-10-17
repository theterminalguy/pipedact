package rules

import (
	"regexp"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
)

// ============================================================================
// SOC 2 CC6.1 / CC6.6: Hardcoded Secrets
// ============================================================================

type RuleHardcodedSecret struct{}

func (r *RuleHardcodedSecret) ID() string             { return "SOC2-CC6-HARDCODED-SECRET" }
func (r *RuleHardcodedSecret) PrincipleID() int       { return 7 }
func (r *RuleHardcodedSecret) Principle() string     { return "SOC 2 CC6.1 / Safeguards" }
func (r *RuleHardcodedSecret) Severity() core.Severity { return core.SeverityCritical }
func (r *RuleHardcodedSecret) Description() string {
	return "Hardcoded credential, private key, or API secret detected in source code."
}
func (r *RuleHardcodedSecret) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkSOC2:     "CC6.1, CC6.6",
		core.FrameworkPIPEDA:   "Clause 4.7",
		core.FrameworkISO27701: "Clause 7.2.8",
		core.FrameworkLaw25:    "Section 10",
	}
}

var secretPattern = regexp.MustCompile(`(?i)(api_?key|jwt_?secret|auth_?token|db_?password)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{16,}["']`)

func (r *RuleHardcodedSecret) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if secretPattern.MatchString(line) && !strings.Contains(line, "process.env") && !strings.Contains(line, "os.Getenv") {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Store credentials in environment variables or a secret vault (AWS Secrets Manager, Vault, GCP Secret Manager).",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// SOC 2 CC6.6 / CC6.7: Insecure Cookies
// ============================================================================

type RuleInsecureCookie struct{}

func (r *RuleInsecureCookie) ID() string             { return "SOC2-CC6-INSECURE-COOKIE" }
func (r *RuleInsecureCookie) PrincipleID() int       { return 7 }
func (r *RuleInsecureCookie) Principle() string     { return "SOC 2 CC6.7 / Safeguards" }
func (r *RuleInsecureCookie) Severity() core.Severity { return core.SeverityHigh }
func (r *RuleInsecureCookie) Description() string {
	return "HTTP cookie emitted without 'secure: true' or 'httpOnly: true' transmission safeguards."
}
func (r *RuleInsecureCookie) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkSOC2:     "CC6.6, CC6.7",
		core.FrameworkPIPEDA:   "Clause 4.7",
		core.FrameworkISO27701: "Clause 7.2.8",
		core.FrameworkLaw25:    "Section 10",
	}
}

var cookieCallRegex = regexp.MustCompile(`(?i)(res\.cookie|set_cookie|SetCookie)\(`)

func (r *RuleInsecureCookie) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if cookieCallRegex.MatchString(line) {
			// Check if same line or subsequent lines declare secure: true
			hasSecure := strings.Contains(line, "secure: true") || strings.Contains(line, "secure: true")
			hasInsecure := strings.Contains(line, "secure: false") || !strings.Contains(ctx.Content, "secure: true")

			if hasInsecure && !hasSecure {
				violations = append(violations, core.Violation{
					RuleID:            r.ID(),
					PrincipleID:       r.PrincipleID(),
					Principle:         r.Principle(),
					Severity:          sev,
					FilePath:          ctx.FilePath,
					Line:              i + 1,
					LineText:          trimmed,
					Message:           r.Description(),
					Remediation:       "Set cookie options: { secure: true, httpOnly: true, sameSite: 'strict' }.",
					CanAutoFix:        false,
					FrameworkMappings: r.Frameworks(),
				})
			}
		}
	}
	return violations
}

// ============================================================================
// SOC 2 CC6.6: Weak Cryptography
// ============================================================================

type RuleWeakCrypto struct{}

func (r *RuleWeakCrypto) ID() string             { return "SOC2-CC6-WEAK-CRYPTO" }
func (r *RuleWeakCrypto) PrincipleID() int       { return 7 }
func (r *RuleWeakCrypto) Principle() string     { return "SOC 2 CC6.6 / Cryptography" }
func (r *RuleWeakCrypto) Severity() core.Severity { return core.SeverityHigh }
func (r *RuleWeakCrypto) Description() string {
	return "Deprecated or cryptographically broken hash function (MD5 or SHA1) detected."
}
func (r *RuleWeakCrypto) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkSOC2:     "CC6.6",
		core.FrameworkPIPEDA:   "Clause 4.7",
		core.FrameworkISO27701: "Clause 7.2.8",
		core.FrameworkLaw25:    "Section 10",
	}
}

var weakHashRegex = regexp.MustCompile(`(?i)(createHash\(['"](md5|sha1)['"]\)|md5\.New\(\)|sha1\.New\(\)|hashlib\.(md5|sha1))`)

func (r *RuleWeakCrypto) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if weakHashRegex.MatchString(line) {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Upgrade to SHA-256 (SHA-2), SHA-3, or Argon2/bcrypt for passwords.",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}

// ============================================================================
// SOC 2 CC6.6: Permissive Wildcard CORS
// ============================================================================

type RuleWildcardCORS struct{}

func (r *RuleWildcardCORS) ID() string             { return "SOC2-CC6-WILDCARD-CORS" }
func (r *RuleWildcardCORS) PrincipleID() int       { return 7 }
func (r *RuleWildcardCORS) Principle() string     { return "SOC 2 CC6.6 / Boundary" }
func (r *RuleWildcardCORS) Severity() core.Severity { return core.SeverityMedium }
func (r *RuleWildcardCORS) Description() string {
	return "Permissive wildcard Access-Control-Allow-Origin ('*') configured on API endpoints."
}
func (r *RuleWildcardCORS) Frameworks() map[core.Framework]string {
	return map[core.Framework]string{
		core.FrameworkSOC2:     "CC6.6",
		core.FrameworkPIPEDA:   "Clause 4.7",
		core.FrameworkISO27701: "Clause 7.2.8",
		core.FrameworkLaw25:    "Section 10",
	}
}

var wildcardCORSRegex = regexp.MustCompile(`(?i)(origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"])`)

func (r *RuleWildcardCORS) Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation {
	var violations []core.Violation
	sev, enabled := EffectiveSeverity(r, cfg)
	if !enabled {
		return nil
	}

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if wildcardCORSRegex.MatchString(line) {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          trimmed,
				Message:           r.Description(),
				Remediation:       "Restrict CORS origin to approved explicit domains: origin: ['https://app.example.com'].",
				CanAutoFix:        false,
				FrameworkMappings: r.Frameworks(),
			})
		}
	}
	return violations
}
