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

var (
	awsKeyRegex      = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	slackTokenRegex  = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)
	privateKeyRegex  = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----`)
	githubTokenRegex = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,}\b`)

	secretKeyNameRegex = regexp.MustCompile(`(?i)\b(api_?key|jwt_?secret|auth_?token|db_?password|access_?token|secret_?key|client_?secret|signing_?key)\b`)
	quotedStringRegex  = regexp.MustCompile(`["']([A-Za-z0-9_\-\.\$\/+=]{16,})["']`)
)

func redactSecrets(line string) string {
	redacted := awsKeyRegex.ReplaceAllString(line, "AKIA[REDACTED_AWS_KEY]")
	redacted = slackTokenRegex.ReplaceAllString(redacted, "xox-[REDACTED_SLACK_TOKEN]")
	redacted = githubTokenRegex.ReplaceAllString(redacted, "ghp_[REDACTED_GH_TOKEN]")
	if secretKeyNameRegex.MatchString(redacted) {
		redacted = quotedStringRegex.ReplaceAllString(redacted, `"[REDACTED_SECRET]"`)
	}
	return redacted
}

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

		isSecretFound := false

		// Check known provider-specific patterns
		if awsKeyRegex.MatchString(line) || slackTokenRegex.MatchString(line) ||
			privateKeyRegex.MatchString(line) || githubTokenRegex.MatchString(line) {
			isSecretFound = true
		} else if secretKeyNameRegex.MatchString(line) {
			// Check if literal high-entropy secret string is assigned
			matches := quotedStringRegex.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				val := strings.ToLower(m[1])
				// Ignore explicit placeholder values
				if strings.Contains(val, "placeholder") || strings.Contains(val, "your_") ||
					strings.Contains(val, "example_") || val == "0000000000000000" {
					continue
				}
				isSecretFound = true
				break
			}
		}

		if isSecretFound {
			violations = append(violations, core.Violation{
				RuleID:            r.ID(),
				PrincipleID:       r.PrincipleID(),
				Principle:         r.Principle(),
				Severity:          sev,
				FilePath:          ctx.FilePath,
				Line:              i + 1,
				LineText:          redactSecrets(trimmed),
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

	for i := 0; i < len(ctx.Lines); i++ {
		line := ctx.Lines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if cookieCallRegex.MatchString(line) {
			// Extract arguments block starting from this line up to matching closing parenthesis or 15 lines
			var blockLines []string
			parenDepth := 0
			endLine := i

			for j := i; j < len(ctx.Lines) && j < i+15; j++ {
				l := ctx.Lines[j]
				blockLines = append(blockLines, l)
				parenDepth += strings.Count(l, "(") - strings.Count(l, ")")
				endLine = j
				if parenDepth <= 0 && j > i {
					break
				}
				if strings.Contains(l, ");") {
					break
				}
			}

			blockText := strings.ToLower(strings.Join(blockLines, " "))

			hasSecureFalse := strings.Contains(blockText, "secure: false") || strings.Contains(blockText, "secure=false")
			hasSecureTrue := strings.Contains(blockText, "secure: true") || strings.Contains(blockText, "secure=true")
			secureInsecure := hasSecureFalse || !hasSecureTrue

			hasHttpOnlyFalse := strings.Contains(blockText, "httponly: false") || strings.Contains(blockText, "httponly=false")
			hasHttpOnlyTrue := strings.Contains(blockText, "httponly: true") || strings.Contains(blockText, "httponly=true")
			httpOnlyInsecure := hasHttpOnlyFalse || !hasHttpOnlyTrue

			if secureInsecure || httpOnlyInsecure {
				var reason string
				if secureInsecure && httpOnlyInsecure {
					reason = "HTTP cookie set without 'secure: true' and 'httpOnly: true' transmission safeguards."
				} else if secureInsecure {
					reason = "HTTP cookie set without 'secure: true' transmission safeguard (cleartext transport risk)."
				} else {
					reason = "HTTP cookie set without 'httpOnly: true' safeguard (XSS token theft risk)."
				}

				violations = append(violations, core.Violation{
					RuleID:            r.ID(),
					PrincipleID:       r.PrincipleID(),
					Principle:         r.Principle(),
					Severity:          sev,
					FilePath:          ctx.FilePath,
					Line:              i + 1,
					LineText:          trimmed,
					Message:           reason,
					Remediation:       "Set cookie options: { secure: true, httpOnly: true, sameSite: 'strict' }.",
					CanAutoFix:        false,
					FrameworkMappings: r.Frameworks(),
				})
			}

			if endLine > i {
				i = endLine
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
