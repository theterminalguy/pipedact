package sanitize

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/luhn"
)

var (
	sinRegex        = regexp.MustCompile(`\b\d{3}[-\s]\d{3}[-\s]\d{3}\b`)
	awsKeyRegex     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	slackTokenRegex = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)
	githubTokenRegex = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,}\b`)
	stripeKeyRegex   = regexp.MustCompile(`\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b`)
	jwtRegex        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	bearerRegex     = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9_\-\.]{20,}\b`)
	privateKeyRegex = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----`)
	secretAssignRegex = regexp.MustCompile(`(?i)\b(api_?key|jwt_?secret|auth_?token|db_?password|access_?token|secret_?key|client_?secret|signing_?key)\s*([:=])\s*["']([A-Za-z0-9_\-\.\$\/+=]{16,})["']`)
)

// MaskSIN replaces a SIN with ***-***-XXX (preserving only last 3 digits for verification) or ***-***-***.
func MaskSIN(sin string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(sin, "")
	if len(digits) >= 3 {
		return fmt.Sprintf("***-***-%s", digits[len(digits)-3:])
	}
	return "***-***-***"
}

// RedactText scrubs sensitive tokens, Canadian SINs, credentials, and API secrets from text.
func RedactText(text string) string {
	if text == "" {
		return ""
	}

	// 1. Redact Canadian SINs
	text = sinRegex.ReplaceAllStringFunc(text, func(m string) string {
		return "***-***-***"
	})

	// 2. Redact Known Provider Tokens
	text = awsKeyRegex.ReplaceAllString(text, "AKIA[REDACTED_AWS_KEY]")
	text = slackTokenRegex.ReplaceAllString(text, "xox-[REDACTED_SLACK_TOKEN]")
	text = githubTokenRegex.ReplaceAllString(text, "ghp_[REDACTED_GH_TOKEN]")
	text = stripeKeyRegex.ReplaceAllString(text, "sk_[REDACTED_STRIPE_KEY]")
	text = jwtRegex.ReplaceAllString(text, "eyJ[REDACTED_JWT_PAYLOAD]")
	text = bearerRegex.ReplaceAllString(text, "Bearer [REDACTED_BEARER_TOKEN]")
	text = privateKeyRegex.ReplaceAllString(text, "-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY_DATA]\n-----END PRIVATE KEY-----")

	// 3. Redact Secret variable assignments
	text = secretAssignRegex.ReplaceAllStringFunc(text, func(m string) string {
		sub := secretAssignRegex.FindStringSubmatch(m)
		if len(sub) == 4 {
			val := strings.ToLower(sub[3])
			if strings.Contains(val, "placeholder") || strings.Contains(val, "your_") || strings.Contains(val, "example_") || val == "0000000000000000" {
				return m
			}
			return fmt.Sprintf(`%s %s "[REDACTED_SECRET]"`, sub[1], sub[2])
		}
		return m
	})

	return text
}

// RedactMessage cleans a violation message, masking any raw SINs without altering standard text.
func RedactMessage(msg string) string {
	return sinRegex.ReplaceAllStringFunc(msg, func(m string) string {
		if luhn.IsValidCanadianSIN(m) {
			return MaskSIN(m)
		}
		return "***-***-***"
	})
}
