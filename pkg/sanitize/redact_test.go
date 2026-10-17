package sanitize

import (
	"strings"
	"testing"
)

func TestRedactText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		excludes string
	}{
		{
			name:     "Canadian SIN with dashes",
			input:    `const sin = "046-454-286";`,
			contains: `***-***-***`,
			excludes: `046-454-286`,
		},
		{
			name:     "AWS Access Key",
			input:    `const key = "AKIAIOSFODNN7EXAMPLE";`,
			contains: `AKIA[REDACTED_AWS_KEY]`,
			excludes: `AKIAIOSFODNN7EXAMPLE`,
		},
		{
			name:     "Slack Token",
			input:    `const token = "xoxb-123456789012-1234567890123-abcdef123456";`,
			contains: `xox-[REDACTED_SLACK_TOKEN]`,
			excludes: `xoxb-123456789012`,
		},
		{
			name:     "GitHub Token",
			input:    `const gh = "ghp_1234567890abcdef1234567890abcdef123456";`,
			contains: `ghp_[REDACTED_GH_TOKEN]`,
			excludes: `ghp_1234567890`,
		},
		{
			name:     "Secret Assignment",
			input:    `const jwt_secret = "super_secret_signing_key_123456789";`,
			contains: `"[REDACTED_SECRET]"`,
			excludes: `super_secret_signing_key`,
		},
		{
			name:     "Placeholder preserved",
			input:    `const apiKey = "your_api_key_here";`,
			contains: `your_api_key_here`,
			excludes: `[REDACTED_SECRET]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := RedactText(tc.input)
			if !strings.Contains(output, tc.contains) {
				t.Errorf("expected output to contain %q, got: %s", tc.contains, output)
			}
			if strings.Contains(output, tc.excludes) {
				t.Errorf("expected output to NOT contain %q, got: %s", tc.excludes, output)
			}
		})
	}
}
