package luhn

import (
	"testing"
)

func TestIsValidCanadianSIN(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"Valid with dashes", "046-454-286", true},
		{"Valid with spaces", "046 454 286", true},
		{"Valid raw digits", "046454286", true},
		{"Invalid check digit", "046-454-287", false},
		{"Too short", "046-454-28", false},
		{"Too long", "046-454-2861", false},
		{"Non-numeric", "046-ABC-286", false},
		{"All zeros", "000-000-000", true}, // mathematically valid Luhn
		{"Standard test SIN", "123-456-782", true}, // 1 + 4 + 3 + 8 + 5 + 3 + 7 + 7 + 2 = 40 (valid)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidCanadianSIN(tt.input)
			if got != tt.valid {
				t.Errorf("IsValidCanadianSIN(%q) = %v, expected %v", tt.input, got, tt.valid)
			}
		})
	}
}

func TestFindCandidateSINs(t *testing.T) {
	text := `logger.info("User registered with SIN: 046-454-286 and backup 123 456 782");`
	candidates := FindCandidateSINs(text)
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidate SINs, got %d", len(candidates))
	}
	if candidates[0] != "046-454-286" || candidates[1] != "123 456 782" {
		t.Errorf("unexpected candidates: %v", candidates)
	}
}
