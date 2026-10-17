package luhn

import (
	"regexp"
	"strings"
)

var sinPattern = regexp.MustCompile(`\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b`)

// CleanSIN strips whitespace and dashes from a candidate string.
func CleanSIN(input string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, input)
}

// IsValidCanadianSIN verifies whether a string is a valid 9-digit Canadian
// Social Insurance Number using the federal mod-10 Luhn algorithm.
func IsValidCanadianSIN(sinStr string) bool {
	clean := CleanSIN(sinStr)
	if len(clean) != 9 {
		return false
	}

	sum := 0
	for i := 0; i < 9; i++ {
		digit := int(clean[i] - '0')
		if i%2 != 0 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}

	return sum%10 == 0
}

// FindCandidateSINs extracts all substrings matching Canadian SIN formatting (with or without dashes/spaces).
func FindCandidateSINs(content string) []string {
	matches := sinPattern.FindAllString(content, -1)
	var candidates []string
	for _, m := range matches {
		cleaned := CleanSIN(m)
		if len(cleaned) == 9 {
			candidates = append(candidates, m)
		}
	}
	return candidates
}

// FormatSIN formats a 9-digit string into the standard XXX-XXX-XXX format.
func FormatSIN(clean string) string {
	if len(clean) != 9 {
		return clean
	}
	return clean[:3] + "-" + clean[3:6] + "-" + clean[6:]
}
