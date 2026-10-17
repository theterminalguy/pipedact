package core

import "strings"

// Severity represents the impact level of a privacy compliance finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ParseSeverity parses a string into a Severity constant.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Level returns a numeric ranking for comparison (higher = more severe).
func (s Severity) Level() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// String returns string representation of Severity.
func (s Severity) String() string {
	return string(s)
}

// Confidence indicates analytical certainty for a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// AssessmentStatus defines audit evaluation outcomes across statutory principles and security criteria.
type AssessmentStatus string

const (
	StatusPass          AssessmentStatus = "PASS"
	StatusFail          AssessmentStatus = "FAIL"
	StatusNotAssessed   AssessmentStatus = "NOT_ASSESSED"
	StatusNotApplicable AssessmentStatus = "NOT_APPLICABLE"
)

// Violation represents a statutory or technical finding against PIPEDA Schedule 1, SOC 2, or ISO 27701.
type Violation struct {
	RuleID            string               `json:"ruleId"`
	PrincipleID       int                  `json:"principleId"`
	Principle         string               `json:"principle"`
	Severity          Severity             `json:"severity"`
	Confidence        Confidence           `json:"confidence,omitempty"`
	FilePath          string               `json:"filePath"`
	Line              int                  `json:"line"`
	Column            int                  `json:"column,omitempty"`
	LineText          string               `json:"lineText"`
	Message           string               `json:"message"`
	Remediation       string               `json:"remediation"`
	CanAutoFix        bool                 `json:"canAutoFix"`
	FrameworkMappings map[Framework]string `json:"frameworkMappings,omitempty"`
}
