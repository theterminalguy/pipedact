package reporters

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/theterminalguy/pipedact/pkg/core"
)

func mockResult() *core.AuditResult {
	principles := core.GetSchedule1Principles()
	principleMap := make(map[int]*core.PrincipleStatus)
	for _, p := range principles {
		principleMap[p.ID] = &core.PrincipleStatus{
			Principle:  p,
			Passing:    p.ID != 7,
			Violations: []core.Violation{},
		}
	}

	violations := []core.Violation{
		{
			RuleID:      "PIPEDA-7-SAFEGUARD-LOG",
			PrincipleID: 7,
			Principle:   "Principle 7: Safeguards",
			Severity:    core.SeverityHigh,
			FilePath:    "src/auth.ts",
			Line:        10,
			LineText:    "logger.info(email)",
			Message:     "PII in log sink",
			Remediation: "Mask identifier",
			CanAutoFix:  true,
		},
	}

	principleMap[7].Violations = violations

	return &core.AuditResult{
		ScannedFiles:    1,
		ScannedLines:    50,
		ScannedBytes:    1024,
		Duration:        10 * time.Millisecond,
		Violations:      violations,
		PrincipleStatus: principleMap,
		ComplianceScore: 80,
		ScoreLabel:      "Substantial Compliance",
		Passed:          false,
	}
}

func TestGenerateSARIF(t *testing.T) {
	result := mockResult()
	sarifBytes, err := GenerateSARIF(result)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(sarifBytes, &parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if parsed["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %v", parsed["version"])
	}
}

func TestGenerateJSON(t *testing.T) {
	result := mockResult()
	jsonBytes, err := GenerateJSON(result)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestGenerateMarkdownDossier(t *testing.T) {
	result := mockResult()
	md := GenerateMarkdownDossier(result)
	if !strings.Contains(md, "OPC PIPEDA Schedule 1 Self-Assessment Compliance Dossier") {
		t.Errorf("expected markdown header")
	}
	if !strings.Contains(md, "Compliance Score:** 80%") {
		t.Error("expected 80% compliance score")
	}
}

func TestGenerateHTML(t *testing.T) {
	result := mockResult()
	htmlDoc := GenerateHTML(result)
	if !strings.Contains(htmlDoc, "<!DOCTYPE html>") {
		t.Errorf("expected valid HTML doctype")
	}
	if !strings.Contains(htmlDoc, "80%") {
		t.Error("expected 80% score in HTML")
	}
}
