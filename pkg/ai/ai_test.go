package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/theterminalguy/pipedact/pkg/core"
)

func TestHeuristicReasonerAnalyze(t *testing.T) {
	reasoner := NewHeuristicReasoner()
	req := &AnalysisRequest{
		FilesCount:      5,
		ComplianceScore: 50,
		ScoreLabel:      "High Legal Risk",
		Violations: []core.Violation{
			{
				RuleID:      "PIPEDA-7-SAFEGUARD-LOG",
				PrincipleID: 7,
				Principle:   "Principle 7: Safeguards",
				Severity:    core.SeverityHigh,
				Message:     "PII in log sink",
			},
			{
				RuleID:      "PIPEDA-4-OVER-COLLECTION",
				PrincipleID: 4,
				Principle:   "Principle 4: Limiting Collection",
				Severity:    core.SeverityHigh,
				Message:     "Health card collected",
			},
		},
	}

	res, err := reasoner.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(res.SemanticRisks) == 0 {
		t.Errorf("expected semantic risks to be identified")
	}

	if !strings.Contains(res.ExecutiveSummary, "PIPEDA") {
		t.Errorf("expected PIPEDA in executive summary")
	}
}

func TestHeuristicReasonerExplain(t *testing.T) {
	reasoner := NewHeuristicReasoner()
	exp, err := reasoner.Explain(context.Background(), "PIPEDA-7-SAFEGUARD-LOG", "")
	if err != nil {
		t.Fatalf("Explain failed: %v", err)
	}

	if exp.Principle != "Principle 7: Safeguards" {
		t.Errorf("expected Principle 7, got %s", exp.Principle)
	}

	if !strings.Contains(exp.LegalSummary, "Clause 4.7") {
		t.Errorf("expected Clause 4.7 in legal summary")
	}

	if !strings.Contains(exp.OPCPrecedent, "Desjardins") {
		t.Errorf("expected Desjardins precedent mention")
	}
}

func TestResolveProvider(t *testing.T) {
	p := ResolveProvider("heuristic")
	if p.Name() != "pipedact Statutory Heuristic Reasoner (Offline/Zero-Egress)" {
		t.Errorf("unexpected provider: %s", p.Name())
	}

	pAuto := ResolveProvider("auto")
	if pAuto == nil {
		t.Errorf("expected provider to be resolved in auto mode")
	}
}
