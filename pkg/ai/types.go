package ai

import (
	"context"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// AnalysisRequest carries context and violations to the AI provider.
type AnalysisRequest struct {
	FilesCount      int
	Violations      []core.Violation
	FileContexts    []*core.FileContext
	ComplianceScore int
	ScoreLabel      string
}

// SemanticRisk represents an AI-identified privacy vulnerability.
type SemanticRisk struct {
	Principle   string   `json:"principle"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	StatutoryRef string  `json:"statutoryRef"`
	Remedy      string   `json:"remedy"`
}

// AnalysisResponse holds synthesized AI audit results.
type AnalysisResponse struct {
	ProviderUsed       string         `json:"providerUsed"`
	ModelUsed          string         `json:"modelUsed"`
	ExecutiveSummary   string         `json:"executiveSummary"`
	QuasiIdentifierRisk string         `json:"quasiIdentifierRisk"`
	PurposeAlignment   string         `json:"purposeAlignment"`
	CrossBorderRisk    string         `json:"crossBorderRisk"`
	SemanticRisks      []SemanticRisk `json:"semanticRisks"`
	RefactoringAdvice  string         `json:"refactoringAdvice"`
}

// ExplanationResponse holds in-depth statutory explanation for a rule or violation.
type ExplanationResponse struct {
	RuleID         string `json:"ruleId"`
	Principle      string `json:"principle"`
	Statute        string `json:"statute"`
	LegalSummary   string `json:"legalSummary"`
	OPCPrecedent   string `json:"opcPrecedent"`
	VulnerableCode string `json:"vulnerableCode"`
	CompliantCode  string `json:"compliantCode"`
}

// Provider defines the interface for an AI privacy analysis engine.
type Provider interface {
	Name() string
	IsAvailable() bool
	Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error)
	Explain(ctx context.Context, ruleID string, codeSnippet string) (*ExplanationResponse, error)
}
