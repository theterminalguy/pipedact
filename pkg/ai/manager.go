package ai

import (
	"context"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// ResolveProvider determines the best available AI provider based on preference and environment.
func ResolveProvider(preference string) Provider {
	pref := strings.ToLower(strings.TrimSpace(preference))

	switch pref {
	case "gemini", "google":
		p := NewGeminiProvider("", "")
		if p.IsAvailable() {
			return p
		}
	case "openai":
		p := NewOpenAIProvider("", "", "")
		if p.IsAvailable() {
			return p
		}
	case "ollama", "local":
		p := NewOllamaProvider("", "")
		if p.IsAvailable() {
			return p
		}
	case "heuristic", "offline":
		return NewHeuristicReasoner()
	}

	// Auto mode: check available API keys in order of precedence
	gemini := NewGeminiProvider("", "")
	if gemini.IsAvailable() {
		return gemini
	}

	openai := NewOpenAIProvider("", "", "")
	if openai.IsAvailable() {
		return openai
	}

	ollama := NewOllamaProvider("", "")
	if ollama.IsAvailable() {
		return ollama
	}

	// Default fallback to built-in Canadian Statutory Reasoner
	return NewHeuristicReasoner()
}

// RunAIAnalysis executes an AI privacy review of an audit result.
func RunAIAnalysis(ctx context.Context, result *core.AuditResult, provider Provider) (*AnalysisResponse, error) {
	if provider == nil {
		provider = ResolveProvider("auto")
	}

	req := &AnalysisRequest{
		FilesCount:      result.ScannedFiles,
		Violations:      result.Violations,
		ComplianceScore: result.ComplianceScore,
		ScoreLabel:      result.ScoreLabel,
	}

	return provider.Analyze(ctx, req)
}
