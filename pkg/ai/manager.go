package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// ResolveProvider determines the best available AI provider based on preference and environment.
func ResolveProvider(preference string) (Provider, error) {
	pref := strings.ToLower(strings.TrimSpace(preference))

	switch pref {
	case "gemini", "google":
		p := NewGeminiProvider("", "")
		if !p.IsAvailable() {
			return nil, fmt.Errorf("gemini provider requested but GEMINI_API_KEY is not set")
		}
		return p, nil
	case "openai":
		p := NewOpenAIProvider("", "", "")
		if !p.IsAvailable() {
			return nil, fmt.Errorf("openai provider requested but OPENAI_API_KEY is not set")
		}
		return p, nil
	case "ollama", "local":
		p := NewOllamaProvider("", "")
		if !p.IsAvailable() {
			return nil, fmt.Errorf("ollama provider requested but local endpoint is not available or reachable")
		}
		return p, nil
	case "heuristic", "offline":
		return NewHeuristicReasoner(), nil
	case "auto", "":
		// Auto mode: check available API keys in order of precedence
		gemini := NewGeminiProvider("", "")
		if gemini.IsAvailable() {
			return gemini, nil
		}

		openai := NewOpenAIProvider("", "", "")
		if openai.IsAvailable() {
			return openai, nil
		}

		ollama := NewOllamaProvider("", "")
		if ollama.IsAvailable() {
			return ollama, nil
		}

		// Default fallback to built-in Canadian Statutory Reasoner
		return NewHeuristicReasoner(), nil
	default:
		return nil, fmt.Errorf("unknown AI provider: %q (supported: auto, gemini, openai, ollama, heuristic)", preference)
	}
}

// RunAIAnalysis executes an AI privacy review of an audit result.
func RunAIAnalysis(ctx context.Context, result *core.AuditResult, provider Provider) (*AnalysisResponse, error) {
	if provider == nil {
		var err error
		provider, err = ResolveProvider("auto")
		if err != nil {
			return nil, err
		}
	}

	req := &AnalysisRequest{
		FilesCount:      result.ScannedFiles,
		Violations:      result.Violations,
		ComplianceScore: result.ComplianceScore,
		ScoreLabel:      result.ScoreLabel,
	}

	return provider.Analyze(ctx, req)
}
