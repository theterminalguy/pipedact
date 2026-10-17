package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type OllamaProvider struct {
	Host   string
	Model  string
	client *http.Client
}

func NewOllamaProvider(host, model string) *OllamaProvider {
	if host == "" {
		host = os.Getenv("OLLAMA_HOST")
		if host == "" {
			host = "http://localhost:11434"
		}
	}
	if model == "" {
		model = os.Getenv("OLLAMA_MODEL")
		if model == "" {
			model = "llama3"
		}
	}
	return &OllamaProvider{
		Host:   host,
		Model:  model,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

func (ol *OllamaProvider) Name() string {
	return "Ollama Local AI (" + ol.Model + ")"
}

func (ol *OllamaProvider) IsAvailable() bool {
	// Probe host with short timeout
	client := http.Client{Timeout: 1 * time.Second}
	res, err := client.Get(ol.Host + "/api/tags")
	if err != nil || res.StatusCode != http.StatusOK {
		return false
	}
	res.Body.Close()
	return true
}

type ollamaGenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaGenerateResponse struct {
	Response string `json:"response"`
}

func (ol *OllamaProvider) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	prompt := fmt.Sprintf(`[INST] You are an expert Canadian Privacy Law Auditor specializing in PIPEDA Schedule 1.
Files: %d, Violations: %d, Score: %d%% (%s)
Violations:
%s
Analyze for: 1. Purpose justification, 2. Quasi-identifier linkage risk, 3. Cross-border risks, 4. Remediations. [/INST]`,
		req.FilesCount, len(req.Violations), req.ComplianceScore, req.ScoreLabel, formatViolationsForPrompt(req.Violations))

	payload := ollamaGenerateRequest{
		Model:  ol.Model,
		Prompt: prompt,
		Stream: false,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ol.Host+"/api/generate", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := ol.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("ollama error (status %d): %s", res.StatusCode, string(body))
	}

	var ollamaResp ollamaGenerateResponse
	if err := json.NewDecoder(res.Body).Decode(&ollamaResp); err != nil {
		return nil, err
	}

	return &AnalysisResponse{
		ProviderUsed:     ol.Name(),
		ModelUsed:        ol.Model,
		ExecutiveSummary: ollamaResp.Response,
	}, nil
}

func (ol *OllamaProvider) Explain(ctx context.Context, ruleID string, codeSnippet string) (*ExplanationResponse, error) {
	prompt := fmt.Sprintf("[INST] Explain PIPEDA Schedule 1 legal basis and OPC precedent for %s. Code: %s [/INST]", ruleID, codeSnippet)
	payload := ollamaGenerateRequest{
		Model:  ol.Model,
		Prompt: prompt,
		Stream: false,
	}
	bodyBytes, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", ol.Host+"/api/generate", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	res, err := ol.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var resp ollamaGenerateResponse
	json.NewDecoder(res.Body).Decode(&resp)
	return &ExplanationResponse{
		RuleID:       ruleID,
		LegalSummary: resp.Response,
	}, nil
}
