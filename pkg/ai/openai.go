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

type OpenAIProvider struct {
	APIKey  string
	Model   string
	BaseURL string
	client  *http.Client
}

func NewOpenAIProvider(apiKey, model, baseURL string) *OpenAIProvider {
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{
		APIKey:  apiKey,
		Model:   model,
		BaseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (o *OpenAIProvider) Name() string {
	return "OpenAI (" + o.Model + ")"
}

func (o *OpenAIProvider) IsAvailable() bool {
	return o.APIKey != ""
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float32         `json:"temperature"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (o *OpenAIProvider) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	if !o.IsAvailable() {
		return nil, fmt.Errorf("openAI API key not configured")
	}

	prompt := fmt.Sprintf(`You are a statutory privacy engineer and regulatory auditor specializing in Canadian PIPEDA Schedule 1.
Context:
- Scanned %d files
- Found %d static violations
- Score: %d%% (%s)

Violations:
%s

Perform semantic PIPEDA analysis:
1. Data Minimization & Statutory Necessity (Principle 4)
2. Quasi-Identifier Linkage Risk in logs/schemas (Principle 7)
3. Cross-Border Data Flow Risk (Clause 4.1.3 & Quebec Law 25)
4. Prioritized Architectural Remediation Strategy`,
		req.FilesCount, len(req.Violations), req.ComplianceScore, req.ScoreLabel, formatViolationsForPrompt(req.Violations))

	payload := openAIRequest{
		Model: o.Model,
		Messages: []openAIMessage{
			{Role: "system", Content: "You are an expert Canadian Federal Privacy Law Auditor for PIPEDA."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.BaseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)

	res, err := o.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("openAI API error (status %d): %s", res.StatusCode, string(respBody))
	}

	var openAIResp openAIResponse
	if err := json.NewDecoder(res.Body).Decode(&openAIResp); err != nil {
		return nil, err
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from OpenAI")
	}

	text := openAIResp.Choices[0].Message.Content

	return &AnalysisResponse{
		ProviderUsed:       o.Name(),
		ModelUsed:          o.Model,
		ExecutiveSummary:   text,
		QuasiIdentifierRisk: "Analyzed by " + o.Name(),
		PurposeAlignment:   "Evaluated against PIPEDA Schedule 1",
	}, nil
}

func (o *OpenAIProvider) Explain(ctx context.Context, ruleID string, codeSnippet string) (*ExplanationResponse, error) {
	if !o.IsAvailable() {
		return nil, fmt.Errorf("openAI API key not configured")
	}

	prompt := fmt.Sprintf("Explain the PIPEDA Schedule 1 statutory basis, OPC precedents, and compliant refactoring for %s.\nCode:\n%s", ruleID, codeSnippet)
	payload := openAIRequest{
		Model: o.Model,
		Messages: []openAIMessage{
			{Role: "system", Content: "You are an expert in Canadian privacy law."},
			{Role: "user", Content: prompt},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.BaseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)

	res, err := o.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var openAIResp openAIResponse
	if err := json.NewDecoder(res.Body).Decode(&openAIResp); err != nil {
		return nil, err
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	return &ExplanationResponse{
		RuleID:       ruleID,
		LegalSummary: openAIResp.Choices[0].Message.Content,
	}, nil
}
