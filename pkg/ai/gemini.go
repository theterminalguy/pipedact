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

type GeminiProvider struct {
	APIKey string
	Model  string
	client *http.Client
}

func NewGeminiProvider(apiKey, model string) *GeminiProvider {
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("GOOGLE_API_KEY")
		}
	}
	if model == "" {
		model = "gemini-2.5-flash"
	}
	return &GeminiProvider{
		APIKey: apiKey,
		Model:  model,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *GeminiProvider) Name() string {
	return "Google Gemini (" + g.Model + ")"
}

func (g *GeminiProvider) IsAvailable() bool {
	return g.APIKey != ""
}

type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (g *GeminiProvider) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("gemini API key not configured")
	}

	prompt := fmt.Sprintf(`You are an expert Canadian Privacy Law Auditor specializing in PIPEDA (Personal Information Protection and Electronic Documents Act), the 10 Fair Information Principles (Schedule 1), and Bill C-27.

Audit Context:
- Files Scanned: %d
- Violations Found: %d
- Static Score: %d%% (%s)

Violations:
%s

Analyze this codebase for:
1. Semantic purpose justification (Principle 4: Data Minimization vs business scope)
2. Quasi-identifier re-identification risks in logs or schemas (Principle 7)
3. Cross-border transfer risks (Clause 4.1.3 & Quebec Law 25)
4. Prioritized refactoring recommendations

Output your analysis in clear, concise structured markdown.`,
		req.FilesCount, len(req.Violations), req.ComplianceScore, req.ScoreLabel, formatViolationsForPrompt(req.Violations))

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", g.Model, g.APIKey)
	payload := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := g.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("gemini API error (status %d): %s", res.StatusCode, string(respBody))
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(res.Body).Decode(&geminiResp); err != nil {
		return nil, err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty response from Gemini")
	}

	output := geminiResp.Candidates[0].Content.Parts[0].Text

	return &AnalysisResponse{
		ProviderUsed:       g.Name(),
		ModelUsed:          g.Model,
		ExecutiveSummary:   output,
		QuasiIdentifierRisk: "Analyzed by " + g.Name(),
		PurposeAlignment:   "Evaluated against PIPEDA Schedule 1",
	}, nil
}

func (g *GeminiProvider) Explain(ctx context.Context, ruleID string, codeSnippet string) (*ExplanationResponse, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("gemini API key not configured")
	}

	prompt := fmt.Sprintf(`Explain the statutory PIPEDA legal basis, OPC investigation precedents, and technical remedy for rule %s.
Code snippet:
%s

Provide:
1. Legal Statutory Summary under PIPEDA Schedule 1
2. Relevant OPC Finding Precedents
3. Compliant Code Refactoring Example`, ruleID, codeSnippet)

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", g.Model, g.APIKey)
	payload := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := g.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("gemini API error: %s", string(respBody))
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(res.Body).Decode(&geminiResp); err != nil {
		return nil, err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty response from Gemini")
	}

	text := geminiResp.Candidates[0].Content.Parts[0].Text
	return &ExplanationResponse{
		RuleID:       ruleID,
		LegalSummary: text,
	}, nil
}
