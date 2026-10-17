package core

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/sanitize"
)

// SkipReason represents the structural reason a file was skipped from scanning.
type SkipReason string

const (
	SkipReasonIgnored    SkipReason = "IGNORED"
	SkipReasonOversized  SkipReason = "OVERSIZED"
	SkipReasonBinary     SkipReason = "BINARY"
	SkipReasonUnreadable SkipReason = "UNREADABLE"
)

// SkippedFile documents a file that was omitted from inspection.
type SkippedFile struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
	Detail string     `json:"detail,omitempty"`
}

// FailedFile documents an explicitly encountered read or file inspection failure.
type FailedFile struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// PrincipleStatus tracks compliance for a single statutory principle.
type PrincipleStatus struct {
	Principle   Principle        `json:"principle"`
	Status      AssessmentStatus `json:"status"`
	Passing     bool             `json:"passing"`
	Violations  []Violation      `json:"violations"`
	ScoreImpact int              `json:"scoreImpact"`
}

// SOC2Status tracks compliance for a single SOC 2 Trust Services Criterion.
type SOC2Status struct {
	Criteria   SOC2Criteria     `json:"criteria"`
	Status     AssessmentStatus `json:"status"`
	Passing    bool             `json:"passing"`
	Violations []Violation      `json:"violations"`
}

// AuditResult encapsulates the full diagnostic outcome of a scan.
type AuditResult struct {
	DiscoveredFiles int                      `json:"discoveredFiles"`
	ScannedFiles    int                      `json:"scannedFiles"`
	ScannedLines    int                      `json:"scannedLines"`
	ScannedBytes    int64                    `json:"scannedBytes"`
	Duration        time.Duration            `json:"duration"`
	Violations      []Violation              `json:"violations"`
	SkippedFiles    []SkippedFile            `json:"skippedFiles,omitempty"`
	FailedFiles     []FailedFile             `json:"failedFiles,omitempty"`
	IsComplete      bool                     `json:"isComplete"`
	PrincipleStatus map[int]*PrincipleStatus `json:"principleStatus"`
	ComplianceScore int                      `json:"complianceScore"`
	ScoreLabel      string                   `json:"scoreLabel"`
	Passed          bool                     `json:"passed"`
	Framework       Framework                `json:"framework"`
	SOC2Status      map[string]*SOC2Status   `json:"soc2Status"`
	SOC2Score       int                      `json:"soc2Score"`
}

// Engine coordinates multi-threaded scanning of targets against rules.
type Engine struct {
	Config          *config.Config
	Rules           []RuleInspector
	TargetFramework Framework
	maxBytes        int64
}

// RuleInspector is an interface implemented by rules for scanning.
type RuleInspector interface {
	ID() string
	PrincipleID() int
	Principle() string
	Severity() Severity
	Description() string
	Frameworks() map[Framework]string
	Inspect(ctx *FileContext, cfg *config.Config) []Violation
}

// NewEngine creates an Engine instance.
func NewEngine(cfg *config.Config, rules []RuleInspector) *Engine {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Engine{
		Config:          cfg,
		Rules:           rules,
		TargetFramework: FrameworkPIPEDA,
		maxBytes:        10 * 1024 * 1024, // 10MB default file limit
	}
}

// SetMaxBytes overrides the maximum file size limit for scanning.
func (e *Engine) SetMaxBytes(bytes int64) {
	if bytes > 0 {
		e.maxBytes = bytes
	}
}

// MaxBytes returns the current maximum file size limit.
func (e *Engine) MaxBytes() int64 {
	return e.maxBytes
}

// SetFramework sets the compliance framework to scan against.
func (e *Engine) SetFramework(fw Framework) {
	e.TargetFramework = fw
}

// Scan targets synchronously using default background context.
func (e *Engine) Scan(targets []string) (*AuditResult, error) {
	return e.ScanContext(context.Background(), targets)
}

// ScanContext scans targets against rules with context cancellation support.
func (e *Engine) ScanContext(ctx context.Context, targets []string) (*AuditResult, error) {
	start := time.Now()

	if len(targets) == 0 {
		targets = []string{"."}
	}

	discovered, filesToScan, initialSkipped, err := e.collectFiles(targets)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var allViolations []Violation
	var skippedFiles []SkippedFile
	skippedFiles = append(skippedFiles, initialSkipped...)
	var failedFiles []FailedFile

	totalLines := 0
	totalBytes := int64(0)
	scannedFilesCount := 0

	// Worker pool for concurrent scanning
	workerCount := 8
	if len(filesToScan) < workerCount {
		workerCount = len(filesToScan)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	fileChan := make(chan string, len(filesToScan))
	for _, f := range filesToScan {
		fileChan <- f
	}
	close(fileChan)

	var wg sync.WaitGroup
	var scanErr error

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				select {
				case <-ctx.Done():
					mu.Lock()
					if scanErr == nil {
						scanErr = ctx.Err()
					}
					mu.Unlock()
					return
				default:
				}

				info, err := os.Stat(path)
				if err != nil {
					mu.Lock()
					failedFiles = append(failedFiles, FailedFile{Path: path, Error: err.Error()})
					mu.Unlock()
					continue
				}

				if info.IsDir() {
					continue
				}

				if info.Size() > e.maxBytes {
					mu.Lock()
					skippedFiles = append(skippedFiles, SkippedFile{
						Path:   path,
						Reason: SkipReasonOversized,
						Detail: fmt.Sprintf("file size (%d bytes) exceeds scan limit (%d bytes)", info.Size(), e.maxBytes),
					})
					mu.Unlock()
					continue
				}

				contentBytes, err := os.ReadFile(path)
				if err != nil {
					mu.Lock()
					failedFiles = append(failedFiles, FailedFile{Path: path, Error: err.Error()})
					mu.Unlock()
					continue
				}

				// Check for binary content (null bytes in first 512 bytes)
				checkLen := len(contentBytes)
				if checkLen > 512 {
					checkLen = 512
				}
				if bytes.IndexByte(contentBytes[:checkLen], 0) != -1 {
					mu.Lock()
					skippedFiles = append(skippedFiles, SkippedFile{
						Path:   path,
						Reason: SkipReasonBinary,
						Detail: "binary content detected",
					})
					mu.Unlock()
					continue
				}

				relPath, _ := filepath.Rel(".", path)
				if relPath == "" {
					relPath = path
				}

				fileCtx := NewFileContext(path, relPath, string(contentBytes))

				var fileViolations []Violation
				for _, rule := range e.Rules {
					if e.TargetFramework != "" && e.TargetFramework != FrameworkAll {
						if _, mapped := rule.Frameworks()[e.TargetFramework]; !mapped {
							continue
						}
					}
					v := rule.Inspect(fileCtx, e.Config)
					if len(v) > 0 {
						fileViolations = append(fileViolations, v...)
					}
				}

				mu.Lock()
				scannedFilesCount++
				totalLines += len(fileCtx.Lines)
				totalBytes += info.Size()
				allViolations = append(allViolations, fileViolations...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if scanErr != nil {
		return nil, scanErr
	}

	// Deterministic sorting of findings
	sort.Slice(allViolations, func(i, j int) bool {
		if allViolations[i].FilePath != allViolations[j].FilePath {
			return allViolations[i].FilePath < allViolations[j].FilePath
		}
		if allViolations[i].Line != allViolations[j].Line {
			return allViolations[i].Line < allViolations[j].Line
		}
		return allViolations[i].RuleID < allViolations[j].RuleID
	})

	result := e.calculateResult(allViolations, discovered, scannedFilesCount, totalLines, totalBytes, skippedFiles, failedFiles, time.Since(start))
	return result, nil
}

func (e *Engine) calculateResult(violations []Violation, discoveredCount, filesCount, linesCount int, bytesCount int64, skipped []SkippedFile, failed []FailedFile, duration time.Duration) *AuditResult {
	principles := GetSchedule1Principles()
	principleMap := make(map[int]*PrincipleStatus)

	for _, p := range principles {
		principleMap[p.ID] = &PrincipleStatus{
			Principle:   p,
			Status:      StatusPass,
			Passing:     true,
			Violations:  []Violation{},
			ScoreImpact: 0,
		}
	}

	// Centralized sanitization of all violations
	var sanitizedViolations []Violation
	for _, v := range violations {
		sanitized := v
		sanitized.LineText = sanitize.RedactText(v.LineText)
		sanitized.Message = sanitize.RedactMessage(v.Message)
		sanitizedViolations = append(sanitizedViolations, sanitized)

		if status, exists := principleMap[sanitized.PrincipleID]; exists {
			status.Status = StatusFail
			status.Passing = false
			status.Violations = append(status.Violations, sanitized)
		}
	}

	if filesCount == 0 && len(violations) == 0 {
		for _, status := range principleMap {
			status.Status = StatusNotAssessed
		}
	}

	// Calculate weighted score (0 - 100)
	earned := 0
	totalWeight := 0
	for _, status := range principleMap {
		totalWeight += status.Principle.Weight
		if status.Passing {
			earned += status.Principle.Weight
		}
	}

	score := 0
	if totalWeight > 0 {
		score = int(math.Round((float64(earned) / float64(totalWeight)) * 100.0))
	}

	scoreLabel := "High Technical Risk (Significant Exceptions Detected)"
	if len(sanitizedViolations) == 0 {
		scoreLabel = "Clean Scan (No Rule Violations)"
	} else if score >= 90 {
		scoreLabel = "Low Technical Risk (Minor Exceptions Flagged)"
	} else if score >= 70 {
		scoreLabel = "Moderate Technical Risk (Remediation Recommended)"
	}

	// SOC 2 Trust Services Criteria Status
	soc2Criteria := GetSOC2Criteria()
	soc2Map := make(map[string]*SOC2Status)
	for _, c := range soc2Criteria {
		soc2Map[c.ID] = &SOC2Status{
			Criteria:   c,
			Status:     StatusPass,
			Passing:    true,
			Violations: []Violation{},
		}
	}

	for _, v := range sanitizedViolations {
		if mapping, ok := v.FrameworkMappings[FrameworkSOC2]; ok {
			for critID, status := range soc2Map {
				if strings.Contains(mapping, critID) {
					status.Status = StatusFail
					status.Passing = false
					status.Violations = append(status.Violations, v)
				}
			}
		}
	}

	if filesCount == 0 && len(sanitizedViolations) == 0 {
		for _, status := range soc2Map {
			status.Status = StatusNotAssessed
		}
	}

	soc2Earned := 0
	soc2TotalWeight := 0
	for _, status := range soc2Map {
		soc2TotalWeight += status.Criteria.Weight
		if status.Passing {
			soc2Earned += status.Criteria.Weight
		}
	}
	soc2Score := 0
	if soc2TotalWeight > 0 {
		soc2Score = int(math.Round((float64(soc2Earned) / float64(soc2TotalWeight)) * 100.0))
	}

	fw := e.TargetFramework
	if fw == "" {
		fw = FrameworkPIPEDA
	}

	finalScore := score
	finalLabel := scoreLabel
	if fw == FrameworkSOC2 {
		finalScore = soc2Score
		if len(sanitizedViolations) == 0 {
			finalLabel = "Clean Scan (No SOC 2 Rule Violations)"
		} else if soc2Score >= 90 {
			finalLabel = "Low Technical Risk (Minor Exceptions Flagged)"
		} else if soc2Score >= 70 {
			finalLabel = "Moderate Technical Risk (Exceptions Flagged)"
		} else {
			finalLabel = "High Technical Risk (Significant Exceptions Detected)"
		}
	}

	hasCriticalOrHigh := false
	for _, v := range sanitizedViolations {
		if v.Severity == SeverityCritical || v.Severity == SeverityHigh {
			hasCriticalOrHigh = true
			break
		}
	}

	isComplete := len(failed) == 0

	return &AuditResult{
		DiscoveredFiles: discoveredCount,
		ScannedFiles:    filesCount,
		ScannedLines:    linesCount,
		ScannedBytes:    bytesCount,
		Duration:        duration,
		Violations:      sanitizedViolations,
		SkippedFiles:    skipped,
		FailedFiles:     failed,
		IsComplete:      isComplete,
		PrincipleStatus: principleMap,
		ComplianceScore: finalScore,
		ScoreLabel:      finalLabel,
		Passed:          isComplete && !hasCriticalOrHigh && len(sanitizedViolations) == 0,
		Framework:       fw,
		SOC2Status:      soc2Map,
		SOC2Score:       soc2Score,
	}
}

func (e *Engine) collectFiles(targets []string) (int, []string, []SkippedFile, error) {
	var collected []string
	var skipped []SkippedFile
	visited := make(map[string]bool)
	visitedCanonical := make(map[string]bool)
	discovered := 0

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("target path not found or inaccessible: %w", err)
		}

		if !info.IsDir() {
			discovered++
			abs, _ := filepath.Abs(target)
			if !visited[abs] {
				visited[abs] = true
				if e.isIgnored(target) {
					skipped = append(skipped, SkippedFile{Path: target, Reason: SkipReasonIgnored, Detail: "path matches ignore patterns"})
				} else if !isScannable(target) {
					skipped = append(skipped, SkippedFile{Path: target, Reason: SkipReasonBinary, Detail: "unsupported file extension"})
				} else {
					collected = append(collected, target)
				}
			}
			continue
		}

		err = filepath.Walk(target, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Circular symlink check
			realPath, evalErr := filepath.EvalSymlinks(path)
			if evalErr == nil {
				if visitedCanonical[realPath] {
					return nil
				}
				visitedCanonical[realPath] = true
			}

			// Skip hidden dirs, git, vendor, node_modules
			name := fi.Name()
			if fi.IsDir() {
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "build" || (strings.HasPrefix(name, ".") && name != ".") {
					return filepath.SkipDir
				}
				return nil
			}

			discovered++
			abs, _ := filepath.Abs(path)
			if !visited[abs] {
				visited[abs] = true
				if e.isIgnored(path) {
					skipped = append(skipped, SkippedFile{Path: path, Reason: SkipReasonIgnored, Detail: "matches ignore configuration"})
				} else if isScannable(path) {
					collected = append(collected, path)
				}
			}
			return nil
		})

		if err != nil {
			return 0, nil, nil, err
		}
	}

	return discovered, collected, skipped, nil
}

func (e *Engine) isIgnored(path string) bool {
	norm := filepath.ToSlash(path)
	base := filepath.Base(norm)

	for _, pattern := range e.Config.Ignore {
		pattern = filepath.ToSlash(pattern)

		// Exact match
		if norm == pattern || strings.HasPrefix(norm, strings.TrimPrefix(pattern, "./")) {
			return true
		}

		// Suffix match e.g. **/*_test.go or **/*.spec.ts
		if strings.HasPrefix(pattern, "**/*") {
			suffix := strings.TrimPrefix(pattern, "**/*")
			if strings.HasSuffix(norm, suffix) {
				return true
			}
		}

		// Directory glob like node_modules/** or testdata/**
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			prefix = strings.TrimPrefix(prefix, "**/")
			if strings.HasPrefix(norm, prefix+"/") || strings.Contains(norm, "/"+prefix+"/") || norm == prefix {
				return true
			}
		}

		matched, err := filepath.Match(pattern, base)
		if err == nil && matched {
			return true
		}

		matched, err = filepath.Match(pattern, norm)
		if err == nil && matched {
			return true
		}
	}
	return false
}

var scannableExtensions = map[string]bool{
	".js":      true,
	".jsx":     true,
	".ts":      true,
	".tsx":     true,
	".mjs":     true,
	".cjs":     true,
	".py":      true,
	".go":      true,
	".prisma":  true,
	".sql":     true,
	".graphql": true,
	".json":    true,
	".yaml":    true,
	".yml":     true,
	".env":     true,
}

func isScannable(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".env") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	return scannableExtensions[ext]
}
