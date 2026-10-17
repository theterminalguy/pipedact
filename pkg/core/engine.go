package core

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theterminalguy/pipedact/pkg/config"
)

// PrincipleStatus tracks compliance for a single statutory principle.
type PrincipleStatus struct {
	Principle   Principle
	Passing     bool
	Violations  []Violation
	ScoreImpact int
}

// SOC2Status tracks compliance for a single SOC 2 Trust Services Criterion.
type SOC2Status struct {
	Criteria   SOC2Criteria `json:"criteria"`
	Passing    bool         `json:"passing"`
	Violations []Violation  `json:"violations"`
}

// AuditResult encapsulates the full diagnostic outcome of a scan.
type AuditResult struct {
	ScannedFiles    int
	ScannedLines    int
	ScannedBytes    int64
	Duration        time.Duration
	Violations      []Violation
	PrincipleStatus map[int]*PrincipleStatus
	ComplianceScore int
	ScoreLabel      string
	Passed          bool
	Framework       Framework
	SOC2Status      map[string]*SOC2Status
	SOC2Score       int
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
		maxBytes:        10 * 1024 * 1024, // 10MB file limit
	}
}

// SetFramework sets the compliance framework to scan against.
func (e *Engine) SetFramework(fw Framework) {
	e.TargetFramework = fw
}

// Scan targets (files or directories).
func (e *Engine) Scan(targets []string) (*AuditResult, error) {
	start := time.Now()

	if len(targets) == 0 {
		targets = []string{"."}
	}

	filesToScan, err := e.collectFiles(targets)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var allViolations []Violation
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
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				info, err := os.Stat(path)
				if err != nil || info.IsDir() || info.Size() > e.maxBytes {
					continue
				}

				contentBytes, err := os.ReadFile(path)
				if err != nil {
					continue
				}

				relPath, _ := filepath.Rel(".", path)
				if relPath == "" {
					relPath = path
				}

				ctx := NewFileContext(path, relPath, string(contentBytes))

				var fileViolations []Violation
				for _, rule := range e.Rules {
					if e.TargetFramework != "" && e.TargetFramework != FrameworkAll {
						if _, mapped := rule.Frameworks()[e.TargetFramework]; !mapped {
							continue
						}
					}
					v := rule.Inspect(ctx, e.Config)
					if len(v) > 0 {
						fileViolations = append(fileViolations, v...)
					}
				}

				mu.Lock()
				scannedFilesCount++
				totalLines += len(ctx.Lines)
				totalBytes += info.Size()
				allViolations = append(allViolations, fileViolations...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

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

	result := e.calculateResult(allViolations, scannedFilesCount, totalLines, totalBytes, time.Since(start))
	return result, nil
}

func (e *Engine) calculateResult(violations []Violation, filesCount, linesCount int, bytesCount int64, duration time.Duration) *AuditResult {
	principles := GetSchedule1Principles()
	principleMap := make(map[int]*PrincipleStatus)

	for _, p := range principles {
		principleMap[p.ID] = &PrincipleStatus{
			Principle:   p,
			Passing:     true,
			Violations:  []Violation{},
			ScoreImpact: 0,
		}
	}

	for _, v := range violations {
		if status, exists := principleMap[v.PrincipleID]; exists {
			status.Passing = false
			status.Violations = append(status.Violations, v)
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

	score := int(math.Round((float64(earned) / float64(totalWeight)) * 100.0))
	scoreLabel := "High Technical Risk (Significant Exceptions Detected)"
	if len(violations) == 0 {
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
			Passing:    true,
			Violations: []Violation{},
		}
	}

	for _, v := range violations {
		if mapping, ok := v.FrameworkMappings[FrameworkSOC2]; ok {
			for critID, status := range soc2Map {
				if strings.Contains(mapping, critID) {
					status.Passing = false
					status.Violations = append(status.Violations, v)
				}
			}
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
		if len(violations) == 0 {
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
	for _, v := range violations {
		if v.Severity == SeverityCritical || v.Severity == SeverityHigh {
			hasCriticalOrHigh = true
			break
		}
	}

	return &AuditResult{
		ScannedFiles:    filesCount,
		ScannedLines:    linesCount,
		ScannedBytes:    bytesCount,
		Duration:        duration,
		Violations:      violations,
		PrincipleStatus: principleMap,
		ComplianceScore: finalScore,
		ScoreLabel:      finalLabel,
		Passed:          !hasCriticalOrHigh && len(violations) == 0,
		Framework:       fw,
		SOC2Status:      soc2Map,
		SOC2Score:       soc2Score,
	}
}

func (e *Engine) collectFiles(targets []string) ([]string, error) {
	var collected []string
	visited := make(map[string]bool)

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			return nil, fmt.Errorf("target path not found or inaccessible: %w", err)
		}

		if !info.IsDir() {
			abs, _ := filepath.Abs(target)
			if !visited[abs] && isScannable(target) && !e.isIgnored(target) {
				visited[abs] = true
				collected = append(collected, target)
			}
			continue
		}

		err = filepath.Walk(target, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip hidden dirs, git, vendor, node_modules
			name := fi.Name()
			if fi.IsDir() {
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "build" || (strings.HasPrefix(name, ".") && name != ".") {
					return filepath.SkipDir
				}
				return nil
			}

			abs, _ := filepath.Abs(path)
			if !visited[abs] && isScannable(path) && !e.isIgnored(path) {
				visited[abs] = true
				collected = append(collected, path)
			}
			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return collected, nil
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
