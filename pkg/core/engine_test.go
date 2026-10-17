package core_test

import (
	"path/filepath"
	"testing"

	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
	"github.com/theterminalguy/pipedact/pkg/rules"
)

func TestEngineScanTSBackend(t *testing.T) {
	cfg := config.DefaultConfig()
	registry := rules.NewRegistry()

	var inspectors []core.RuleInspector
	for _, r := range registry.All() {
		inspectors = append(inspectors, r)
	}

	engine := core.NewEngine(cfg, inspectors)
	targetDir := filepath.Join("..", "..", "testdata", "ts_backend")

	result, err := engine.Scan([]string{targetDir})
	if err != nil {
		t.Fatalf("Engine.Scan failed: %v", err)
	}

	if result.ScannedFiles != 1 {
		t.Errorf("expected 1 file scanned, got %d", result.ScannedFiles)
	}

	if len(result.Violations) == 0 {
		t.Fatalf("expected violations in TS backend, got 0")
	}

	// Verify principles flagged: 7 (safeguards), 3 (consent), 4 (collection)
	flagged := make(map[int]bool)
	for _, v := range result.Violations {
		flagged[v.PrincipleID] = true
	}

	if !flagged[7] {
		t.Errorf("expected Principle 7 (Safeguards) to be flagged")
	}
	if !flagged[3] {
		t.Errorf("expected Principle 3 (Consent) to be flagged")
	}
	if !flagged[4] {
		t.Errorf("expected Principle 4 (Limiting Collection) to be flagged")
	}

	if result.ComplianceScore >= 70 {
		t.Errorf("expected score < 70, got %d", result.ComplianceScore)
	}
}

func TestEngineScanPrismaSchema(t *testing.T) {
	cfg := config.DefaultConfig()
	registry := rules.NewRegistry()

	var inspectors []core.RuleInspector
	for _, r := range registry.All() {
		inspectors = append(inspectors, r)
	}

	engine := core.NewEngine(cfg, inspectors)
	targetDir := filepath.Join("..", "..", "testdata", "prisma_schema")

	result, err := engine.Scan([]string{targetDir})
	if err != nil {
		t.Fatalf("Engine.Scan failed: %v", err)
	}

	if len(result.Violations) == 0 {
		t.Fatalf("expected violations in Prisma schema, got 0")
	}

	flagged := make(map[int]bool)
	for _, v := range result.Violations {
		flagged[v.PrincipleID] = true
	}

	if !flagged[2] {
		t.Errorf("expected Principle 2 (Purposes) to be flagged")
	}
	if !flagged[5] {
		t.Errorf("expected Principle 5 (Retention) to be flagged")
	}
}

func TestEngineScanSOC2Framework(t *testing.T) {
	cfg := config.DefaultConfig()
	registry := rules.NewRegistry()

	var inspectors []core.RuleInspector
	for _, r := range registry.All() {
		inspectors = append(inspectors, r)
	}

	engine := core.NewEngine(cfg, inspectors)
	engine.SetFramework(core.FrameworkSOC2)
	targetDir := filepath.Join("..", "..", "testdata", "ts_backend")

	result, err := engine.Scan([]string{targetDir})
	if err != nil {
		t.Fatalf("Engine.Scan failed: %v", err)
	}

	if result.Framework != core.FrameworkSOC2 {
		t.Errorf("expected FrameworkSOC2, got %v", result.Framework)
	}
	if len(result.SOC2Status) == 0 {
		t.Errorf("expected SOC2Status populated, got empty")
	}
}

func TestEngineScanNonexistentTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	engine := core.NewEngine(cfg, nil)

	_, err := engine.Scan([]string{"/nonexistent/directory/or/file"})
	if err == nil {
		t.Fatalf("expected error when scanning nonexistent target, got nil")
	}
}

func TestEngineScanDeterministicOrder(t *testing.T) {
	cfg := config.DefaultConfig()
	registry := rules.NewRegistry()

	var inspectors []core.RuleInspector
	for _, r := range registry.All() {
		inspectors = append(inspectors, r)
	}

	engine := core.NewEngine(cfg, inspectors)
	targetDir := filepath.Join("..", "..", "testdata")

	res1, err := engine.Scan([]string{targetDir})
	if err != nil {
		t.Fatalf("scan 1 failed: %v", err)
	}
	res2, err := engine.Scan([]string{targetDir})
	if err != nil {
		t.Fatalf("scan 2 failed: %v", err)
	}

	if len(res1.Violations) != len(res2.Violations) {
		t.Fatalf("mismatched violation counts: %d vs %d", len(res1.Violations), len(res2.Violations))
	}

	for i := range res1.Violations {
		v1 := res1.Violations[i]
		v2 := res2.Violations[i]
		if v1.FilePath != v2.FilePath || v1.Line != v2.Line || v1.RuleID != v2.RuleID {
			t.Errorf("finding order mismatch at %d: %s:%d vs %s:%d", i, v1.FilePath, v1.Line, v2.FilePath, v2.Line)
		}
	}
}
