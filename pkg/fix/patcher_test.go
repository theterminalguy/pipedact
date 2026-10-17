package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theterminalguy/pipedact/pkg/core"
)

func TestPatcherApplyFixesSafeguardLog(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.ts")
	initialContent := `import { logger } from './logger';
function logUser(email: string, phone: string) {
    logger.info("user event", {
        email,
        phoneNumber: phone
    });
}
`
	if err := os.WriteFile(testFile, []byte(initialContent), 0755); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	patcher := NewPatcher()
	violations := []core.Violation{
		{
			RuleID:     "PIPEDA-7-SAFEGUARD-LOG",
			CanAutoFix: true,
			FilePath:   testFile,
			Line:       3,
		},
	}

	report, err := patcher.ApplyFixes(testFile, violations)
	if err != nil {
		t.Fatalf("ApplyFixes failed: %v", err)
	}

	if !report.Modified {
		t.Errorf("expected file to be modified")
	}

	if report.Diff == "" {
		t.Errorf("expected unified diff in report, got empty")
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected file permissions 0755 preserved, got %v", info.Mode().Perm())
	}

	updated, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	content := string(updated)
	if !strings.Contains(content, "maskIdentifier(email)") {
		t.Errorf("expected email to be masked, got: %s", content)
	}
	if !strings.Contains(content, "import { maskIdentifier } from '../privacy/redact';") {
		t.Errorf("expected import to be prepended, got: %s", content)
	}
}

func TestPatcherDryRun(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_dryrun.ts")
	initialContent := `import { logger } from './logger';
function logUser(email: string, phone: string) {
    logger.info("user event", {
        email,
        phoneNumber: phone
    });
}
`
	if err := os.WriteFile(testFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	patcher := NewPatcher()
	violations := []core.Violation{
		{
			RuleID:     "PIPEDA-7-SAFEGUARD-LOG",
			CanAutoFix: true,
			FilePath:   testFile,
			Line:       3,
		},
	}

	report, err := patcher.ApplyFixesWithOptions(testFile, violations, FixOptions{DryRun: true})
	if err != nil {
		t.Fatalf("ApplyFixesWithOptions failed: %v", err)
	}

	if !report.Modified {
		t.Errorf("expected report.Modified to be true for dry run")
	}

	if report.Diff == "" {
		t.Errorf("expected diff in dry run report")
	}

	// Verify file on disk is UNTOUCHED
	onDisk, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(onDisk) != initialContent {
		t.Errorf("expected file on disk to remain unchanged in dry run mode")
	}
}

func TestPatcherIdempotency(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_idempotent.ts")
	initialContent := `import { logger } from './logger';
function logUser(email: string, phone: string) {
    logger.info("user event", {
        email,
        phoneNumber: phone
    });
}
`
	if err := os.WriteFile(testFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	patcher := NewPatcher()
	violations := []core.Violation{
		{
			RuleID:     "PIPEDA-7-SAFEGUARD-LOG",
			CanAutoFix: true,
			FilePath:   testFile,
			Line:       3,
		},
	}

	// Pass 1
	report1, err := patcher.ApplyFixes(testFile, violations)
	if err != nil || !report1.Modified {
		t.Fatalf("first pass failed: err=%v, modified=%v", err, report1.Modified)
	}

	// Pass 2
	report2, err := patcher.ApplyFixes(testFile, violations)
	if err != nil {
		t.Fatalf("second pass failed: %v", err)
	}
	if report2.Modified {
		t.Errorf("second pass should be idempotent and report Modified=false")
	}
}

func TestPatcherUnsafeRuleIgnored(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "schema.prisma")
	initialContent := `
model User {
  id    String @id
  sin   String
}
`
	if err := os.WriteFile(testFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	patcher := NewPatcher()
	// Attempt to autofix with CanAutoFix: false or unsafe rule
	violations := []core.Violation{
		{
			RuleID:     "PIPEDA-2-PURPOSE-UNTAGGED",
			CanAutoFix: false,
			FilePath:   testFile,
			Line:       4,
		},
		{
			RuleID:     "PIPEDA-5-RETENTION-DISPOSAL",
			CanAutoFix: false,
			FilePath:   testFile,
			Line:       2,
		},
	}

	report, err := patcher.ApplyFixes(testFile, violations)
	if err != nil {
		t.Fatalf("ApplyFixes failed: %v", err)
	}

	if report.Modified {
		t.Errorf("expected no modification for unsafe/disabled rules")
	}

	onDisk, _ := os.ReadFile(testFile)
	if string(onDisk) != initialContent {
		t.Errorf("expected schema file to be untouched")
	}
}
