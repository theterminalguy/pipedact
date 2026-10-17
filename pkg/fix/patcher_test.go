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
