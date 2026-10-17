package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCmd_Execution(t *testing.T) {
	tmpDir := t.TempDir()
	vulnerableFile := filepath.Join(tmpDir, "auth.ts")
	vulnerableCode := `
import { logger } from './logger';
function handle(req: any) {
    logger.info("user details", {
        sin: "046-454-286"
    });
}
`
	if err := os.WriteFile(vulnerableFile, []byte(vulnerableCode), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cmd := newCheckCmd()
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)

	cmd.SetArgs([]string{vulnerableFile})

	// Should fail because vulnerableFile has violations exceeding HIGH threshold
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error from check command on vulnerable codebase, got nil")
	}
}

func TestCheckCmd_NonexistentTarget(t *testing.T) {
	cmd := newCheckCmd()
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)

	cmd.SetArgs([]string{"/nonexistent/path/xyz"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error on nonexistent path, got nil")
	}
}
