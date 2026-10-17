package reporters

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/theterminalguy/pipedact/pkg/core"
)

// PrintTerminal outputs formatted, colorized findings to stdout or specified writer.
func PrintTerminal(w io.Writer, result *core.AuditResult, strict bool) {
	if w == nil {
		w = os.Stdout
	}

	bold := color.New(color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	gray := color.New(color.FgHiBlack)

	fmt.Fprintf(w, "\n")
	bold.Fprintf(w, "🍁 pipedact v1.2.0")
	fmt.Fprintf(w, " — Statutory Privacy Linter for PIPEDA (CA-Schedule 1)\n")
	gray.Fprintf(w, "   Scanned %d files (%d lines) in %v\n\n", result.ScannedFiles, result.ScannedLines, result.Duration)

	if len(result.Violations) == 0 {
		green.Fprintf(w, "✔ CLEAN PIPEDA AUDIT: No statutory privacy violations detected.\n")
		fmt.Fprintf(w, "  All 10 Fair Information Principles verified. Compliance score: ")
		green.Fprintf(w, "100%% (Audit Ready)\n\n")
		return
	}

	for i, v := range result.Violations {
		var badge *color.Color
		switch v.Severity {
		case core.SeverityCritical:
			badge = color.New(color.BgRed, color.FgWhite, color.Bold)
		case core.SeverityHigh:
			badge = red
		case core.SeverityMedium:
			badge = yellow
		case core.SeverityLow:
			badge = blue
		default:
			badge = gray
		}

		fmt.Fprintf(w, "  #%d ", i+1)
		badge.Fprintf(w, "[%s]", v.Severity)
		bold.Fprintf(w, " %s", v.Principle)
		gray.Fprintf(w, " (%s)\n", v.RuleID)

		fmt.Fprintf(w, "     %s:%d\n", v.FilePath, v.Line)
		fmt.Fprintf(w, "     %s\n", v.Message)

		if v.LineText != "" {
			gray.Fprintf(w, "     > ")
			fmt.Fprintf(w, "%s\n", v.LineText)
		}

		green.Fprintf(w, "     Remedy: ")
		fmt.Fprintf(w, "%s\n\n", v.Remediation)
	}

	// Compliance Score Bar & Summary
	fmt.Fprintf(w, "─────────────────────────────────────────────────────────────────────────────\n")
	bold.Fprintf(w, "PIPEDA Compliance Score: ")

	if result.ComplianceScore >= 90 {
		green.Fprintf(w, "%d%% — %s\n", result.ComplianceScore, result.ScoreLabel)
	} else if result.ComplianceScore >= 70 {
		yellow.Fprintf(w, "%d%% — %s\n", result.ComplianceScore, result.ScoreLabel)
	} else {
		red.Fprintf(w, "%d%% — %s\n", result.ComplianceScore, result.ScoreLabel)
	}

	fmt.Fprintf(w, "Total Violations: %d | Schedule 1 Status: ", len(result.Violations))
	if result.Passed {
		green.Fprintf(w, "PASS (Exit 0)\n\n")
	} else {
		red.Fprintf(w, "FAIL (Exit 1)\n\n")
	}
}
