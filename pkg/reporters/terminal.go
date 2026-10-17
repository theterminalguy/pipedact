package reporters

import (
	"fmt"
	"io"
	"os"
	"strings"

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
	switch result.Framework {
	case core.FrameworkSOC2:
		bold.Fprintf(w, "🛡️  pipedact v1.2.0")
		fmt.Fprintf(w, " — SOC 2 Type II Trust Services Criteria Scanner (Security & Privacy)\n")
	case core.FrameworkAll:
		bold.Fprintf(w, "🌐 pipedact v1.2.0")
		fmt.Fprintf(w, " — Multi-Framework Scanner (PIPEDA / SOC 2 / ISO 27701 / Quebec Law 25)\n")
	default:
		bold.Fprintf(w, "🍁 pipedact v1.2.0")
		fmt.Fprintf(w, " — Statutory Privacy Linter for PIPEDA (CA-Schedule 1)\n")
	}
	gray.Fprintf(w, "   Scanned %d files (%d lines) in %v\n\n", result.ScannedFiles, result.ScannedLines, result.Duration)

	if len(result.Violations) == 0 {
		if result.Framework == core.FrameworkSOC2 {
			green.Fprintf(w, "✔ CLEAN SOC 2 AUDIT: No security or privacy criteria exceptions detected.\n")
			fmt.Fprintf(w, "  All Trust Services Criteria verified. Readiness score: ")
			green.Fprintf(w, "100%% (Audit Ready)\n\n")
		} else {
			green.Fprintf(w, "✔ CLEAN AUDIT: No statutory compliance violations detected.\n")
			fmt.Fprintf(w, "  All Fair Information Principles verified. Compliance score: ")
			green.Fprintf(w, "100%% (Audit Ready)\n\n")
		}
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

		if len(v.FrameworkMappings) > 0 {
			var fwRefs []string
			if ref, ok := v.FrameworkMappings[core.FrameworkPIPEDA]; ok && ref != "" {
				fwRefs = append(fwRefs, fmt.Sprintf("PIPEDA: %s", ref))
			}
			if ref, ok := v.FrameworkMappings[core.FrameworkSOC2]; ok && ref != "" {
				fwRefs = append(fwRefs, fmt.Sprintf("SOC 2: %s", ref))
			}
			if ref, ok := v.FrameworkMappings[core.FrameworkISO27701]; ok && ref != "" {
				fwRefs = append(fwRefs, fmt.Sprintf("ISO 27701: %s", ref))
			}
			if ref, ok := v.FrameworkMappings[core.FrameworkLaw25]; ok && ref != "" {
				fwRefs = append(fwRefs, fmt.Sprintf("Law 25: %s", ref))
			}
			if len(fwRefs) > 0 {
				gray.Fprintf(w, "     Frameworks: %s\n", strings.Join(fwRefs, " | "))
			}
		}

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
	scoreTitle := "PIPEDA Compliance Score: "
	if result.Framework == core.FrameworkSOC2 {
		scoreTitle = "SOC 2 Type II Readiness Score: "
	} else if result.Framework == core.FrameworkAll {
		scoreTitle = "Unified Compliance Score: "
	}
	bold.Fprintf(w, "%s", scoreTitle)

	if result.ComplianceScore >= 90 {
		green.Fprintf(w, "%d%% — %s\n", result.ComplianceScore, result.ScoreLabel)
	} else if result.ComplianceScore >= 70 {
		yellow.Fprintf(w, "%d%% — %s\n", result.ComplianceScore, result.ScoreLabel)
	} else {
		red.Fprintf(w, "%d%% — %s\n", result.ComplianceScore, result.ScoreLabel)
	}

	if result.Framework == core.FrameworkAll {
		gray.Fprintf(w, "   PIPEDA Schedule 1 Score: %d%% | SOC 2 Type II Readiness: %d%%\n", result.ComplianceScore, result.SOC2Score)
	}

	statusLabel := "Compliance Gate Status: "
	if result.Framework == core.FrameworkSOC2 {
		statusLabel = "SOC 2 Gate Status: "
	}
	fmt.Fprintf(w, "Total Violations: %d | %s", len(result.Violations), statusLabel)
	if result.Passed {
		green.Fprintf(w, "PASS (Exit 0)\n\n")
	} else {
		red.Fprintf(w, "FAIL (Exit 1)\n\n")
	}
}

// PrintAIAnalysis outputs the AI-synthesized semantic privacy audit to the terminal.
func PrintAIAnalysis(w io.Writer, providerUsed, summary string, risksCount int) {
	if w == nil {
		w = os.Stdout
	}

	magenta := color.New(color.FgMagenta, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	gray := color.New(color.FgHiBlack)

	fmt.Fprintf(w, "─────────────────────────────────────────────────────────────────────────────\n")
	magenta.Fprintf(w, "🤖 AI Privacy Intelligence & Semantic Reasoning")
	gray.Fprintf(w, " (Engine: %s)\n\n", providerUsed)

	fmt.Fprintf(w, "%s\n\n", summary)

	if risksCount > 0 {
		cyan.Fprintf(w, "💡 Recommendation: ")
		fmt.Fprintf(w, "Review flagged architectural risks above or run 'pipedact check --fix' to apply safe patches.\n\n")
	}
}
