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
		fmt.Fprintf(w, " — Security & Privacy Static Scanner (Mapped to SOC 2 Criteria)\n")
	case core.FrameworkAll:
		bold.Fprintf(w, "🌐 pipedact v1.2.0")
		fmt.Fprintf(w, " — Multi-Standard Privacy & Security Scanner (PIPEDA / SOC 2 / ISO 27701 / Law 25)\n")
	default:
		bold.Fprintf(w, "🍁 pipedact v1.2.0")
		fmt.Fprintf(w, " — Privacy & Security Code Linter (PIPEDA Schedule 1)\n")
	}

	if !result.IsComplete {
		yellow.Fprintf(w, "⚠️  PARTIAL SCAN WARNING: %d file(s) failed to read or process\n", len(result.FailedFiles))
		gray.Fprintf(w, "   Discovered: %d | Scanned: %d (%d lines) | Skipped: %d | Failed: %d in %v\n\n",
			result.DiscoveredFiles, result.ScannedFiles, result.ScannedLines, len(result.SkippedFiles), len(result.FailedFiles), result.Duration)
	} else {
		gray.Fprintf(w, "   Discovered: %d | Scanned: %d (%d lines) | Skipped: %d in %v\n\n",
			result.DiscoveredFiles, result.ScannedFiles, result.ScannedLines, len(result.SkippedFiles), result.Duration)
	}

	if len(result.FailedFiles) > 0 {
		red.Fprintf(w, "  Failed Files (%d):\n", len(result.FailedFiles))
		for _, f := range result.FailedFiles {
			red.Fprintf(w, "   ✖ %s: %s\n", f.Path, f.Error)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(result.SkippedFiles) > 0 {
		gray.Fprintf(w, "  Skipped Files (%d):\n", len(result.SkippedFiles))
		for i, s := range result.SkippedFiles {
			if i >= 10 {
				gray.Fprintf(w, "   ... and %d more\n", len(result.SkippedFiles)-10)
				break
			}
			gray.Fprintf(w, "   - %s [%s: %s]\n", s.Path, s.Reason, s.Detail)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(result.Violations) == 0 {
		if !result.IsComplete {
			yellow.Fprintf(w, "⚠️  INCOMPLETE SCAN: 0 violations in %d scanned files, but %d file(s) could not be evaluated.\n",
				result.ScannedFiles, len(result.FailedFiles))
			if strict {
				red.Fprintf(w, "  Strict mode failure: Incomplete scans are not permitted.\n\n")
			} else {
				fmt.Fprintf(w, "\n")
			}
		} else if result.Framework == core.FrameworkSOC2 {
			green.Fprintf(w, "✔ CLEAN SCAN: No technical exceptions detected for mapped SOC 2 criteria.\n")
			fmt.Fprintf(w, "  All automated checks passed. Technical readiness score: ")
			green.Fprintf(w, "100%% (Passing)\n\n")
		} else {
			green.Fprintf(w, "✔ CLEAN SCAN: No potential privacy violations detected.\n")
			fmt.Fprintf(w, "  All automated checks passed. Technical score: ")
			green.Fprintf(w, "100%% (Passing)\n\n")
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
		gray.Fprintf(w, " (%s)", v.RuleID)
		if v.Confidence != "" {
			gray.Fprintf(w, " [Confidence: %s]", v.Confidence)
		}
		fmt.Fprintf(w, "\n")

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
	scoreTitle := "PIPEDA Technical Score: "
	if result.Framework == core.FrameworkSOC2 {
		scoreTitle = "SOC 2 Technical Readiness: "
	} else if result.Framework == core.FrameworkAll {
		scoreTitle = "Multi-Framework Technical Score: "
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
		gray.Fprintf(w, "   PIPEDA Score: %d%% | SOC 2 Readiness: %d%%\n", result.ComplianceScore, result.SOC2Score)
	}

	passed := result.Passed
	if strict && !result.IsComplete {
		passed = false
	}

	fmt.Fprintf(w, "Total Violations: %d | Gate Status: ", len(result.Violations))
	if passed {
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
