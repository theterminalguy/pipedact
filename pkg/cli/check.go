package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/ai"
	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
	"github.com/theterminalguy/pipedact/pkg/fix"
	"github.com/theterminalguy/pipedact/pkg/reporters"
	"github.com/theterminalguy/pipedact/pkg/rules"
)

func newCheckCmd() *cobra.Command {
	var (
		strict     bool
		failOn     string
		format     string
		outFile    string
		applyFix   bool
		enableAI   bool
		aiProvider string
		framework  string
	)

	cmd := &cobra.Command{
		Use:          "check [paths...]",
		Aliases:      []string{"scan", "lint"},
		Short:        "Scan codebase for statutory PIPEDA and SOC 2 compliance violations",
		SilenceUsage: true,
		Long: `Recursively analyzes target source files, database schemas, and API calls against
the 10 Fair Information Principles in PIPEDA Schedule 1, SOC 2 Trust Services Criteria,
ISO/IEC 27701, and Quebec Law 25.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, loadedPath, err := config.LoadConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			if loadedPath != "" && format == "text" && outFile == "" {
				color.New(color.FgHiBlack).Printf("Loaded configuration from %s\n", loadedPath)
			}

			registry := rules.NewRegistry()
			var inspectors []core.RuleInspector
			for _, r := range registry.All() {
				inspectors = append(inspectors, r)
			}

			engine := core.NewEngine(cfg, inspectors)
			fw := core.ParseFramework(framework)
			engine.SetFramework(fw)
			result, err := engine.Scan(args)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Apply automated remediation if --fix flag was provided
			if applyFix && len(result.Violations) > 0 {
				patcher := fix.NewPatcher()
				violationsByFile := make(map[string][]core.Violation)
				for _, v := range result.Violations {
					violationsByFile[v.FilePath] = append(violationsByFile[v.FilePath], v)
				}

				totalPatched := 0
				for filePath, fViolations := range violationsByFile {
					report, err := patcher.ApplyFixes(filePath, fViolations)
					if err != nil {
						color.New(color.FgYellow).Fprintf(os.Stderr, "[remediation] Warning: failed to apply fixes to %s: %v\n", filePath, err)
						continue
					}
					if report.Modified {
						totalPatched += len(report.PatchedRules)
						color.New(color.FgGreen).Printf("[remediation] Automatically patched %d issues in %s\n", len(report.PatchedRules), filePath)
					}
				}

				if totalPatched > 0 {
					// Re-scan to update violations and score
					var rescanErr error
					result, rescanErr = engine.Scan(args)
					if rescanErr != nil {
						return fmt.Errorf("rescan after auto-remediation failed: %w", rescanErr)
					}
				}
			}

			// Optional AI semantic privacy reasoning
			var aiRes *ai.AnalysisResponse
			if enableAI {
				prov, provErr := ai.ResolveProvider(aiProvider)
				if provErr != nil {
					return fmt.Errorf("ai provider error: %w", provErr)
				}
				var aiErr error
				aiRes, aiErr = ai.RunAIAnalysis(cmd.Context(), result, prov)
				if aiErr != nil {
					color.New(color.FgYellow).Fprintf(os.Stderr, "Warning: AI semantic analysis failed: %v\n", aiErr)
				}
			}

			// Format and output results
			var outputBytes []byte
			switch strings.ToLower(format) {
			case "sarif":
				outputBytes, err = reporters.GenerateSARIF(result)
				if err != nil {
					return err
				}
			case "json":
				outputBytes, err = reporters.GenerateJSON(result)
				if err != nil {
					return err
				}
			case "markdown", "md":
				outputBytes = []byte(reporters.GenerateMarkdownDossier(result))
			case "html":
				outputBytes = []byte(reporters.GenerateHTML(result))
			default:
				// Default text format to terminal
				if outFile == "" {
					reporters.PrintTerminal(os.Stdout, result, strict)
					if aiRes != nil {
						reporters.PrintAIAnalysis(os.Stdout, aiRes.ProviderUsed, aiRes.ExecutiveSummary, len(aiRes.SemanticRisks))
					}
				} else {
					var sb strings.Builder
					reporters.PrintTerminal(&sb, result, strict)
					if aiRes != nil {
						reporters.PrintAIAnalysis(&sb, aiRes.ProviderUsed, aiRes.ExecutiveSummary, len(aiRes.SemanticRisks))
					}
					outputBytes = []byte(sb.String())
				}
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, outputBytes, 0644); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
				fmt.Printf("Report successfully saved to %s\n", outFile)
			} else if format != "text" {
				fmt.Println(string(outputBytes))
			}

			// Determine exit code
			failThreshold := core.ParseSeverity(failOn)
			shouldFail := false
			failCount := 0

			if strict && len(result.Violations) > 0 {
				shouldFail = true
				failCount = len(result.Violations)
			} else {
				for _, v := range result.Violations {
					if v.Severity.Level() >= failThreshold.Level() {
						shouldFail = true
						failCount++
					}
				}
			}

			if shouldFail {
				return fmt.Errorf("compliance policy threshold exceeded: %d violations meeting or exceeding %s severity", failCount, failThreshold.String())
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&strict, "strict", "s", false, "Fail build (exit code 1) on ANY detected violation")
	cmd.Flags().StringVar(&failOn, "fail-on", "HIGH", "Severity threshold to trigger exit 1 (CRITICAL, HIGH, MEDIUM, LOW)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, sarif, json, markdown, html")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "Output file path (default stdout)")
	cmd.Flags().BoolVar(&applyFix, "fix", false, "Automatically remediate detected violations where safe")
	cmd.Flags().BoolVar(&enableAI, "ai", false, "Enable AI semantic privacy analysis (Gemini, OpenAI, Ollama, Heuristic)")
	cmd.Flags().StringVar(&aiProvider, "ai-provider", "auto", "AI provider to use (auto, gemini, openai, ollama, heuristic)")
	cmd.Flags().StringVar(&framework, "framework", "pipeda", "Target compliance framework: pipeda, soc2, iso27701, law25, all")

	return cmd
}
