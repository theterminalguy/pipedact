package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
	"github.com/theterminalguy/pipedact/pkg/fix"
	"github.com/theterminalguy/pipedact/pkg/reporters"
	"github.com/theterminalguy/pipedact/pkg/rules"
)

func newCheckCmd() *cobra.Command {
	var (
		strict   bool
		failOn   string
		format   string
		outFile  string
		applyFix bool
	)

	cmd := &cobra.Command{
		Use:     "check [paths...]",
		Aliases: []string{"scan", "lint"},
		Short:   "Scan codebase for statutory PIPEDA privacy violations",
		Long: `Recursively analyzes target source files, database schemas, and API calls against
the 10 Fair Information Principles in PIPEDA Schedule 1.`,
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
					if err == nil && report.Modified {
						totalPatched += len(report.PatchedRules)
						color.New(color.FgGreen).Printf("[remediation] Automatically patched %d issues in %s\n", len(report.PatchedRules), filePath)
					}
				}

				if totalPatched > 0 {
					// Re-scan to update violations and score
					result, _ = engine.Scan(args)
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
				} else {
					var sb strings.Builder
					reporters.PrintTerminal(&sb, result, strict)
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

			if strict && len(result.Violations) > 0 {
				shouldFail = true
			} else {
				for _, v := range result.Violations {
					if v.Severity.Level() >= failThreshold.Level() {
						shouldFail = true
						break
					}
				}
			}

			if shouldFail {
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&strict, "strict", "s", false, "Fail build (exit code 1) on ANY detected violation")
	cmd.Flags().StringVar(&failOn, "fail-on", "HIGH", "Severity threshold to trigger exit 1 (CRITICAL, HIGH, MEDIUM, LOW)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, sarif, json, markdown, html")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "Output file path (default stdout)")
	cmd.Flags().BoolVar(&applyFix, "fix", false, "Automatically remediate detected violations where safe")

	return cmd
}
