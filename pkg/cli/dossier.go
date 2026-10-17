package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
	"github.com/theterminalguy/pipedact/pkg/reporters"
	"github.com/theterminalguy/pipedact/pkg/rules"
)

func newDossierCmd() *cobra.Command {
	var (
		format    string
		outFile   string
		framework string
	)

	cmd := &cobra.Command{
		Use:   "dossier [paths...]",
		Short: "Generate PIPEDA or SOC 2 technical assessment report",
		Long: `Generates a structured technical assessment report synthesizing static analysis findings
mapped to PIPEDA Schedule 1 principles or AICPA SOC 2 Trust Services Criteria.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.LoadConfig(cfgFile)
			if err != nil {
				return err
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
				return err
			}

			var output string
			switch strings.ToLower(format) {
			case "html":
				output = reporters.GenerateHTML(result)
			case "json":
				bytes, err := reporters.GenerateJSON(result)
				if err != nil {
					return err
				}
				output = string(bytes)
			default:
				output = reporters.GenerateMarkdownDossier(result)
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(output), 0644); err != nil {
					return err
				}
				fmt.Printf("Dossier successfully exported to %s\n", outFile)
			} else {
				fmt.Println(output)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "markdown", "Dossier format: markdown, html, json")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "Output file path (default stdout)")
	cmd.Flags().StringVar(&framework, "framework", "pipeda", "Target compliance framework: pipeda, soc2, iso27701, law25, all")

	return cmd
}
