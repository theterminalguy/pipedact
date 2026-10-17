package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:           "pipedact",
		Short:         "pipedact 🍁 — Privacy & Security Code Linter for PIPEDA and SOC 2",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `pipedact is an open-source static analysis engine and compliance auditor in Go.
It scans codebases, database schemas, and CI/CD pipelines to detect privacy risks, insecure
patterns, and compliance gaps mapped to PIPEDA Schedule 1, SOC 2 Trust Services Criteria,
ISO/IEC 27701, and Quebec Law 25.`,
	}
)

// Execute runs the root CLI command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to .pipedactrc.yaml configuration file")

	rootCmd.AddCommand(newCheckCmd())
	rootCmd.AddCommand(newDossierCmd())
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newValidateSINCmd())
	rootCmd.AddCommand(newPrinciplesCmd())
	rootCmd.AddCommand(newServeCmd())
	rootCmd.AddCommand(newExplainCmd())
}
