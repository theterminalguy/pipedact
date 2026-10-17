package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "pipedact",
		Short: "pipedact 🍁 — Statutory Privacy-as-Code Linter & OPC Compliance Suite for PIPEDA",
		Long: `pipedact is an open-source static analysis engine and compliance auditor in Go.
It scans codebases, database schemas, and CI/CD pipelines to ensure compliance with Canada's
Personal Information Protection and Electronic Documents Act (PIPEDA) and the 10 Fair
Information Principles in Schedule 1.`,
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
}
