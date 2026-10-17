package cli

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/ai"
)

func newExplainCmd() *cobra.Command {
	var aiProvider string

	cmd := &cobra.Command{
		Use:   "explain <rule-id>",
		Short: "Explain a PIPEDA rule, statutory basis, and OPC precedent using AI",
		Long: `Provides in-depth Canadian statutory analysis, Office of the Privacy Commissioner (OPC)
investigation precedents, and compliant refactoring code examples for a given rule ID.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID := args[0]
			prov, err := ai.ResolveProvider(aiProvider)
			if err != nil {
				return err
			}

			bold := color.New(color.Bold)
			magenta := color.New(color.FgMagenta, color.Bold)
			cyan := color.New(color.FgCyan, color.Bold)
			green := color.New(color.FgGreen, color.Bold)
			red := color.New(color.FgRed, color.Bold)
			gray := color.New(color.FgHiBlack)

			resp, err := prov.Explain(context.Background(), ruleID, "")
			if err != nil {
				return fmt.Errorf("failed to generate explanation: %w", err)
			}

			fmt.Println()
			bold.Printf("🍁 PIPEDA Statutory Explainer: ")
			magenta.Printf("%s\n", ruleID)
			gray.Printf("   Engine: %s\n\n", prov.Name())

			if resp.Principle != "" {
				cyan.Printf("Statutory Principle: ")
				fmt.Printf("%s (%s)\n\n", resp.Principle, resp.Statute)
			}

			bold.Println("Legal Summary & Statutory Mandate:")
			fmt.Printf("%s\n\n", resp.LegalSummary)

			if resp.OPCPrecedent != "" {
				bold.Println("OPC Investigation Precedents:")
				fmt.Printf("%s\n\n", resp.OPCPrecedent)
			}

			if resp.VulnerableCode != "" {
				red.Println("Anti-Pattern Example:")
				fmt.Printf("%s\n\n", resp.VulnerableCode)
			}

			if resp.CompliantCode != "" {
				green.Println("Compliant Code Pattern:")
				fmt.Printf("%s\n\n", resp.CompliantCode)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&aiProvider, "ai-provider", "auto", "AI provider (auto, gemini, openai, ollama, heuristic)")
	return cmd
}
