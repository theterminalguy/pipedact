package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/luhn"
)

func newValidateSINCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate-sin <sin...>",
		Short: "Validate Canadian Social Insurance Numbers (SIN) with mod-10 Luhn check",
		Long: `Tests one or more candidate strings against the official Canadian federal
Social Insurance Number mod-10 Luhn checksum algorithm.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			green := color.New(color.FgGreen, color.Bold)
			red := color.New(color.FgRed, color.Bold)
			hasInvalid := false

			for _, candidate := range args {
				clean := luhn.CleanSIN(candidate)
				isValid := luhn.IsValidCanadianSIN(candidate)

				if isValid {
					green.Printf("✔ VALID:   ")
					fmt.Printf("%s (Formatted: %s) — Mod-10 Luhn check passed\n", candidate, luhn.FormatSIN(clean))
				} else {
					red.Printf("✘ INVALID: ")
					fmt.Printf("%s — Mod-10 Luhn check failed or invalid digit count\n", candidate)
					hasInvalid = true
				}
			}

			if hasInvalid {
				os.Exit(1)
			}
		},
	}
}
