package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/core"
)

func newPrinciplesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "principles",
		Aliases: []string{"rules", "matrix"},
		Short:   "Display the PIPEDA Schedule 1 Fair Information Principles technical matrix",
		Run: func(cmd *cobra.Command, args []string) {
			principles := core.GetSchedule1Principles()

			bold := color.New(color.Bold)
			cyan := color.New(color.FgCyan)

			bold.Println("\n🍁 PIPEDA Schedule 1 — 10 Fair Information Principles Technical Map")
			fmt.Println("How pipedact maps Canadian federal statutory requirements to automated gates.")
			fmt.Println()

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tPRINCIPLE\tSTATUTE\tSEVERITY\tWEIGHT\tTECHNICAL GATE")
			fmt.Fprintln(w, "──\t─────────\t───────\t────────\t──────\t──────────────")

			for _, p := range principles {
				sevStr := string(p.Severity)
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d%%\t%s\n", p.ID, p.Name, p.Statutory, sevStr, p.Weight, p.Gate)
			}

			w.Flush()
			cyan.Println("\nRun 'pipedact check' to run automated gates against your local codebase.")
			fmt.Println()
		},
	}
}
