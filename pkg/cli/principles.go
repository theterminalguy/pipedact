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
	var framework string

	cmd := &cobra.Command{
		Use:     "principles",
		Aliases: []string{"rules", "matrix", "criteria"},
		Short:   "Display the compliance principles and Trust Services Criteria matrix",
		Run: func(cmd *cobra.Command, args []string) {
			fw := core.ParseFramework(framework)
			bold := color.New(color.Bold)
			cyan := color.New(color.FgCyan)

			if fw == core.FrameworkSOC2 {
				bold.Println("\n🛡️  AICPA SOC 2 Type II — Trust Services Criteria Technical Map")
				fmt.Println("How pipedact maps Security (CC6/CC7) and Privacy (P1-P5) criteria to automated gates.")
				fmt.Println()

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "CRITERIA\tCATEGORY\tNAME\tWEIGHT\tDESCRIPTION")
				fmt.Fprintln(w, "────────\t────────\t────\t──────\t───────────")

				for _, c := range core.GetSOC2Criteria() {
					fmt.Fprintf(w, "%s\t%s\t%s\t%d%%\t%s\n", c.ID, c.Category, c.Name, c.Weight, c.Description)
				}
				w.Flush()
				cyan.Println("\nRun 'pipedact check --framework soc2' to verify your codebase against SOC 2 criteria.")
				fmt.Println()
				return
			}

			principles := core.GetSchedule1Principles()
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

	cmd.Flags().StringVar(&framework, "framework", "pipeda", "Framework matrix to display: pipeda, soc2")
	return cmd
}
