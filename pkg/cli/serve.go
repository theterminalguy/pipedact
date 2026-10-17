package cli

import (
	"fmt"
	"io/fs"
	"net/http"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/web"
)

func newServeCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"ui", "playground"},
		Short:   "Start local web server hosting the interactive PIPEDA Compliance Suite",
		Long: `Launches an embedded HTTP server hosting the pipedact interactive audit playground,
OPC Schedule 1 Dossier evaluator, and CI/CD terminal simulator.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			subFS, err := fs.Sub(web.StaticFS, "static")
			if err != nil {
				return fmt.Errorf("failed to load embedded static filesystem: %w", err)
			}

			serverMux := http.NewServeMux()
			serverMux.Handle("/", http.FileServer(http.FS(subFS)))

			bold := color.New(color.Bold)
			green := color.New(color.FgGreen, color.Bold)
			cyan := color.New(color.FgCyan)

			addr := fmt.Sprintf(":%d", port)
			url := fmt.Sprintf("http://localhost:%d", port)

			bold.Println("\n🍁 pipedact Web Suite")
			green.Printf("✔ Local server running at: %s\n", url)
			cyan.Println("Press Ctrl+C to terminate.")

			return http.ListenAndServe(addr, serverMux)
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	return cmd
}
