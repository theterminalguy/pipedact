package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/theterminalguy/pipedact/pkg/config"
)

func newInitCmd() *cobra.Command {
	var withCI bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize PIPEDA compliance policy manifest and GitHub Action workflow",
		Long: `Creates a default .pipedactrc.yaml policy configuration file and optional
GitHub Actions CI workflow (.github/workflows/pipeda.yml).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			green := color.New(color.FgGreen, color.Bold)
			manifestPath := ".pipedactrc.yaml"

			if _, err := os.Stat(manifestPath); err == nil {
				fmt.Printf("File %s already exists. Skipping overwrite.\n", manifestPath)
			} else {
				content := config.GenerateDefaultYAML()
				if err := os.WriteFile(manifestPath, []byte(content), 0644); err != nil {
					return fmt.Errorf("failed to write %s: %w", manifestPath, err)
				}
				green.Printf("✔ Created %s\n", manifestPath)
			}

			if withCI {
				workflowDir := filepath.Join(".github", "workflows")
				workflowPath := filepath.Join(workflowDir, "pipeda.yml")
				if err := os.MkdirAll(workflowDir, 0755); err != nil {
					return err
				}

				workflowYAML := `name: PIPEDA Compliance Gate
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  privacy-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'
          cache: true
      - name: Install pipedact
        run: go install github.com/theterminalguy/pipedact/cmd/pipedact@latest
      - name: Run Privacy Linter
        run: pipedact check . --strict --format sarif --out audit.sarif
      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        continue-on-error: true
        with:
          sarif_file: audit.sarif
`
				if err := os.WriteFile(workflowPath, []byte(workflowYAML), 0644); err != nil {
					return fmt.Errorf("failed to write %s: %w", workflowPath, err)
				}
				green.Printf("✔ Created %s\n", workflowPath)
			}

			fmt.Println("\nConfiguration ready. Run 'pipedact check' to start auditing!")
			return nil
		},
	}

	cmd.Flags().BoolVar(&withCI, "ci", true, "Generate .github/workflows/pipeda.yml CI workflow")
	return cmd
}
