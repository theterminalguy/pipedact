package reporters

import (
	"encoding/json"

	"github.com/theterminalguy/pipedact/pkg/core"
)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// GenerateSARIF produces OASIS SARIF 2.1.0 compliant JSON bytes.
func GenerateSARIF(result *core.AuditResult) ([]byte, error) {
	var sarifResults []sarifResult

	for _, v := range result.Violations {
		level := "warning"
		if v.Severity == core.SeverityCritical || v.Severity == core.SeverityHigh {
			level = "error"
		}

		sarifResults = append(sarifResults, sarifResult{
			RuleID: v.RuleID,
			Level:  level,
			Message: sarifMessage{
				Text: v.Message + " Remediation: " + v.Remediation,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: v.FilePath,
						},
						Region: sarifRegion{
							StartLine: v.Line,
						},
					},
				},
			},
		})
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "pipedact",
						Version:        "1.2.0",
						InformationURI: "https://github.com/theterminalguy/pipedact",
					},
				},
				Results: sarifResults,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}
