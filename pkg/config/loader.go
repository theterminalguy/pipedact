package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var defaultCandidateNames = []string{
	".pipedactrc.yaml",
	".pipedactrc.yml",
	".pipedact.yaml",
	".pipedact.yml",
}

// LoadConfig attempts to load configuration from the specified path or standard search locations.
func LoadConfig(specifiedPath string) (*Config, string, error) {
	cfg := DefaultConfig()

	if specifiedPath != "" {
		data, err := os.ReadFile(specifiedPath)
		if err != nil {
			return nil, "", err
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, "", err
		}
		return cfg, specifiedPath, nil
	}

	// Search current directory and parent directories up to git root
	cwd, err := os.Getwd()
	if err != nil {
		return cfg, "", nil
	}

	dir := cwd
	for {
		for _, candidate := range defaultCandidateNames {
			candidatePath := filepath.Join(dir, candidate)
			if stat, err := os.Stat(candidatePath); err == nil && !stat.IsDir() {
				data, err := os.ReadFile(candidatePath)
				if err == nil {
					if err := yaml.Unmarshal(data, cfg); err == nil {
						return cfg, candidatePath, nil
					}
				}
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return cfg, "", nil
}

// GenerateDefaultYAML returns a well-commented default YAML configuration as a string.
func GenerateDefaultYAML() string {
	return `version: "1.0"
jurisdiction: "CA-PIPEDA"

privacy_officer:
  name: "Data Privacy Officer"
  email: "privacy@organization.ca"
  dispute_url: "https://organization.ca/legal/privacy/dispute"

# Principle 2 & 4: Limiting Collection & Identifying Purposes
schemas:
  enforcePurposeTags: true
  allowedPurposes:
    - user_authentication
    - billing_tax_invoicing
    - order_fulfillment
    - security_fraud_prevention
    - analytics_consented

# Principle 7: Safeguards (Redact Logging Sinks)
sinks:
  disallowedLogIdentifiers:
    - canadian_sin
    - credit_card
    - phone_number
    - email_address
    - provincial_health_card
  blockSinks:
    - console.log
    - console.error
    - logger.*
    - logging.*
    - print

# Principle 5: Retention Enforcement
retention:
  defaultMaxTtlDays: 730
  requireHardDeleteSchedule: true

ignore:
  - "**/*_test.go"
  - "**/*.spec.ts"
  - "**/*.test.ts"
  - "node_modules/**"
  - "vendor/**"
  - ".git/**"
  - "dist/**"
  - "build/**"
`
}
