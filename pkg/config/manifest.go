package config

// RuleConfig allows enabling/disabling or overriding severity per rule.
type RuleConfig struct {
	Enabled  *bool   `yaml:"enabled"`
	Severity *string `yaml:"severity"`
}

// PrivacyOfficerConfig defines designated statutory contact information.
type PrivacyOfficerConfig struct {
	Name       string `yaml:"name"`
	Email      string `yaml:"email"`
	DisputeURL string `yaml:"dispute_url"`
}

// SchemasConfig defines schema audit policies.
type SchemasConfig struct {
	EnforcePurposeTags bool     `yaml:"enforcePurposeTags"`
	AllowedPurposes    []string `yaml:"allowedPurposes"`
}

// SinksConfig defines log sink restriction policies.
type SinksConfig struct {
	DisallowedLogIdentifiers []string `yaml:"disallowedLogIdentifiers"`
	BlockSinks               []string `yaml:"blockSinks"`
}

// RetentionConfig defines retention policies.
type RetentionConfig struct {
	DefaultMaxTtlDays         int  `yaml:"defaultMaxTtlDays"`
	RequireHardDeleteSchedule bool `yaml:"requireHardDeleteSchedule"`
}

// Config represents the complete .pipedactrc.yaml manifest.
type Config struct {
	Version        string                `yaml:"version"`
	Jurisdiction   string                `yaml:"jurisdiction"`
	PrivacyOfficer PrivacyOfficerConfig  `yaml:"privacy_officer"`
	Schemas        SchemasConfig         `yaml:"schemas"`
	Sinks          SinksConfig           `yaml:"sinks"`
	Retention      RetentionConfig       `yaml:"retention"`
	Rules          map[string]RuleConfig `yaml:"rules"`
	Ignore         []string              `yaml:"ignore"`
}

// DefaultConfig returns default sensible values for PIPEDA Schedule 1 compliance.
func DefaultConfig() *Config {
	return &Config{
		Version:      "1.0",
		Jurisdiction: "CA-PIPEDA",
		PrivacyOfficer: PrivacyOfficerConfig{
			Name:       "Designated Privacy Officer",
			Email:      "privacy@organization.ca",
			DisputeURL: "https://organization.ca/legal/privacy/dispute",
		},
		Schemas: SchemasConfig{
			EnforcePurposeTags: true,
			AllowedPurposes: []string{
				"user_authentication",
				"billing_tax_invoicing",
				"order_fulfillment",
				"security_fraud_prevention",
				"analytics_consented",
			},
		},
		Sinks: SinksConfig{
			DisallowedLogIdentifiers: []string{
				"canadian_sin",
				"credit_card",
				"phone_number",
				"email_address",
				"provincial_health_card",
			},
			BlockSinks: []string{
				"console.log",
				"console.error",
				"logger.*",
				"logging.*",
				"print",
			},
		},
		Retention: RetentionConfig{
			DefaultMaxTtlDays:         730,
			RequireHardDeleteSchedule: true,
		},
		Rules: make(map[string]RuleConfig),
		Ignore: []string{
			"**/*_test.go",
			"**/*.test.ts",
			"**/*.spec.ts",
			"node_modules/**",
			"vendor/**",
			".git/**",
			"dist/**",
			"build/**",
		},
	}
}
