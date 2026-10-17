package rules

import (
	"github.com/theterminalguy/pipedact/pkg/config"
	"github.com/theterminalguy/pipedact/pkg/core"
)

// Rule represents a single statutory or technical privacy gate.
type Rule interface {
	ID() string
	PrincipleID() int
	Principle() string
	Severity() core.Severity
	Description() string
	Inspect(ctx *core.FileContext, cfg *config.Config) []core.Violation
}

// Registry stores and manages all active rules.
type Registry struct {
	rules []Rule
}

// NewRegistry creates a registry initialized with all PIPEDA Schedule 1 rules.
func NewRegistry() *Registry {
	r := &Registry{}
	r.Register(
		&RuleSafeguardLog{},
		&RuleRawSIN{},
		&RuleConsentOptIn{},
		&RuleOverCollection{},
		&RulePurposeUntagged{},
		&RuleRetentionDisposal{},
		&RuleIncompleteDSR{},
		&RuleUnvettedSubprocessor{},
		&RuleAccuracyValidator{},
		&RuleOpennessPolicyRoute{},
		&RuleChallengingRecourse{},
	)
	return r
}

// Register adds one or more rules to the registry.
func (r *Registry) Register(rules ...Rule) {
	r.rules = append(r.rules, rules...)
}

// All returns all registered rules.
func (r *Registry) All() []Rule {
	return r.rules
}

// EffectiveSeverity calculates the severity of a rule considering user config overrides.
func EffectiveSeverity(rule Rule, cfg *config.Config) (core.Severity, bool) {
	if cfg != nil && cfg.Rules != nil {
		if rCfg, exists := cfg.Rules[rule.ID()]; exists {
			if rCfg.Enabled != nil && !*rCfg.Enabled {
				return rule.Severity(), false
			}
			if rCfg.Severity != nil {
				return core.ParseSeverity(*rCfg.Severity), true
			}
		}
	}
	return rule.Severity(), true
}
