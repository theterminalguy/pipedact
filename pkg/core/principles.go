package core

// Principle represents one of the 10 Fair Information Principles in PIPEDA Schedule 1.
type Principle struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Weight      int    `json:"weight"`
	Automated   bool   `json:"automated"`
	Statutory   string `json:"statutory"`
	Meaning     string `json:"meaning"`
	Gate        string `json:"gate"`
	Severity    Severity `json:"severity"`
	DefaultNote string `json:"defaultNote"`
}

// GetSchedule1Principles returns the official 10 Fair Information Principles from PIPEDA Schedule 1.
func GetSchedule1Principles() []Principle {
	return []Principle{
		{
			ID:          1,
			Name:        "1. Accountability",
			Weight:      10,
			Automated:   true,
			Statutory:   "Clause 4.1",
			Meaning:     "Designating a Privacy Officer and auditing third-party transfers.",
			Gate:        "Audits external API URLs & SDK calls to unvetted sub-processors; checks privacy_officer manifest.",
			Severity:    SeverityMedium,
			DefaultNote: "Data flows mapped; 3rd-party processors inventoried.",
		},
		{
			ID:          2,
			Name:        "2. Identifying Purposes",
			Weight:      10,
			Automated:   true,
			Statutory:   "Clause 4.2",
			Meaning:     "Specify why information is collected before or at collection.",
			Gate:        "Rejects database migration or schema without @privacy(purpose: '...') tags.",
			Severity:    SeverityHigh,
			DefaultNote: "Unannotated schema fields missing lawful purpose tags.",
		},
		{
			ID:          3,
			Name:        "3. Consent",
			Weight:      15,
			Automated:   true,
			Statutory:   "Clause 4.3",
			Meaning:     "Knowledge and meaningful consent before processing personal data.",
			Gate:        "Enforces conditional consent guard wrappers on tracking & marketing triggers.",
			Severity:    SeverityHigh,
			DefaultNote: "Third-party dispatch occurs without verified opt-in.",
		},
		{
			ID:          4,
			Name:        "4. Limiting Collection",
			Weight:      10,
			Automated:   true,
			Statutory:   "Clause 4.4",
			Meaning:     "Collect only what is necessary for declared purposes (Minimization).",
			Gate:        "Detects over-collection fields (e.g., requesting SIN or Health Card during standard registration).",
			Severity:    SeverityHigh,
			DefaultNote: "Excessive PII requested (health card/SIN during retail registration).",
		},
		{
			ID:          5,
			Name:        "5. Retention & Disposal",
			Weight:      10,
			Automated:   true,
			Statutory:   "Clause 4.5",
			Meaning:     "Keep personal info only as long as necessary, then destroy or anonymize.",
			Gate:        "Ensures DB models declare TTL indexes, expiration dates, or cron deletion cascades.",
			Severity:    SeverityMedium,
			DefaultNote: "Missing automated TTL disposal or anonymization triggers.",
		},
		{
			ID:          6,
			Name:        "6. Accuracy",
			Weight:      5,
			Automated:   true,
			Statutory:   "Clause 4.6",
			Meaning:     "Keep personal data accurate, complete, and up-to-date as necessary.",
			Gate:        "Validates regex & boundary validators (e.g. Luhn algorithm for Canadian SIN).",
			Severity:    SeverityLow,
			DefaultNote: "SIN validator with Luhn algorithm active on input boundary.",
		},
		{
			ID:          7,
			Name:        "7. Safeguards",
			Weight:      20,
			Automated:   true,
			Statutory:   "Clause 4.7",
			Meaning:     "Protect information against loss, unauthorized access, copying, disclosure.",
			Gate:        "Blocks raw PII flowing to stdout, server logs, or unencrypted storage.",
			Severity:    SeverityCritical,
			DefaultNote: "Unredacted personal data detected in application logging sinks.",
		},
		{
			ID:          8,
			Name:        "8. Openness",
			Weight:      10,
			Automated:   false,
			Statutory:   "Clause 4.8",
			Meaning:     "Make clear information about privacy policies readily available.",
			Gate:        "Checks presence of public privacy endpoints and versioned policy routes (/privacy).",
			Severity:    SeverityLow,
			DefaultNote: "Privacy policy route accessible at /legal/privacy or /privacy.",
		},
		{
			ID:          9,
			Name:        "9. Individual Access",
			Weight:      10,
			Automated:   true,
			Statutory:   "Clause 4.9",
			Meaning:     "Upon request, inform individuals of existence, use, disclosure, and provide data export (DSAR).",
			Gate:        "Audits user data export routines to ensure all stored tables (profile, billing, logs) are included.",
			Severity:    SeverityMedium,
			DefaultNote: "DSR export endpoint omits payment, audit, or consent history tables.",
		},
		{
			ID:          10,
			Name:        "10. Challenging Compliance",
			Weight:      10,
			Automated:   false,
			Statutory:   "Clause 4.10",
			Meaning:     "Address challenges and complaints concerning compliance.",
			Gate:        "Verifies privacy dispute contact points or ticketing integration routes.",
			Severity:    SeverityInfo,
			DefaultNote: "Privacy Officer dispute intake webhooks or forms configured.",
		},
	}
}
