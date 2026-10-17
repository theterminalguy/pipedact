package core

import "strings"

// Framework represents a compliance standard or privacy legislation.
type Framework string

const (
	FrameworkPIPEDA   Framework = "pipeda"
	FrameworkSOC2     Framework = "soc2"
	FrameworkISO27701 Framework = "iso27701"
	FrameworkLaw25    Framework = "law25"
	FrameworkAll      Framework = "all"
)

// ParseFramework normalizes string inputs into a Framework constant.
func ParseFramework(s string) Framework {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "soc2", "soc-2", "soc_2":
		return FrameworkSOC2
	case "iso", "iso27701", "iso-27701":
		return FrameworkISO27701
	case "law25", "law-25", "qc-law25", "quebec":
		return FrameworkLaw25
	case "all", "multi":
		return FrameworkAll
	default:
		return FrameworkPIPEDA
	}
}

// FrameworkMapping stores the statutory or criteria reference across compliance regimes.
type FrameworkMapping struct {
	PIPEDA   string `json:"pipeda,omitempty"`
	SOC2     string `json:"soc2,omitempty"`
	ISO27701 string `json:"iso27701,omitempty"`
	Law25    string `json:"law25,omitempty"`
}

// SOC2Criteria represents a Trust Services Criterion in SOC 2.
type SOC2Criteria struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Weight      int    `json:"weight"`
}

// GetSOC2Criteria returns the standard Trust Services Criteria for Security and Privacy.
func GetSOC2Criteria() []SOC2Criteria {
	return []SOC2Criteria{
		{
			ID:          "CC6.1",
			Category:    "Security (Common Criteria)",
			Name:        "Logical Access & Authentication Controls",
			Description: "Access to sensitive systems and data is restricted using strong authentication and access controls.",
			Weight:      15,
		},
		{
			ID:          "CC6.6",
			Category:    "Security (Common Criteria)",
			Name:        "Boundary Protection & Encryption-in-Transit",
			Description: "Transmission of data across external boundaries is safeguarded using strong cryptography.",
			Weight:      15,
		},
		{
			ID:          "CC6.7",
			Category:    "Security (Common Criteria)",
			Name:        "Data Transmission Safeguards",
			Description: "Sensitive data is protected from unauthorized disclosure during transmission and logging.",
			Weight:      15,
		},
		{
			ID:          "P1.1",
			Category:    "Privacy Trust Criteria",
			Name:        "Notice and Communication of Privacy Objectives",
			Description: "The entity provides notice of its privacy practices and identified purposes for data collection.",
			Weight:      10,
		},
		{
			ID:          "P2.1",
			Category:    "Privacy Trust Criteria",
			Name:        "Choice and Consent",
			Description: "Consent is obtained prior to collecting, using, or disclosing personal data.",
			Weight:      15,
		},
		{
			ID:          "P3.1",
			Category:    "Privacy Trust Criteria",
			Name:        "Collection Minimization",
			Description: "Personal information is limited to information necessary for the identified purposes.",
			Weight:      10,
		},
		{
			ID:          "P4.1",
			Category:    "Privacy Trust Criteria",
			Name:        "Retention, Disposal, and Purging",
			Description: "Personal information is retained only as long as necessary and disposed of securely.",
			Weight:      10,
		},
		{
			ID:          "P5.1",
			Category:    "Privacy Trust Criteria",
			Name:        "Data Subject Access & Portability",
			Description: "Individuals are provided access to their personal information for review and export.",
			Weight:      10,
		},
	}
}
