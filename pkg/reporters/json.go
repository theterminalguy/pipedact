package reporters

import (
	"encoding/json"

	"github.com/theterminalguy/pipedact/pkg/core"
)

// GenerateJSON produces formatted JSON representation of the audit result.
func GenerateJSON(result *core.AuditResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
