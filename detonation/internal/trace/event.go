// SPDX-License-Identifier: AGPL-3.0-or-later
package trace

type TraceEvent struct {
	Phase     string                 `json:"phase"`
	Category  string                 `json:"category"`
	Operation string                 `json:"operation"`
	PID       int                    `json:"pid"`
	Binary    string                 `json:"binary"`
	Detail    map[string]interface{} `json:"detail"`
	Timestamp string                 `json:"timestamp,omitempty"`
}

type DynFinding struct {
	RuleID     string `json:"rule_id"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	File       string `json:"file,omitempty"`
	Line       *int   `json:"line,omitempty"`
	Evidence   string `json:"evidence"`
}
