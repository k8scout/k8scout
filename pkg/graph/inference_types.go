package graph

import (
	"github.com/hac01/k8scout/pkg/kube"
)

// Severity levels for risk findings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// RiskFinding represents a single identified risk, with evidence and mitigation.
type RiskFinding struct {
	ID            string   `json:"id"`
	RuleID        string   `json:"rule_id"`
	Severity      Severity `json:"severity"`
	Score         float64  `json:"score"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Evidence      []string `json:"evidence,omitempty"`
	Mitigation    string   `json:"mitigation"`
	AffectedNodes []string `json:"affected_nodes,omitempty"`
	// MITREIDs maps this finding to MITRE ATT&CK for Containers technique IDs.
	MITREIDs []string `json:"mitre_ids,omitempty"`
	// AttackPath is the ordered sequence of graph steps for multi-hop findings.
	// Nil for single-step (non-traversal) findings.
	AttackPath []PathStep `json:"attack_path,omitempty"`
	// PathWeight is the cumulative attacker-effort weight of the attack path.
	// Lower weight = easier/more realistic path. Zero for non-traversal findings.
	PathWeight float64 `json:"path_weight,omitempty"`
	// AttackStages describes the progressive escalation stages in a multi-hop path.
	// Each stage represents a distinct level of access gained during the attack.
	// Nil for single-step findings.
	AttackStages []AttackStage `json:"attack_stages,omitempty"`
	// ChainShape classifies the path's structural realism for the UI:
	// "full_chain", "foothold_start", "bridge_start", or "abstract_start".
	// Empty for single-step findings.
	ChainShape string `json:"chain_shape,omitempty"`
}

// ChainShapeFromPathShape converts a PathShape into the string label persisted
// on RiskFinding.ChainShape.
func ChainShapeFromPathShape(shape PathShape) string {
	switch {
	case shape.FullChain:
		return "full_chain"
	case shape.StartRole == RoleFoothold:
		return "foothold_start"
	case shape.StartRole == RoleBridge:
		return "bridge_start"
	default:
		return "abstract_start"
	}
}

// AttackStage describes one stage of a progressive attack chain.
type AttackStage struct {
	Stage       int    `json:"stage"`       // 0 = initial foothold, 1 = first pivot, 2+ = derived access
	Label       string `json:"label"`       // e.g. "Initial Foothold", "Workload Takeover", "Credential Theft"
	NodeID      string `json:"node_id"`     // the node that anchors this stage
	Description string `json:"description"` // what access is gained at this stage
}

// inferenceRule defines a single detection rule applied to the graph + raw data.
type inferenceRule struct {
	RuleID     string
	Severity   Severity
	Score      float64
	Title      string
	Mitigation string
	// MITREIDs maps this rule to MITRE ATT&CK for Containers technique IDs.
	MITREIDs []string
	// check returns (description, evidence, affectedNodeIDs) or ("", nil, nil) if rule doesn't fire.
	check func(g *Graph, result *kube.EnumerationResult) (desc string, evidence []string, nodes []string)
}

// dangerousPerm describes a verb+resource combination that is high-risk for any SA that holds it.
type dangerousPerm struct {
	verb, resource string
	ruleID         string
	title          string
	severity       Severity
	score          float64
	desc           string
	mitigation     string
}
