package output

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/graph"
)

// SARIF v2.1.0 output structures.

// SARIFLog is the top-level SARIF log object.
type SARIFLog struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool       SARIFTool       `json:"tool"`
	Results    []SARIFResult   `json:"results"`
	Taxonomies []SARIFTaxonomy `json:"taxonomies,omitempty"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver and its rules.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a detection rule.
type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription SARIFMessage      `json:"shortDescription"`
	FullDescription  *SARIFMessage     `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	DefaultConfig    *SARIFRuleConfig  `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFRuleConfig holds default severity/level for a rule.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFResult is a single finding/result.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage is a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes where a finding was detected.
type SARIFLocation struct {
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFLogicalLocation describes a logical location (namespace, resource, etc.).
type SARIFLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFTaxonomy describes a taxonomy (e.g., MITRE ATT&CK).
type SARIFTaxonomy struct {
	Name            string         `json:"name"`
	Version         string         `json:"version,omitempty"`
	InformationURI  string         `json:"informationUri,omitempty"`
	Taxa            []SARIFTaxon   `json:"taxa,omitempty"`
}

// SARIFTaxon is a single taxonomy entry.
type SARIFTaxon struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	ShortDescription SARIFMessage `json:"shortDescription,omitempty"`
}

// ConvertToSARIF converts k8scout findings into a SARIF v2.1.0 log.
func ConvertToSARIF(findings []graph.RiskFinding, meta MetaBlock) SARIFLog {
	ruleMap := make(map[string]int)
	var rules []SARIFRule
	var results []SARIFResult
	var allMITRE []string

	for _, f := range findings {
		ruleIdx, exists := ruleMap[f.RuleID]
		if !exists {
			ruleIdx = len(rules)
			ruleMap[f.RuleID] = ruleIdx
			rules = append(rules, SARIFRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: SARIFMessage{Text: f.Title},
				DefaultConfig: &SARIFRuleConfig{
					Level: severityToSARIFLevel(f.Severity),
				},
				Properties: map[string]interface{}{
					"security-severity": fmt.Sprintf("%.1f", f.Score),
				},
			})
		}

		result := SARIFResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIdx,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   SARIFMessage{Text: f.Description},
			Properties: map[string]interface{}{
				"score":      f.Score,
				"evidence":   f.Evidence,
				"mitigation": f.Mitigation,
			},
		}

		if len(f.MITREIDs) > 0 {
			result.Properties["mitre_ids"] = f.MITREIDs
			allMITRE = append(allMITRE, f.MITREIDs...)
		}

		if f.AttackPath != nil {
			pathSteps := make([]string, 0, len(f.AttackPath))
			for _, step := range f.AttackPath {
				if step.Edge != nil {
					pathSteps = append(pathSteps, fmt.Sprintf("[%s] → %s", step.Edge.Kind, step.Node.ID))
				} else {
					pathSteps = append(pathSteps, step.Node.ID)
				}
			}
			result.Properties["attack_path"] = pathSteps
			result.Properties["path_weight"] = f.PathWeight
		}

		for _, nodeID := range f.AffectedNodes {
			loc := parseSARIFLocation(nodeID)
			result.Locations = append(result.Locations, loc)
		}

		results = append(results, result)
	}

	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "k8scout",
				Version:        meta.Version,
				InformationURI: "https://github.com/k8scout/k8scout",
				Rules:          rules,
			},
		},
		Results: results,
	}

	// Add MITRE ATT&CK taxonomy if any findings reference it.
	mitreSet := make(map[string]bool)
	for _, id := range allMITRE {
		mitreSet[id] = true
	}
	if len(mitreSet) > 0 {
		var taxa []SARIFTaxon
		for id := range mitreSet {
			taxa = append(taxa, SARIFTaxon{
				ID:               id,
				ShortDescription: SARIFMessage{Text: "MITRE ATT&CK technique " + id},
			})
		}
		run.Taxonomies = append(run.Taxonomies, SARIFTaxonomy{
			Name:           "MITRE ATT&CK for Containers",
			Version:        "14.1",
			InformationURI: "https://attack.mitre.org/matrices/enterprise/containers/",
			Taxa:           taxa,
		})
	}

	return SARIFLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs:    []SARIFRun{run},
	}
}

func severityToSARIFLevel(s graph.Severity) string {
	switch s {
	case graph.SeverityCritical, graph.SeverityHigh:
		return "error"
	case graph.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func parseSARIFLocation(nodeID string) SARIFLocation {
	parts := strings.SplitN(nodeID, ":", 3)
	kind := "resource"
	name := nodeID
	fqn := nodeID

	if len(parts) >= 2 {
		kind = parts[0]
		name = parts[len(parts)-1]
	}

	return SARIFLocation{
		LogicalLocations: []SARIFLogicalLocation{
			{
				Name:               name,
				FullyQualifiedName: fqn,
				Kind:               kind,
			},
		},
	}
}
