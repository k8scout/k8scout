// Package output handles JSON and text rendering of enumeration reports.
package output

import (
	"time"

	"github.com/hac01/k8scout/pkg/graph"
	"github.com/hac01/k8scout/pkg/kube"
)

// Report is the top-level structure written to the JSON output file.
type Report struct {
	Meta           MetaBlock              `json:"meta"`
	Identity       kube.IdentityInfo      `json:"identity"`
	Permissions    kube.PermissionsInfo   `json:"permissions"`
	ClusterObjects kube.ClusterObjects    `json:"cluster_objects"`
	Graph          *graph.Graph           `json:"graph"`
	RiskFindings   []graph.RiskFinding    `json:"risk_findings"`
	AINarrative    *AINarrative           `json:"ai_narrative,omitempty"`
	AuditFootprint []kube.AuditEntry      `json:"audit_footprint,omitempty"`
}

// MetaBlock contains tool and run metadata.
type MetaBlock struct {
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	Timestamp     time.Time `json:"timestamp"`
	ClusterServer string    `json:"cluster,omitempty"`
	TimeoutSecs   int       `json:"timeout_s"`
	Stealth       bool      `json:"stealth,omitempty"`
}

// AINarrative holds the OpenAI-generated risk narrative.
type AINarrative struct {
	Summary     string   `json:"summary"`
	Mitigations []string `json:"mitigations"`
	ModelUsed   string   `json:"model_used"`
}

// MetaInfo constructs a MetaBlock.
func MetaInfo(version string, timeoutSecs int, serverVersion string) MetaBlock {
	return MetaBlock{
		Tool:          "k8scout",
		Version:       version,
		Timestamp:     time.Now().UTC(),
		ClusterServer: serverVersion,
		TimeoutSecs:   timeoutSecs,
	}
}

// ReviewerReport is the top-level output structure for reviewer mode —
// a full cluster security assessment from an external read-only perspective.
type ReviewerReport struct {
	Meta              MetaBlock                   `json:"meta"`
	ReviewerIdentity  kube.IdentityInfo           `json:"reviewer_identity"`
	ClusterObjects    kube.ClusterObjects         `json:"cluster_objects"`
	AllIdentityPerms  []kube.IdentityPermissions  `json:"all_identity_permissions"`
	PodSecurityIssues []kube.PodSecurityIssue     `json:"pod_security_issues"`
	Graph             *graph.Graph                `json:"graph"`
	RiskFindings      []graph.RiskFinding         `json:"risk_findings"`
	Summary           ReviewerSummary             `json:"summary"`
	AINarrative       *AINarrative                `json:"ai_narrative,omitempty"`
}

// ReviewerSummary provides aggregate statistics for the security review.
type ReviewerSummary struct {
	TotalIdentities      int `json:"total_identities"`
	CriticalFindings     int `json:"critical_findings"`
	HighFindings         int `json:"high_findings"`
	MediumFindings       int `json:"medium_findings"`
	LowFindings          int `json:"low_findings"`
	PodSecurityIssues    int `json:"pod_security_issue_count"`
	PrivilegedWorkloads  int `json:"privileged_workloads"`
	ClusterAdminBindings int `json:"cluster_admin_bindings"`
}

// BuildReviewerSummary assembles the summary block from reviewer findings.
func BuildReviewerSummary(
	findings []graph.RiskFinding,
	allPerms []kube.IdentityPermissions,
	podIssues []kube.PodSecurityIssue,
	clusterObjects kube.ClusterObjects,
) ReviewerSummary {
	s := ReviewerSummary{
		TotalIdentities:   len(allPerms),
		PodSecurityIssues: len(podIssues),
	}
	for _, f := range findings {
		switch f.Severity {
		case graph.SeverityCritical:
			s.CriticalFindings++
		case graph.SeverityHigh:
			s.HighFindings++
		case graph.SeverityMedium:
			s.MediumFindings++
		default:
			s.LowFindings++
		}
		if f.RuleID == "PRIVESC-CLUSTER-ADMIN-BINDING" || f.RuleID == "REVIEW-CLUSTER-ADMIN-BINDING" {
			s.ClusterAdminBindings++
		}
	}
	for _, wl := range clusterObjects.Workloads {
		if len(wl.PrivilegedContainers) > 0 {
			s.PrivilegedWorkloads++
		}
	}
	return s
}
