package output

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/graph"
)

const (
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

func printText(r Report) error {
	sep := strings.Repeat("─", 72)

	fmt.Printf("\n%s%s k8scout v%s — Kubernetes Permission Audit%s\n", colorBold, colorCyan, r.Meta.Version, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, sep, colorReset)

	// ── Identity ─────────────────────────────────────────────────────────────
	fmt.Printf("%s▶ Identity%s\n", colorBold, colorReset)
	fmt.Printf("  Username  : %s\n", r.Identity.Username)
	fmt.Printf("  UID       : %s\n", r.Identity.UID)
	fmt.Printf("  Groups    : %s\n", strings.Join(r.Identity.Groups, ", "))
	fmt.Printf("  Namespace : %s\n\n", r.Identity.Namespace)

	// ── SSAR Spot Checks ─────────────────────────────────────────────────────
	fmt.Printf("%s▶ High-Risk Permission Checks (SSAR)%s\n", colorBold, colorReset)
	fmt.Printf("  %-40s %-20s %s\n", "Permission", "Namespace", "Result")
	fmt.Printf("  %s\n", strings.Repeat("-", 68))
	for _, c := range r.Permissions.SSARChecks {
		perm := c.Verb + " " + c.Resource
		if c.Subresource != "" {
			perm = c.Verb + " " + c.Resource + "/" + c.Subresource
		}
		ns := c.Namespace
		if ns == "" {
			ns = "(cluster)"
		}
		result := colorGreen + "✓ ALLOWED" + colorReset
		if !c.Allowed {
			result = "✗ denied"
		}
		fmt.Printf("  %-40s %-20s %s\n", perm, ns, result)
	}
	fmt.Println()

	// ── Cluster Summary ───────────────────────────────────────────────────────
	fmt.Printf("%s▶ Cluster Objects Discovered%s\n", colorBold, colorReset)
	fmt.Printf("  Namespaces           : %d\n", len(r.ClusterObjects.Namespaces))
	fmt.Printf("  ServiceAccounts      : %d\n", len(r.ClusterObjects.ServiceAccounts))
	fmt.Printf("  ClusterRoles         : %d\n", len(r.ClusterObjects.ClusterRoles))
	fmt.Printf("  ClusterRoleBindings  : %d\n", len(r.ClusterObjects.ClusterRoleBindings))
	fmt.Printf("  Roles                : %d\n", len(r.ClusterObjects.Roles))
	fmt.Printf("  RoleBindings         : %d\n", len(r.ClusterObjects.RoleBindings))
	fmt.Printf("  Workloads            : %d\n", len(r.ClusterObjects.Workloads))
	fmt.Printf("  Pods                 : %d\n", len(r.ClusterObjects.Pods))
	fmt.Printf("  Secrets (meta only)  : %d\n", len(r.ClusterObjects.SecretsMeta))
	fmt.Printf("  Nodes                : %d\n\n", len(r.ClusterObjects.Nodes))

	// ── Graph Summary ─────────────────────────────────────────────────────────
	if r.Graph != nil {
		fmt.Printf("%s▶ Permission Graph%s\n", colorBold, colorReset)
		fmt.Printf("  Nodes : %d\n", len(r.Graph.Nodes))
		fmt.Printf("  Edges : %d (including %d inferred)\n\n",
			len(r.Graph.Edges), countInferred(r.Graph))
	}

	// ── Risk Findings ─────────────────────────────────────────────────────────
	fmt.Printf("%s▶ Risk Findings (%d total)%s\n", colorBold, len(r.RiskFindings), colorReset)
	fmt.Printf("  %s\n", strings.Repeat("-", 68))

	for _, f := range r.RiskFindings {
		sev := severityColor(f.Severity)
		fmt.Printf("\n  %s[%s]%s %s%s%s\n", sev, f.Severity, colorReset, colorBold, f.Title, colorReset)
		fmt.Printf("  Rule: %-30s Score: %.1f/10\n", f.RuleID, f.Score)
		fmt.Printf("  %s\n", wordWrap(f.Description, 68, "  "))
		if len(f.Evidence) > 0 {
			fmt.Printf("  Evidence:\n")
			for _, e := range f.Evidence {
				fmt.Printf("    • %s\n", e)
			}
		}
		fmt.Printf("  %sMitigation:%s\n%s\n", colorGreen, colorReset,
			indent(f.Mitigation, "    "))
	}

	// ── AI Narrative ──────────────────────────────────────────────────────────
	if r.AINarrative != nil {
		fmt.Printf("\n%s%s\n%s▶ AI Risk Narrative (%s)%s\n%s%s\n",
			colorCyan, sep, colorBold, r.AINarrative.ModelUsed, colorReset, colorCyan, sep)
		fmt.Printf("\n%s\n\n", wordWrap(r.AINarrative.Summary, 72, ""))
		fmt.Printf("%sPrioritized Mitigations:%s\n", colorBold, colorReset)
		for _, m := range r.AINarrative.Mitigations {
			fmt.Printf("  %s\n", m)
		}
	}

	fmt.Printf("\n%s%s%s\n", colorCyan, sep, colorReset)
	fmt.Printf("Full JSON report: %s\n\n", r.Meta.ClusterServer)

	return nil
}

func printReviewerText(r ReviewerReport) error {
	sep := strings.Repeat("─", 72)

	fmt.Printf("\n%s%s k8scout v%s — Kubernetes Security Review (Reviewer Mode)%s\n",
		colorBold, colorCyan, r.Meta.Version, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, sep, colorReset)

	// ── Reviewer identity ─────────────────────────────────────────────────────
	fmt.Printf("%s▶ Reviewer Identity%s\n", colorBold, colorReset)
	fmt.Printf("  Running as : %s\n", r.ReviewerIdentity.Username)
	fmt.Printf("  Groups     : %s\n\n", strings.Join(r.ReviewerIdentity.Groups, ", "))

	// ── Summary ───────────────────────────────────────────────────────────────
	fmt.Printf("%s▶ Cluster Summary%s\n", colorBold, colorReset)
	fmt.Printf("  Namespaces           : %d\n", len(r.ClusterObjects.Namespaces))
	fmt.Printf("  ServiceAccounts      : %d\n", len(r.ClusterObjects.ServiceAccounts))
	fmt.Printf("  ClusterRoles         : %d\n", len(r.ClusterObjects.ClusterRoles))
	fmt.Printf("  ClusterRoleBindings  : %d\n", len(r.ClusterObjects.ClusterRoleBindings))
	fmt.Printf("  Roles                : %d\n", len(r.ClusterObjects.Roles))
	fmt.Printf("  RoleBindings         : %d\n", len(r.ClusterObjects.RoleBindings))
	fmt.Printf("  Workloads            : %d\n", len(r.ClusterObjects.Workloads))
	fmt.Printf("  Pods                 : %d\n", len(r.ClusterObjects.Pods))
	fmt.Printf("  Nodes                : %d\n\n", len(r.ClusterObjects.Nodes))

	// ── Risk summary ──────────────────────────────────────────────────────────
	fmt.Printf("%s▶ Risk Summary%s\n", colorBold, colorReset)
	fmt.Printf("  Identities analyzed       : %d\n", r.Summary.TotalIdentities)
	fmt.Printf("  %sCritical findings         : %d%s\n", colorRed+colorBold, r.Summary.CriticalFindings, colorReset)
	fmt.Printf("  %sHigh findings             : %d%s\n", colorRed, r.Summary.HighFindings, colorReset)
	fmt.Printf("  %sMedium findings           : %d%s\n", colorYellow, r.Summary.MediumFindings, colorReset)
	fmt.Printf("  Low/Info findings         : %d\n", r.Summary.LowFindings)
	fmt.Printf("  Pod security issues       : %d\n", r.Summary.PodSecurityIssues)
	fmt.Printf("  Privileged workloads      : %d\n", r.Summary.PrivilegedWorkloads)
	fmt.Printf("  cluster-admin bindings    : %d\n\n", r.Summary.ClusterAdminBindings)

	// ── Graph ─────────────────────────────────────────────────────────────────
	if r.Graph != nil {
		fmt.Printf("%s▶ Permission Graph%s\n", colorBold, colorReset)
		fmt.Printf("  Nodes : %d   Edges : %d\n\n", len(r.Graph.Nodes), len(r.Graph.Edges))
	}

	// ── Findings ──────────────────────────────────────────────────────────────
	fmt.Printf("%s▶ Risk Findings (%d total)%s\n", colorBold, len(r.RiskFindings), colorReset)
	fmt.Printf("  %s\n", strings.Repeat("-", 68))

	for _, f := range r.RiskFindings {
		sev := severityColor(f.Severity)
		fmt.Printf("\n  %s[%s]%s %s%s%s\n", sev, f.Severity, colorReset, colorBold, f.Title, colorReset)
		fmt.Printf("  Rule: %-38s Score: %.1f/10\n", f.RuleID, f.Score)
		fmt.Printf("  %s\n", wordWrap(f.Description, 68, "  "))
		if len(f.Evidence) > 0 {
			fmt.Printf("  Evidence:\n")
			for _, e := range f.Evidence {
				fmt.Printf("    • %s\n", e)
			}
		}
		fmt.Printf("  %sMitigation:%s\n%s\n", colorGreen, colorReset, indent(f.Mitigation, "    "))
	}

	fmt.Printf("\n%s%s%s\n", colorCyan, sep, colorReset)
	fmt.Printf("Full JSON report saved to output file.\n\n")
	return nil
}

func countInferred(g *graph.Graph) int {
	n := 0
	for _, e := range g.Edges {
		if e.Inferred {
			n++
		}
	}
	return n
}

func severityColor(s graph.Severity) string {
	switch s {
	case graph.SeverityCritical:
		return colorRed + colorBold
	case graph.SeverityHigh:
		return colorRed
	case graph.SeverityMedium:
		return colorYellow
	default:
		return colorGreen
	}
}

func wordWrap(s string, width int, prefix string) string {
	words := strings.Fields(s)
	var lines []string
	var line string
	for _, w := range words {
		if len(line)+len(w)+1 > width {
			lines = append(lines, prefix+line)
			line = w
		} else {
			if line != "" {
				line += " "
			}
			line += w
		}
	}
	if line != "" {
		lines = append(lines, prefix+line)
	}
	return strings.Join(lines, "\n")
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = prefix + strings.TrimSpace(l)
	}
	return strings.Join(lines, "\n")
}
