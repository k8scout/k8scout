package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

// MaxAttackPathDepth is the maximum number of hops FindPaths will explore when
// searching for attack paths. Configurable here so A1-3 and future callers share
// the same default without re-defining it.
const MaxAttackPathDepth = 5

// MaxPathsPerGoal caps the number of paths emitted per goal node to prevent
// report flooding on densely connected graphs.
const MaxPathsPerGoal = 50

// GoalKind classifies the type of high-value target a graph node represents.
// Uses the same string-enum pattern as NodeKind and EdgeKind in this package.
type GoalKind string

const (
	// ClusterAdmin — a ClusterRoleBinding that grants cluster-admin.
	// Reaching this node means full cluster control.
	ClusterAdmin GoalKind = "cluster_admin"

	// NodeExec — a Kubernetes node.
	// Reaching this node means host-level code execution.
	NodeExec GoalKind = "node_exec"

	// SecretAccess — a secret whose values have been captured or which is a
	// service-account token (immediately usable for impersonation).
	SecretAccess GoalKind = "secret_access"

	// IdentityTakeover — a ServiceAccount annotated with a cloud IAM identity
	// (IRSA, Azure Workload Identity, GKE Workload Identity).
	// Reaching this node means acquiring a cloud-plane identity.
	IdentityTakeover GoalKind = "identity_takeover"

	// WorkloadTakeover — a workload running with weakened isolation
	// (privileged containers, hostPID, or hostNetwork).
	// Reaching this node enables container escape to the host.
	WorkloadTakeover GoalKind = "workload_takeover"

	// CloudEscalation — a workload that mounts a projected service-account token
	// scoped to a cloud audience (e.g. STS, Azure AD).
	// Distinct from IdentityTakeover: this detects the token injection mechanism
	// rather than the SA annotation.
	CloudEscalation GoalKind = "cloud_escalation"
)

// GoalNode pairs a graph node with its high-value classification.
type GoalNode struct {
	NodeID      string
	GoalKind    GoalKind
	Description string  // short human-readable justification
	BaseScore   float64 // pre-adjustment risk score (0–10)
}

// HighValueTargets scans g for nodes that represent meaningful attack destinations
// and returns them as GoalNodes. It performs no Kubernetes API calls and does not
// modify the graph.
//
// The function makes one pass over g.Nodes; pre-built lookup maps from r provide
// O(1) access to the raw metadata that is not stored in node Metadata fields.
func HighValueTargets(g *Graph, r *kube.EnumerationResult) []GoalNode {
	// Pre-build lookup maps so the node pass stays O(nodes).

	// crbMap: CRB name → BindingInfo (for RoleRef lookup).
	crbMap := make(map[string]kube.BindingInfo, len(r.ClusterObjects.ClusterRoleBindings))
	for _, crb := range r.ClusterObjects.ClusterRoleBindings {
		crbMap[crb.Name] = crb
	}

	// wlMap: "workload:<ns>:<name>" → WorkloadInfo (for PrivilegedContainers, HostPID, etc.).
	wlMap := make(map[string]kube.WorkloadInfo, len(r.ClusterObjects.Workloads))
	for _, wl := range r.ClusterObjects.Workloads {
		wlMap["workload:"+wl.Namespace+":"+wl.Name] = wl
	}

	var goals []GoalNode

	for i := range g.Nodes {
		n := &g.Nodes[i]

		switch {

		// ── ClusterAdmin ──────────────────────────────────────────────────────
		// Two detection patterns:
		// (a) crb:<name> nodes whose RoleRef is cluster-admin — detected via raw binding data.
		// (b) clusterrole:cluster-admin — targeted directly by inferred edges from
		//     emitInferredEdges (create bindings, escalate, bind permissions).
		//     This entry ensures multi-hop traversal can reach it.
		case n.ID == "clusterrole:cluster-admin":
			goals = append(goals, GoalNode{
				NodeID:      n.ID,
				GoalKind:    ClusterAdmin,
				Description: "clusterrole:cluster-admin — full cluster control via built-in cluster-admin role",
				BaseScore:   10.0,
			})

		case strings.HasPrefix(n.ID, "crb:"):
			name := strings.TrimPrefix(n.ID, "crb:")
			if crb, ok := crbMap[name]; ok && crb.RoleRef.Name == "cluster-admin" {
				goals = append(goals, GoalNode{
					NodeID:      n.ID,
					GoalKind:    ClusterAdmin,
					Description: fmt.Sprintf("ClusterRoleBinding %q grants cluster-admin", name),
					BaseScore:   10.0,
				})
			}

		// ── NodeExec ─────────────────────────────────────────────────────────
		// Every node:<name> node — host-level access.
		case n.Kind == KindNode:
			goals = append(goals, GoalNode{
				NodeID:      n.ID,
				GoalKind:    NodeExec,
				Description: fmt.Sprintf("Kubernetes node %q — host-level code execution", n.Name),
				BaseScore:   9.0,
			})

		// ── SecretAccess ─────────────────────────────────────────────────────
		// Secrets with captured values or SA-token type.
		case n.Kind == KindSecret:
			capturedValues := n.Metadata["has_captured_values"] == "true"
			isSAToken := n.Metadata["type"] == "kubernetes.io/service-account-token"
			if capturedValues || isSAToken {
				reason := "contains captured secret values"
				if isSAToken && !capturedValues {
					reason = "service-account token (usable for impersonation)"
				} else if isSAToken && capturedValues {
					reason = "service-account token with captured values"
				}
				goals = append(goals, GoalNode{
					NodeID:      n.ID,
					GoalKind:    SecretAccess,
					Description: fmt.Sprintf("Secret %s/%s — %s", n.Namespace, n.Name, reason),
					BaseScore:   8.5,
				})
			}

		// ── IdentityTakeover ─────────────────────────────────────────────────
		// SA nodes annotated with a cloud IAM identity.
		case n.Kind == KindServiceAccount && n.Metadata["cloud_role"] != "":
			provider := n.Metadata["cloud_provider"]
			cloudRole := n.Metadata["cloud_role"]
			goals = append(goals, GoalNode{
				NodeID:   n.ID,
				GoalKind: IdentityTakeover,
				Description: fmt.Sprintf(
					"ServiceAccount %s/%s carries %s cloud identity %q",
					n.Namespace, n.Name, provider, cloudRole,
				),
				BaseScore: 9.5,
			})

		// ── WorkloadTakeover + CloudEscalation ───────────────────────────────
		// Workload nodes are checked for both conditions in one map lookup.
		case n.Kind == KindWorkload:
			wl, ok := wlMap[n.ID]
			if !ok {
				break
			}

			// WorkloadTakeover: weakened isolation allows container escape.
			if len(wl.PrivilegedContainers) > 0 || wl.HostPID || wl.HostNetwork {
				goals = append(goals, GoalNode{
					NodeID:      n.ID,
					GoalKind:    WorkloadTakeover,
					Description: fmt.Sprintf("Workload %s/%s: %s", n.Namespace, n.Name, workloadTakeoverReason(wl)),
					BaseScore:   8.5,
				})
			}

			// CloudEscalation: projected token with non-default cloud audience.
			for _, vol := range wl.Volumes {
				if vol.Audience != "" {
					goals = append(goals, GoalNode{
						NodeID:   n.ID,
						GoalKind: CloudEscalation,
						Description: fmt.Sprintf(
							"Workload %s/%s mounts projected token for cloud audience %q",
							n.Namespace, n.Name, vol.Audience,
						),
						BaseScore: 9.0,
					})
					break // one CloudEscalation entry per workload
				}
			}
		}
	}

	return goals
}

// workloadTakeoverReason builds a short summary of why a workload qualifies as
// a WorkloadTakeover target.
func workloadTakeoverReason(wl kube.WorkloadInfo) string {
	var parts []string
	if len(wl.PrivilegedContainers) > 0 {
		parts = append(parts, fmt.Sprintf("privileged containers: [%s]", strings.Join(wl.PrivilegedContainers, ", ")))
	}
	if wl.HostPID {
		parts = append(parts, "hostPID=true")
	}
	if wl.HostNetwork {
		parts = append(parts, "hostNetwork=true")
	}
	return strings.Join(parts, "; ")
}
