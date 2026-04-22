package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

// MaxAttackPathDepth is the maximum number of hops FindPaths will explore when
// searching for attack paths. Set to 12 to accommodate multi-level chains that
// traverse RBAC intermediaries (pod → SA → binding → role → target) and
// derived footholds (patch workload → SA₂ → SA₂'s targets).
const MaxAttackPathDepth = 12

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

	// EnumerationVantage — an SA/identity that gains broader visibility into the
	// cluster (list pods cluster-wide, list secrets, list nodes, etc.) compared
	// to the starting foothold. Reaching this node expands reconnaissance reach
	// without necessarily granting privileges.
	EnumerationVantage GoalKind = "enumeration_vantage"

	// CredentialAccess — a secret or token-bearing resource that yields fresh
	// credentials (service-account token secret, dockerconfigjson, TLS key, etc.)
	// even when values are not yet captured. Distinct from SecretAccess: this
	// fires on type/keys alone, modelling the credential-access intermediate goal.
	CredentialAccess GoalKind = "credential_access"

	// StrongerFoothold — a workload or pod that, if taken over, would put the
	// attacker in a materially better position than the current foothold
	// (different namespace, privileged execution context, cluster-scoped
	// workload like DaemonSet). Captures weak-foothold → strong-foothold pivots.
	StrongerFoothold GoalKind = "stronger_foothold"

	// AdmissionControl — a mutating webhook that intercepts pod-related resources.
	// Controlling this webhook allows injecting sidecars, replacing service accounts,
	// and modifying security contexts in all future workloads within its scope.
	AdmissionControl GoalKind = "admission_control"
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

	// High-visibility resource types for EnumerationVantage detection.
	vantageResources := map[string]float64{
		"pods":       6.5,
		"secrets":    7.0, // knowing secret names is already useful recon
		"namespaces": 5.5,
		"nodes":      6.5,
		"services":   5.0,
		"endpoints":  5.0,
	}

	var goals []GoalNode

	for i := range g.Nodes {
		n := &g.Nodes[i]

		// ── EnumerationVantage (resource:<name>[:ns]) ─────────────────────────
		// Fires before Kind-based cases because resource nodes share NodeKind
		// values with concrete objects (e.g. resource:pods has Kind=KindPod).
		if strings.HasPrefix(n.ID, "resource:") {
			// resource:<res> or resource:<ns>:<res>
			parts := strings.Split(strings.TrimPrefix(n.ID, "resource:"), ":")
			resName := parts[len(parts)-1]
			if score, ok := vantageResources[resName]; ok {
				scope := "cluster-wide"
				if len(parts) == 2 {
					scope = "namespace " + parts[0]
				}
				goals = append(goals, GoalNode{
					NodeID:      n.ID,
					GoalKind:    EnumerationVantage,
					Description: fmt.Sprintf("List/get %s (%s) — reconnaissance vantage point", resName, scope),
					BaseScore:   score,
				})
			}
			continue
		}

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
			secType := n.Metadata["type"]
			isSAToken := secType == "kubernetes.io/service-account-token"
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
			} else if credKind := credentialSecretKind(secType); credKind != "" {
				// CredentialAccess: typed credential secret without captured values.
				goals = append(goals, GoalNode{
					NodeID:      n.ID,
					GoalKind:    CredentialAccess,
					Description: fmt.Sprintf("Secret %s/%s — %s (credential material)", n.Namespace, n.Name, credKind),
					BaseScore:   7.0,
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

		// ── CloudIdentity ───────────────────────────────────────────────────
		// Cloud IAM identity nodes are always high-value targets.
		case n.Kind == KindCloudIdentity:
			provider := n.Metadata["cloud_provider"]
			cloudRole := n.Metadata["cloud_role"]
			goals = append(goals, GoalNode{
				NodeID:   n.ID,
				GoalKind: IdentityTakeover,
				Description: fmt.Sprintf(
					"Cloud IAM identity (%s) %q — cloud-plane access",
					provider, cloudRole,
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
			// Triggers on: privileged containers, hostPID/hostNetwork, dangerous Linux
			// capabilities (SYS_ADMIN etc.), or sensitive hostPath mounts.
			if workloadIsTakeoverTarget(wl) {
				goals = append(goals, GoalNode{
					NodeID:      n.ID,
					GoalKind:    WorkloadTakeover,
					Description: fmt.Sprintf("Workload %s/%s: %s", n.Namespace, n.Name, workloadTakeoverReason(wl)),
					BaseScore:   workloadTakeoverScore(wl),
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

			// StrongerFoothold: workloads that materially improve attacker position
			// without already qualifying as WorkloadTakeover. Triggers on DaemonSets
			// (cluster-scoped reach) or workloads in control-plane namespaces.
			if !workloadIsTakeoverTarget(wl) && isStrongerFootholdWorkload(wl) {
				goals = append(goals, GoalNode{
					NodeID:      n.ID,
					GoalKind:    StrongerFoothold,
					Description: fmt.Sprintf("Workload %s/%s: %s", n.Namespace, n.Name, strongerFootholdReason(wl)),
					BaseScore:   6.5,
				})
			}

		// ── AdmissionControl ─────────────────────────────────────────────────
		// Mutating webhooks that intercept pod-related resources.
		case n.Kind == KindWebhook && n.Metadata["webhook_kind"] == "Mutating" && n.Metadata["intercepts_pods"] == "true":
			goals = append(goals, GoalNode{
				NodeID:      n.ID,
				GoalKind:    AdmissionControl,
				Description: fmt.Sprintf("Mutating webhook %q intercepts pod creation — controls future workload specs", n.Name),
				BaseScore:   8.5,
			})
		}
	}

	return goals
}

// workloadIsTakeoverTarget returns true if the workload has any property that
// makes it a high-value target for container escape or host compromise.
func workloadIsTakeoverTarget(wl kube.WorkloadInfo) bool {
	return len(wl.PrivilegedContainers) > 0 ||
		wl.HostPID || wl.HostNetwork || wl.HostIPC ||
		len(wl.DangerousCapabilities) > 0 ||
		hasWritableHostPaths(wl)
}

// hasWritableHostPaths returns true if any hostPath mount is NOT in ReadOnlyHostPaths.
func hasWritableHostPaths(wl kube.WorkloadInfo) bool {
	if len(wl.HostPathMounts) == 0 {
		return false
	}
	roSet := make(map[string]bool, len(wl.ReadOnlyHostPaths))
	for _, p := range wl.ReadOnlyHostPaths {
		roSet[p] = true
	}
	for _, p := range wl.HostPathMounts {
		if !roSet[p] {
			return true
		}
	}
	return false
}

// workloadTakeoverScore returns the base risk score for a WorkloadTakeover goal.
// Privileged containers and hostPID/hostNetwork score highest (direct escape);
// dangerous capabilities and hostPath mounts are slightly lower.
func workloadTakeoverScore(wl kube.WorkloadInfo) float64 {
	if len(wl.PrivilegedContainers) > 0 {
		return 9.0
	}
	if wl.HostPID || wl.HostNetwork || wl.HostIPC {
		return 8.5
	}
	if len(wl.DangerousCapabilities) > 0 {
		return 8.0
	}
	// hostPath mount — writable is high-risk, read-only is lower
	if hasWritableHostPaths(wl) {
		return 7.5
	}
	return 5.0 // read-only hostPath only
}

// credentialSecretKind maps a Kubernetes secret type to a short human label
// when the type represents credential material. Returns "" when the type is
// not credential-bearing.
func credentialSecretKind(secType string) string {
	switch secType {
	case "kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg":
		return "image-pull credential"
	case "kubernetes.io/tls":
		return "TLS key + cert"
	case "kubernetes.io/ssh-auth":
		return "SSH private key"
	case "kubernetes.io/basic-auth":
		return "username/password"
	case "bootstrap.kubernetes.io/token":
		return "cluster bootstrap token"
	}
	return ""
}

// controlPlaneNamespaces are namespaces where workload takeover yields outsized
// lateral reach even without privileged containers.
var controlPlaneNamespaces = map[string]bool{
	"kube-system":          true,
	"kube-public":          true,
	"kube-node-lease":      true,
	"openshift-operators":  true,
	"openshift-system":     true,
	"cert-manager":         true,
	"ingress-nginx":        true,
	"istio-system":         true,
	"linkerd":              true,
	"gatekeeper-system":    true,
	"kyverno":              true,
}

// isStrongerFootholdWorkload returns true if the workload represents a
// materially improved foothold: DaemonSet reach or control-plane namespace.
func isStrongerFootholdWorkload(wl kube.WorkloadInfo) bool {
	if wl.Kind == "DaemonSet" {
		return true
	}
	if controlPlaneNamespaces[wl.Namespace] {
		return true
	}
	return false
}

// strongerFootholdReason explains why a workload is a stronger foothold.
func strongerFootholdReason(wl kube.WorkloadInfo) string {
	var parts []string
	if wl.Kind == "DaemonSet" {
		parts = append(parts, "DaemonSet (runs on every node)")
	}
	if controlPlaneNamespaces[wl.Namespace] {
		parts = append(parts, fmt.Sprintf("control-plane namespace %q", wl.Namespace))
	}
	return strings.Join(parts, "; ")
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
	if wl.HostIPC {
		parts = append(parts, "hostIPC=true")
	}
	if len(wl.DangerousCapabilities) > 0 {
		parts = append(parts, fmt.Sprintf("dangerous caps: [%s]", strings.Join(wl.DangerousCapabilities, ", ")))
	}
	if len(wl.HostPathMounts) > 0 {
		parts = append(parts, fmt.Sprintf("hostPath mounts: [%s]", strings.Join(wl.HostPathMounts, ", ")))
	}
	return strings.Join(parts, "; ")
}
