package graph

import (
	"fmt"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)

// ── Active enrichment: derived SSRR edges ───────────────────────────────────

// emitDerivedSSRREdges creates concrete capability edges for ServiceAccounts
// whose permissions were discovered via impersonated SSRR during active
// enrichment. This is the bridge that turns "we can become SA X" into
// "SA X can read secrets / patch workloads / escalate to cluster-admin."
//
// For each derived identity with enriched SSRR data, it creates the same
// kind of edges that buildConcreteIdentityEdges creates for the current
// identity — but sourced from the derived SA node instead.
func emitDerivedSSRREdges(g *Graph, result *kube.EnumerationResult, log *zap.Logger) {
	if len(result.DerivedIdentities) == 0 {
		return
	}

	// Build node lookup from current graph.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for _, di := range result.DerivedIdentities {
		saID := saNodeID(di.Namespace, di.SAName)

		// Ensure the SA node exists in the graph.
		if nodeByID[saID] == nil {
			n := Node{
				ID:        saID,
				Kind:      KindServiceAccount,
				Name:      di.SAName,
				Namespace: di.Namespace,
				Metadata: map[string]string{
					"enriched":        "true",
					"derived_via":     di.How,
				},
			}
			g.Nodes = append(g.Nodes, n)
			nodeByID[saID] = &g.Nodes[len(g.Nodes)-1]
		} else {
			// Mark existing node as enriched.
			n := nodeByID[saID]
			if n.Metadata == nil {
				n.Metadata = map[string]string{}
			}
			n.Metadata["enriched"] = "true"
		}

		addEdge := func(to string, kind EdgeKind, reason string) {
			if nodeByID[to] == nil {
				return
			}
			key := saID + "|" + string(kind) + "|" + to
			if seen[key] {
				return
			}
			seen[key] = true
			newEdges = append(newEdges, Edge{
				From:   saID,
				To:     to,
				Kind:   kind,
				Reason: reason,
			})
			count++
		}

		for ns, rules := range di.SSRRRules {
			for _, rule := range rules {
				// Patch workloads → concrete workload edges.
				for _, wlRes := range []string{"deployments", "daemonsets", "statefulsets"} {
					if containsAny(rule.Verbs, "patch", "update", "*") && containsAny(rule.Resources, wlRes, "*") {
						for _, wl := range result.ClusterObjects.Workloads {
							if wl.Namespace == ns {
								addEdge("workload:"+wl.Namespace+":"+wl.Name, EdgeCanPatch,
									fmt.Sprintf("enriched SSRR: %s can patch %s in %s", di.SAName, wlRes, ns))
							}
						}
					}
				}

				// Get/List secrets → concrete secret edges.
				if containsAny(rule.Verbs, "get", "*") && containsAny(rule.Resources, "secrets", "*") {
					for _, sm := range result.ClusterObjects.SecretsMeta {
						if sm.Namespace == ns {
							addEdge("secret:"+sm.Namespace+":"+sm.Name, EdgeCanGet,
								fmt.Sprintf("enriched SSRR: %s can get secrets in %s", di.SAName, ns))
						}
					}
				} else if containsAny(rule.Verbs, "list", "*") && containsAny(rule.Resources, "secrets", "*") {
					for _, sm := range result.ClusterObjects.SecretsMeta {
						if sm.Namespace == ns {
							addEdge("secret:"+sm.Namespace+":"+sm.Name, EdgeCanList,
								fmt.Sprintf("enriched SSRR: %s can list secrets in %s", di.SAName, ns))
						}
					}
				}

				// Exec into pods.
				if containsAny(rule.Verbs, "create", "*") && containsAny(rule.Resources, "pods/exec", "*") {
					for _, pod := range result.ClusterObjects.Pods {
						if pod.Namespace == ns {
							addEdge("pod:"+pod.Namespace+":"+pod.Name, EdgeCanExec,
								fmt.Sprintf("enriched SSRR: %s can exec in %s", di.SAName, ns))
						}
					}
				}

				// Create pods → SA takeover + node scheduling.
				if containsAny(rule.Verbs, "create", "*") && containsAny(rule.Resources, "pods", "*") &&
					!containsAny(rule.Resources, "pods/exec") {
					for _, sa := range result.ClusterObjects.ServiceAccounts {
						if sa.Namespace == ns {
							addEdge(saNodeID(sa.Namespace, sa.Name), EdgeCanCreate,
								fmt.Sprintf("enriched SSRR: %s can create pods as SA in %s", di.SAName, ns))
						}
					}
				}

				// Impersonate SAs.
				if containsAny(rule.Verbs, "impersonate", "*") &&
					containsAny(rule.Resources, "serviceaccounts", "users", "*") {
					for _, sa := range result.ClusterObjects.ServiceAccounts {
						if sa.Namespace == ns || ns == "" {
							addEdge(saNodeID(sa.Namespace, sa.Name), EdgeCanImpersonate,
								fmt.Sprintf("enriched SSRR: %s can impersonate SAs", di.SAName))
						}
					}
				}

				// Create/patch CRBs → cluster-admin escalation.
				if containsAny(rule.Verbs, "create", "patch", "*") &&
					containsAny(rule.Resources, "clusterrolebindings", "*") {
					addEdge("clusterrole:cluster-admin", EdgeCanCreate,
						fmt.Sprintf("enriched SSRR: %s can create/patch CRBs", di.SAName))
				}

				// Escalate/bind clusterroles → cluster-admin.
				if containsAny(rule.Verbs, "escalate", "bind", "*") &&
					containsAny(rule.Resources, "clusterroles", "*") {
					addEdge("clusterrole:cluster-admin", EdgeCanEscalate,
						fmt.Sprintf("enriched SSRR: %s can escalate clusterroles", di.SAName))
				}

				// Get/List nodes.
				if containsAny(rule.Verbs, "get", "list", "*") && containsAny(rule.Resources, "nodes", "*") {
					for _, n := range result.ClusterObjects.Nodes {
						addEdge("node:"+n.Name, EdgeCanList,
							fmt.Sprintf("enriched SSRR: %s can access nodes", di.SAName))
					}
				}
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("derived SSRR capability edges emitted",
			zap.Int("edges", count),
			zap.Int("derived_identities", len(result.DerivedIdentities)))
	}
}

// ── Derived foothold edges ──────────────────────────────────────────────────

// emitDerivedFootholdEdges models workload takeover as a path enrichment step.
// When the current identity (or foothold pod) can patch/create workloads or
// exec into pods, the target workload's SA becomes a "derived identity" whose
// capabilities are reachable. This function adds edges that connect takeover
// targets to their SA's downstream capabilities, enabling chains like:
//
//	pod(foothold) → SA → identity → [can_patch] → workload → [runs_as] → SA₂ → [can_get] → secret
//
// Without this pass, the chain stops at SA₂ when SA₂ has no direct capability
// edges (because RBAC objects may not be enumerated or the transitive pass
// didn't find bindings for SA₂).
//
// The derived enrichment also handles:
//   - Exec-reachable pods: exec into pod → that pod's SA capabilities
//   - Token-steal chains: secret(SA-token) → authenticates_as → SA → SA capabilities
func emitDerivedFootholdEdges(g *Graph, result *kube.EnumerationResult, log *zap.Logger) {
	// Build outbound index from current edge list.
	outbound := make(map[string][]int)
	for i := range g.Edges {
		outbound[g.Edges[i].From] = append(outbound[g.Edges[i].From], i)
	}

	// Node lookup.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	identityID := "identity:" + result.Identity.Username

	// Collect all SAs that the current identity can "become" through workload
	// takeover (patch/create) or exec. These are "derived SAs" — one pivot away.
	derivedSAs := make(map[string]string) // saID → reason

	// 1. Patching a workload → the workload's SA becomes a derived identity.
	for _, ei := range outbound[identityID] {
		e := &g.Edges[ei]
		if e.Kind != EdgeCanPatch && e.Kind != EdgeCanCreate {
			continue
		}
		wlNode := nodeByID[e.To]
		if wlNode == nil || (wlNode.Kind != KindWorkload && wlNode.Kind != KindPod) {
			continue
		}
		// Follow workload → [runs_as] → SA
		for _, wi := range outbound[e.To] {
			we := &g.Edges[wi]
			if we.Kind != EdgeRunsAs {
				continue
			}
			saNode := nodeByID[we.To]
			if saNode != nil && saNode.Kind == KindServiceAccount {
				derivedSAs[we.To] = fmt.Sprintf("workload takeover via %s %s", e.Kind, e.To)
			}
		}
	}

	// Also check from foothold pod if in-cluster.
	if result.Identity.InCluster && result.Identity.PodName != "" {
		footholdPodID := "pod:" + result.Identity.Namespace + ":" + result.Identity.PodName
		for _, ei := range outbound[footholdPodID] {
			e := &g.Edges[ei]
			if e.Kind != EdgeCanPatch && e.Kind != EdgeCanCreate {
				continue
			}
			wlNode := nodeByID[e.To]
			if wlNode == nil || (wlNode.Kind != KindWorkload && wlNode.Kind != KindPod) {
				continue
			}
			for _, wi := range outbound[e.To] {
				we := &g.Edges[wi]
				if we.Kind != EdgeRunsAs {
					continue
				}
				saNode := nodeByID[we.To]
				if saNode != nil && saNode.Kind == KindServiceAccount {
					if _, ok := derivedSAs[we.To]; !ok {
						derivedSAs[we.To] = fmt.Sprintf("workload takeover via %s %s (from foothold)", e.Kind, e.To)
					}
				}
			}
		}
	}

	// 2. Exec into a pod → that pod's SA becomes a derived identity.
	execSources := []string{identityID}
	if result.Identity.InCluster && result.Identity.PodName != "" {
		execSources = append(execSources, "pod:"+result.Identity.Namespace+":"+result.Identity.PodName)
	}
	for _, src := range execSources {
		for _, ei := range outbound[src] {
			e := &g.Edges[ei]
			if e.Kind != EdgeCanExec {
				continue
			}
			podNode := nodeByID[e.To]
			if podNode == nil || podNode.Kind != KindPod {
				continue
			}
			for _, pi := range outbound[e.To] {
				pe := &g.Edges[pi]
				if pe.Kind != EdgeRunsAs {
					continue
				}
				saNode := nodeByID[pe.To]
				if saNode != nil && saNode.Kind == KindServiceAccount {
					if _, ok := derivedSAs[pe.To]; !ok {
						derivedSAs[pe.To] = fmt.Sprintf("exec into pod %s", e.To)
					}
				}
			}
		}
	}

	// 3. Impersonation → target SA is a derived identity.
	for _, src := range execSources {
		for _, ei := range outbound[src] {
			e := &g.Edges[ei]
			if e.Kind != EdgeCanImpersonate {
				continue
			}
			saNode := nodeByID[e.To]
			if saNode != nil && saNode.Kind == KindServiceAccount {
				if _, ok := derivedSAs[e.To]; !ok {
					derivedSAs[e.To] = fmt.Sprintf("impersonation of %s", e.To)
				}
			}
		}
	}

	if len(derivedSAs) == 0 {
		return
	}

	// For each derived SA, check if it already has capability edges.
	// If not, try to synthesize them from SSRR data (when the derived SA
	// happens to be in a namespace where SSRR reported permissions).
	// Also, for SAs with known workloads, create identity-to-workload-SA
	// shortcut edges that help the pathfinder reach deeper targets.
	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for saID, reason := range derivedSAs {
		// Check if this derived SA has any outgoing capability edges already
		// (from transitive pass or RBAC enumeration).
		hasCapabilities := false
		for _, ei := range outbound[saID] {
			e := &g.Edges[ei]
			switch e.Kind {
			case EdgeCanList, EdgeCanGet, EdgeCanCreate, EdgeCanPatch, EdgeCanDelete,
				EdgeCanExec, EdgeCanPortForward, EdgeCanImpersonate,
				EdgeCanEscalate, EdgeCanBind, EdgeInferred, EdgeAssumesCloudRole:
				hasCapabilities = true
			}
			if hasCapabilities {
				break
			}
		}

		// Mark the SA as a derived foothold for path classification.
		if saNode := nodeByID[saID]; saNode != nil {
			if saNode.Metadata == nil {
				saNode.Metadata = map[string]string{}
			}
			saNode.Metadata["derived_foothold"] = "true"
			saNode.Metadata["derived_via"] = reason
		}

		// If the SA has no capability edges and we have workloads that run as this SA,
		// create workload→SA traversal shortcut from identity through the workload chain.
		// This ensures the pathfinder can discover: identity → workload → SA → (SA's targets).
		if !hasCapabilities {
			// Check if any workloads/pods use this SA and have interesting properties
			// (privileged, hostPID, etc.) that create container escape edges.
			for _, wi := range outbound[saID] {
				we := &g.Edges[wi]
				// SA might have runs_on/mounts/authenticates_as from workloads that
				// run as this SA (reverse direction). Check outbound for cloud roles.
				if we.Kind == EdgeAssumesCloudRole {
					hasCapabilities = true
					break
				}
			}
		}

		// Create identity → SA edge if not already present, to enable
		// the pathfinder to reach this SA as a pivot point.
		key := identityID + "|derived|" + saID
		if !seen[key] {
			seen[key] = true
			// Don't duplicate if identity already reaches this SA via existing edges.
			alreadyReachable := false
			for _, ei := range outbound[identityID] {
				if g.Edges[ei].To == saID {
					alreadyReachable = true
					break
				}
			}
			if !alreadyReachable {
				newEdges = append(newEdges, Edge{
					From:   identityID,
					To:     saID,
					Kind:   EdgeInferred,
					Reason: fmt.Sprintf("derived foothold: %s", reason),
				})
				count++
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("derived foothold edges emitted",
			zap.Int("derived_sas", len(derivedSAs)),
			zap.Int("new_edges", count))
	}
}
