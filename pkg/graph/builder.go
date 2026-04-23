package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)


// Build constructs the permission graph from raw enumeration data.
// It runs five passes (as described in the design doc):
//   Pass 1 — Direct SSRR/SSAR edges
//   Pass 2 — RBAC binding expansion
//   Pass 3 — Workload → SA edges
//   Pass 4 — Volume mount edges
//   Pass 5 — Inference (handled separately in inference.go)
func Build(result *kube.EnumerationResult, log *zap.Logger) *Graph {
	nm := make(nodeMap)
	var edges []Edge

	// ── Register the current identity node ───────────────────────────────────
	identityID := "identity:" + result.Identity.Username
	identityNode := &Node{
		ID:        identityID,
		Kind:      KindIdentity,
		Name:      result.Identity.Username,
		Namespace: result.Identity.Namespace,
		Metadata:  map[string]string{"groups": strings.Join(result.Identity.Groups, ",")},
	}
	nm[identityID] = identityNode

	// ── Pass 1: SSRR → direct permission edges ───────────────────────────────
	for ns, rules := range result.Permissions.SSRRByNamespace {
		for _, rule := range rules {
			for _, verb := range rule.Verbs {
				ek := verbToEdgeKind(verb)
				if ek == "" {
					continue
				}
				for _, res := range rule.Resources {
					// Create a synthetic resource node representing the resource type.
					resID := resourceNodeID(res, ns)
					if _, ok := nm[resID]; !ok {
						nm[resID] = &Node{
							ID:        resID,
							Kind:      resourceToNodeKind(res),
							Name:      res,
							Namespace: ns,
						}
					}
					edges = append(edges, Edge{
						From:   identityID,
						To:     resID,
						Kind:   ek,
						Reason: fmt.Sprintf("SSRR rule in namespace %q", ns),
					})
				}
			}
		}
	}

	// Also layer SSAR checks as direct edges (more authoritative than SSRR).
	for _, check := range result.Permissions.SSARChecks {
		if !check.Allowed {
			continue
		}
		ek := verbToEdgeKind(check.Verb)
		if ek == "" {
			continue
		}
		ns := check.Namespace
		res := check.Resource
		if check.Subresource != "" {
			res = check.Resource + "/" + check.Subresource
		}
		resID := resourceNodeID(res, ns)
		if _, ok := nm[resID]; !ok {
			nm[resID] = &Node{
				ID:        resID,
				Kind:      resourceToNodeKind(check.Resource),
				Name:      res,
				Namespace: ns,
			}
		}
		edges = append(edges, Edge{
			From:   identityID,
			To:     resID,
			Kind:   ek,
			Reason: "SSAR confirmed",
		})
	}

	// ── Passes 2–4: shared object graph (RBAC, workloads, pods, secrets, nodes) ─
	objEdges := buildObjectGraph(nm, result)
	edges = append(edges, objEdges...)

	// ── Pass 5: foothold anchoring and concrete lateral-movement edges ────────
	//
	// 5a. Synthesize the foothold subgraph when running in-cluster.
	//     Even when the SA lacks list-pods permission, we know our own pod name
	//     (HOSTNAME), SA (TokenReview), and node (downward API). Create these
	//     nodes if they don't already exist so attack paths always start from
	//     a concrete foothold: pod → SA → identity → SSRR capabilities.
	if result.Identity.InCluster && result.Identity.PodName != "" {
		podID := "pod:" + result.Identity.Namespace + ":" + result.Identity.PodName

		// Create or update the foothold pod node.
		if _, ok := nm[podID]; !ok {
			nm[podID] = &Node{
				ID:        podID,
				Kind:      KindPod,
				Name:      result.Identity.PodName,
				Namespace: result.Identity.Namespace,
				Metadata:  map[string]string{},
			}
			log.Info("synthesized foothold pod node (SA cannot list pods)", zap.String("pod", podID))
		}
		n := nm[podID]
		if n.Metadata == nil {
			n.Metadata = map[string]string{}
		}
		n.Metadata["is_foothold"] = "true"
		if result.Identity.OwnerWorkload != "" {
			n.Metadata["owner_workload"] = result.Identity.OwnerWorkload
			n.Metadata["owner_workload_kind"] = result.Identity.OwnerWorkloadKind
		}
		if n.RiskScore < 5.0 {
			n.RiskScore = 5.0
		}
		log.Info("foothold node anchored", zap.String("pod", podID))

		// Synthesize the SA node and pod→SA edge if the SA is known.
		if result.Identity.SAName != "" {
			saID := "sa:" + result.Identity.Namespace + ":" + result.Identity.SAName
			if _, ok := nm[saID]; !ok {
				nm[saID] = &Node{
					ID:        saID,
					Kind:      KindServiceAccount,
					Name:      result.Identity.SAName,
					Namespace: result.Identity.Namespace,
					Metadata:  map[string]string{},
				}
				log.Info("synthesized SA node for foothold", zap.String("sa", saID))
			}
			// pod → runs_as → SA (if not already present).
			if !hasEdge(edges, podID, saID, EdgeRunsAs) {
				edges = append(edges, Edge{
					From:   podID,
					To:     saID,
					Kind:   EdgeRunsAs,
					Reason: "foothold pod runs as this SA",
				})
			}
			// SA → identity (so paths can flow: pod → SA → identity → SSRR targets).
			if !hasEdge(edges, saID, identityID, EdgeRunsAs) {
				edges = append(edges, Edge{
					From:   saID,
					To:     identityID,
					Kind:   EdgeRunsAs,
					Reason: "SA authenticates as this API identity",
				})
			}
		}

		// Synthesize the host node if known (informational — no runs_on edge
		// unless the pod is actually escapable; runs_on implies container escape).
		if result.Identity.NodeName != "" {
			nodeID := "node:" + result.Identity.NodeName
			if _, ok := nm[nodeID]; !ok {
				nm[nodeID] = &Node{
					ID:       nodeID,
					Kind:     KindNode,
					Name:     result.Identity.NodeName,
					Metadata: map[string]string{},
				}
				log.Info("synthesized node for foothold host", zap.String("node", nodeID))
			}
			nn := nm[nodeID]
			if nn.Metadata == nil {
				nn.Metadata = map[string]string{}
			}
			nn.Metadata["is_foothold_node"] = "true"
		}
	}

	// 5b. Bridge SA → identity for ALL modes (in-cluster and out-of-cluster).
	//     This ensures paths can flow: SA → identity → SSRR/SSAR targets.
	//     Weight is 0.1 (EdgeRunsAs) — a zero-effort transition since the SA IS the identity.
	//     Replaces the old EdgeInferred shortcut (weight 2.0) that hid the real chain.
	if result.Identity.SAName != "" {
		saID := saNodeID(result.Identity.Namespace, result.Identity.SAName)
		if nm[saID] != nil {
			if !hasEdge(edges, saID, identityID, EdgeRunsAs) {
				edges = append(edges, Edge{
					From:   saID,
					To:     identityID,
					Kind:   EdgeRunsAs,
					Reason: "SA authenticates as this API identity",
				})
			}
		}
	}

	// 5c. Emit concrete per-pod exec and portforward edges from SSAR checks.
	edges = append(edges, buildConcreteReachabilityEdges(nm, result, identityID)...)

	// 5d. Emit concrete identity → resource edges for all SSAR-confirmed permissions.
	//     This bridges the abstract/concrete gap: the identity gets edges to
	//     actual workloads, secrets, and SAs — not just abstract resource type nodes.
	edges = append(edges, buildConcreteIdentityEdges(nm, result, identityID)...)

	// ── Materialize nodeMap → []Node ─────────────────────────────────────────
	nodes := make([]Node, 0, len(nm))
	for _, n := range nm {
		nodes = append(nodes, *n)
	}

	g := &Graph{Nodes: nodes, Edges: edges}

	// ── Pass 6: Inferred edges (moved from inference.go) ─────────────────────
	// Must run before BuildIndex so the index includes inferred edges, and
	// before any pathfinding so all traversable edges are visible.
	emitInferredEdges(g, result)

	// ── Pass 7: Transitive SA capability edges ───────────────────────────────
	// Collapse RBAC chains: SA → granted_by → binding → bound_to → role → cap → target
	// into direct SA → cap → target edges. This reduces path length by 2-3 hops
	// and enables deeper multi-step attack chains within the depth limit.
	emitTransitiveSAEdges(g, log)

	// ── Pass 7b: Active enrichment — derived SA capability edges ─────────────
	// When SSRR was run as derived identities (via impersonation), create
	// concrete capability edges from those SAs to the resources they can access.
	// This is the key enabler for multi-level attack paths: the graph now knows
	// what SAs we can "become" AND what those SAs can do.
	emitDerivedSSRREdges(g, result, log)

	// ── Pass 8: Derived foothold edges ───────────────────────────────────────
	// When identity can patch/exec into a workload, model the full takeover:
	// the target workload's SA capabilities become reachable from the identity.
	emitDerivedFootholdEdges(g, result, log)

	// ── Pass 9: Node-derived expansion ──────────────────────────────────────
	// When an attacker escapes to a node (privileged pod → runs_on → node),
	// they gain access to SA tokens of all pods running on that node.
	// Emit node → [can_get] → SA edges for co-located pods.
	emitNodeDerivedEdges(g, result, log)

	// ── Pass 10: Mount-derived SA capabilities ──────────────────────────────
	// When a derived SA has no RBAC capability edges, infer that it can
	// access the secrets/configmaps mounted by its own workloads.
	emitMountDerivedSAEdges(g, log)

	// ── Build adjacency index for O(1) lookups during traversal ──────────────
	g.BuildIndex()

	log.Info("graph built",
		zap.Int("nodes", len(g.Nodes)),
		zap.Int("edges", len(g.Edges)),
		zap.Bool("in_cluster", result.Identity.InCluster))

	return g
}

// BuildReviewer constructs the permission graph for reviewer mode.
// Instead of a single current-identity node it creates nodes for ALL RBAC subjects
// whose effective permissions were computed from RBAC rules, giving a full cluster
// attack-surface view.
func BuildReviewer(result *kube.ReviewerEnumerateResult, log *zap.Logger) *Graph {
	nm := make(nodeMap)
	var edges []Edge

	// ── Pass 1-reviewer: one node per computed identity + RBAC-derived edges ──
	for _, ip := range result.AllIdentityPerms {
		nodeID := reviewerIdentityNodeID(ip)
		nodeKind := KindServiceAccount
		if ip.SubjectKind != "ServiceAccount" {
			nodeKind = KindIdentity
		}

		if _, ok := nm[nodeID]; !ok {
			nm[nodeID] = &Node{
				ID:        nodeID,
				Kind:      nodeKind,
				Name:      ip.Name,
				Namespace: ip.Namespace,
				Metadata: map[string]string{
					"subject":     ip.Subject,
					"bound_roles": strings.Join(ip.BoundRoles, "; "),
				},
			}
		}

		// Add permission edges from this identity's computed RBAC rules.
		for _, rule := range ip.Rules {
			for _, verb := range rule.Verbs {
				ek := verbToEdgeKind(verb)
				if ek == "" {
					continue
				}
				// Use the SA's own namespace as the edge scope; cluster-scoped resources get "".
				ns := ip.Namespace
				for _, res := range rule.Resources {
					resID := resourceNodeID(res, ns)
					if _, ok := nm[resID]; !ok {
						nm[resID] = &Node{
							ID:        resID,
							Kind:      resourceToNodeKind(res),
							Name:      res,
							Namespace: ns,
						}
					}
					edges = append(edges, Edge{
						From:   nodeID,
						To:     resID,
						Kind:   ek,
						Reason: fmt.Sprintf("RBAC rule for %s", ip.Subject),
					})
				}
			}
		}
	}

	// ── Passes 2–4: shared object graph ───────────────────────────────────────
	objEdges := buildObjectGraph(nm, result.EnumerationResult)
	edges = append(edges, objEdges...)

	nodes := make([]Node, 0, len(nm))
	for _, n := range nm {
		nodes = append(nodes, *n)
	}

	g := &Graph{Nodes: nodes, Edges: edges}

	// ── Pass 9: Node-derived expansion ───────────────────────────────────────
	// Reuse standard-mode enrichment: when a pod has a container-escape path to
	// its node (EdgeRunsOn emitted in buildObjectGraph), any SA of a co-located
	// pod becomes reachable from that node. Data-driven and identity-agnostic,
	// so it applies equally to reviewer mode.
	emitNodeDerivedEdges(g, result.EnumerationResult, log)

	// ── Pass 10: Mount-derived SA capabilities ───────────────────────────────
	// For SAs without RBAC capability edges, treat their workloads' mounted
	// secrets/configmaps as readable targets (workload takeover → filesystem).
	// Gated on "no existing capability edges", so SAs with expanded rules
	// from pass 1-reviewer are untouched.
	emitMountDerivedSAEdges(g, log)

	g.BuildIndex()

	log.Info("reviewer graph built",
		zap.Int("nodes", len(g.Nodes)),
		zap.Int("edges", len(g.Edges)),
		zap.Int("identities", len(result.AllIdentityPerms)))

	return g
}

