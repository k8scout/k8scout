package graph

import (
	"fmt"

	"go.uber.org/zap"
)

// ── Transitive SA capability edges ──────────────────────────────────────────

// emitTransitiveSAEdges resolves the RBAC chain for each ServiceAccount and
// creates direct SA → target capability edges. This collapses:
//
//	SA → [granted_by] → binding → [bound_to] → role → [can_*] → target
//
// into a single hop:
//
//	SA → [can_*] → target
//
// The original RBAC chain edges are preserved for visualization, but the
// shortcut edges enable Dijkstra to find deeper multi-step attack chains
// (e.g. pod → SA → secret → authenticates_as → SA₂ → target) within the
// depth limit.
func emitTransitiveSAEdges(g *Graph, log *zap.Logger) {
	// Build quick lookup maps from edge list (index not yet built).
	outbound := make(map[string][]int) // nodeID → edge indices
	for i := range g.Edges {
		outbound[g.Edges[i].From] = append(outbound[g.Edges[i].From], i)
	}

	// Capability edge kinds that should be propagated from roles to SAs.
	isCapabilityEdge := map[EdgeKind]bool{
		EdgeCanList: true, EdgeCanGet: true, EdgeCanCreate: true,
		EdgeCanPatch: true, EdgeCanDelete: true, EdgeCanExec: true,
		EdgeCanPortForward: true, EdgeCanImpersonate: true,
		EdgeCanEscalate: true, EdgeCanBind: true, EdgeInferred: true,
	}

	// Dedup: avoid emitting the same SA→kind→target edge twice.
	seen := make(map[string]bool)

	var newEdges []Edge
	count := 0

	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindServiceAccount {
			continue
		}
		saID := n.ID

		// Step 1: SA → [granted_by] → bindings
		for _, ei := range outbound[saID] {
			e := &g.Edges[ei]
			if e.Kind != EdgeGrantedBy {
				continue
			}
			bindingID := e.To

			// Step 2: binding → [bound_to] → role
			for _, bi := range outbound[bindingID] {
				be := &g.Edges[bi]
				if be.Kind != EdgeBoundTo {
					continue
				}
				roleID := be.To

				// Step 3: role → [capability] → target
				for _, ri := range outbound[roleID] {
					re := &g.Edges[ri]
					if !isCapabilityEdge[re.Kind] {
						continue
					}
					targetID := re.To
					key := saID + "|" + string(re.Kind) + "|" + targetID
					if seen[key] {
						continue
					}
					seen[key] = true

					newEdges = append(newEdges, Edge{
						From:   saID,
						To:     targetID,
						Kind:   re.Kind,
						Reason: fmt.Sprintf("transitive: %s via %s → %s", saID, bindingID, roleID),
					})
					count++
				}
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("transitive SA capability edges emitted", zap.Int("count", count))
	}
}
