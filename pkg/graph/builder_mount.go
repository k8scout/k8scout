package graph

import (
	"fmt"

	"go.uber.org/zap"
)

// ── Mount-derived SA capabilities ───────────────────────────────────────────

// emitMountDerivedSAEdges handles the common case where a derived SA has no
// RBAC capability edges (RBAC not enumerated, impersonation unavailable) but
// we know the SA's workloads mount secrets. Taking over the workload gives
// filesystem access to those mounted secrets regardless of RBAC.
//
// For each SA without capability edges, find workloads/pods that run as it,
// collect their mounted secrets/configmaps, and emit SA → [can_get] → target
// edges. These model: "I took over this SA's workload, so I can read its mounts."
func emitMountDerivedSAEdges(g *Graph, log *zap.Logger) {
	// Build outbound index.
	outbound := make(map[string][]int)
	inbound := make(map[string][]int)
	for i := range g.Edges {
		outbound[g.Edges[i].From] = append(outbound[g.Edges[i].From], i)
		inbound[g.Edges[i].To] = append(inbound[g.Edges[i].To], i)
	}

	// Node lookup.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	// Capability edge kinds.
	isCapability := map[EdgeKind]bool{
		EdgeCanList: true, EdgeCanGet: true, EdgeCanCreate: true,
		EdgeCanPatch: true, EdgeCanDelete: true, EdgeCanExec: true,
		EdgeCanPortForward: true, EdgeCanImpersonate: true,
		EdgeCanEscalate: true, EdgeCanBind: true,
	}

	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindServiceAccount {
			continue
		}

		// Check if this SA already has capability edges.
		hasCaps := false
		for _, ei := range outbound[n.ID] {
			if isCapability[g.Edges[ei].Kind] {
				hasCaps = true
				break
			}
		}
		if hasCaps {
			continue // SA already has known capabilities; no need for heuristics
		}

		// Find workloads/pods that run_as this SA (reverse edges).
		for _, ei := range inbound[n.ID] {
			e := &g.Edges[ei]
			if e.Kind != EdgeRunsAs {
				continue
			}
			wlNode := nodeByID[e.From]
			if wlNode == nil || (wlNode.Kind != KindWorkload && wlNode.Kind != KindPod) {
				continue
			}

			// Collect this workload/pod's mounted secrets and configmaps.
			for _, mi := range outbound[e.From] {
				me := &g.Edges[mi]
				if me.Kind != EdgeMounts {
					continue
				}
				targetNode := nodeByID[me.To]
				if targetNode == nil {
					continue
				}
				if targetNode.Kind != KindSecret && targetNode.Kind != KindConfigMap {
					continue
				}

				key := n.ID + "|mount_derived|" + me.To
				if seen[key] {
					continue
				}
				seen[key] = true

				newEdges = append(newEdges, Edge{
					From:   n.ID,
					To:     me.To,
					Kind:   EdgeCanGet,
					Reason: fmt.Sprintf("mount-derived: %s's workload %s mounts this resource", n.Name, wlNode.Name),
				})
				count++
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("mount-derived SA capability edges emitted", zap.Int("count", count))
	}
}
