package graph

import "container/heap"

// EdgeWeightOf returns the attacker-effort weight for traversing an edge.
// Lower weight = easier for the attacker = more dangerous.
//
// Weight categories:
//   - 0.0–0.1: automatic/structural (no attacker action needed)
//   - 0.3–0.5: token theft, volume access, cloud role assumption
//   - 1.0–1.5: active exploitation (exec, impersonate, escape)
//   - 2.0–3.0: API mutation (patch workload, create binding)
//   - 5.0+:    speculative or hard-to-exploit
func EdgeWeightOf(e *Edge) float64 {
	switch e.Kind {
	// Structural: no attacker action, just graph topology.
	case EdgeGrantedBy, EdgeBoundTo, EdgeGrants:
		return 0.1

	// Automatic: token is auto-mounted or cloud role is auto-assumed.
	case EdgeRunsAs:
		return 0.1
	case EdgeAssumesCloudRole:
		return 0.2

	// Passive data access: read volumes, steal tokens.
	case EdgeMounts:
		return 0.3
	case EdgeAuthenticatesAs:
		return 0.5

	// Active exploitation: shell access, container escape.
	case EdgeCanExec:
		return 1.0
	case EdgeRunsOn:
		return 1.0 // only emitted for escapable pods
	case EdgeCanImpersonate:
		return 1.5

	// API reads: listing/getting sensitive resources.
	case EdgeCanGet:
		return 1.0
	case EdgeCanList:
		return 1.0
	case EdgeCanPortForward:
		return 2.0

	// API mutations: modifying workloads, creating bindings.
	case EdgeCanCreate:
		return 2.0
	case EdgeCanPatch:
		return 2.0
	case EdgeCanDelete:
		return 3.0

	// Direct RBAC escalation.
	case EdgeCanEscalate:
		return 1.0
	case EdgeCanBind:
		return 1.0

	// Inferred edges: speculative multi-step escalation, higher difficulty.
	case EdgeInferred:
		return 2.0

	// Dead ends: should never be traversed.
	case EdgeMemberOf:
		return 100.0

	default:
		return 5.0
	}
}

// ScoredPath pairs an AttackPath with its cumulative attacker-effort weight.
type ScoredPath struct {
	Path   AttackPath `json:"path"`
	Weight float64    `json:"weight"`
}

// ── Priority queue for weighted path search ──────────────────────────────────

type pqEntry struct {
	path    AttackPath
	visited map[string]bool
	weight  float64
}

type pq []pqEntry

func (h pq) Len() int            { return len(h) }
func (h pq) Less(i, j int) bool  { return h[i].weight < h[j].weight }
func (h pq) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *pq) Push(x interface{}) { *h = append(*h, x.(pqEntry)) }
func (h *pq) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// maxQueueSize bounds memory usage. At ~500 bytes per entry (path of depth 8
// + visited set), 50k entries ≈ 25 MB — well within budget for any cluster.
const maxQueueSize = 50000

// FindWeightedPaths returns up to maxPaths lowest-weight simple paths from
// `from` to `to`, using Dijkstra-style priority-queue expansion.
//
// This replaces the exponential BFS-all-paths approach. The priority queue
// ensures the cheapest (most attacker-realistic) paths are found first, and
// the queue size bound prevents combinatorial explosion on dense graphs.
//
// Dead-end edges (member_of → namespace) are automatically pruned.
// If maxDepth == 0, depth is unbounded (still bounded by graph size).
func (g *Graph) FindWeightedPaths(from, to string, maxDepth, maxPaths int) []ScoredPath {
	if g.nodeByID(from) == nil || g.nodeByID(to) == nil {
		return nil
	}
	if from == to {
		return nil
	}

	startNode := g.nodeByID(from)
	initial := pqEntry{
		path:    AttackPath{PathStep{Node: startNode, Edge: nil, Hop: 0}},
		visited: map[string]bool{from: true},
		weight:  0,
	}

	h := &pq{initial}
	heap.Init(h)

	var results []ScoredPath
	// Track the worst (highest) weight among collected results for pruning.
	worstWeight := float64(1<<62 - 1) // effectively +inf

	for h.Len() > 0 && len(results) < maxPaths {
		current := heap.Pop(h).(pqEntry)

		lastStep := current.path[len(current.path)-1]
		currentID := lastStep.Node.ID
		nextHop := lastStep.Hop + 1

		if maxDepth > 0 && nextHop > maxDepth {
			continue
		}

		// Weight pruning: if we already have enough results and this partial
		// path already exceeds the worst collected, skip — it cannot improve.
		if len(results) >= maxPaths && current.weight >= worstWeight {
			continue
		}

		// Get outbound edges.
		var outEdges []*Edge
		if g.idx != nil {
			outEdges = g.idx.outbound[currentID]
		} else {
			for i := range g.Edges {
				if g.Edges[i].From == currentID {
					outEdges = append(outEdges, &g.Edges[i])
				}
			}
		}

		for _, e := range outEdges {
			if deadEndEdges[e.Kind] {
				continue
			}

			neighborID := e.To
			if current.visited[neighborID] {
				continue
			}

			neighborNode := g.nodeByID(neighborID)
			if neighborNode == nil {
				continue
			}

			edgeW := EdgeWeightOf(e)
			newWeight := current.weight + edgeW

			// Prune if this partial path already exceeds the worst collected.
			if len(results) >= maxPaths && newWeight >= worstWeight {
				continue
			}

			newPath := make(AttackPath, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = PathStep{Node: neighborNode, Edge: e, Hop: nextHop}

			if neighborID == to {
				results = append(results, ScoredPath{Path: newPath, Weight: newWeight})
				// Update worst weight for future pruning.
				if newWeight > worstWeight || len(results) <= maxPaths {
					worst := float64(0)
					for _, r := range results {
						if r.Weight > worst {
							worst = r.Weight
						}
					}
					worstWeight = worst
				}
				continue
			}

			// Queue size bound — drop if full.
			if h.Len() >= maxQueueSize {
				continue
			}

			newVisited := make(map[string]bool, len(current.visited)+1)
			for k := range current.visited {
				newVisited[k] = true
			}
			newVisited[neighborID] = true

			heap.Push(h, pqEntry{path: newPath, visited: newVisited, weight: newWeight})
		}
	}

	// Sort results by weight (priority queue gives us cheapest-first arrivals,
	// but insertion order may differ from weight order due to multi-goal interleaving).
	sortScoredPaths(results)

	return results
}

// sortScoredPaths sorts scored paths by weight ascending (lowest weight first).
func sortScoredPaths(paths []ScoredPath) {
	for i := 1; i < len(paths); i++ {
		for j := i; j > 0 && paths[j].Weight < paths[j-1].Weight; j-- {
			paths[j], paths[j-1] = paths[j-1], paths[j]
		}
	}
}
