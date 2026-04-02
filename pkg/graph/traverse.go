package graph

// EdgeDirection controls which edge directions are followed during traversal.
type EdgeDirection int

const (
	// Outbound follows edges where the given node is the source (From).
	Outbound EdgeDirection = iota
	// Inbound follows edges where the given node is the target (To).
	Inbound
	// Both follows edges in either direction.
	Both
)

// PathStep is a single hop in an AttackPath.
//
// The first step in any path represents the origin node and has Edge == nil
// and Hop == 0. Every subsequent step has the edge that was traversed to
// reach Node, and Hop incremented by one.
type PathStep struct {
	Node *Node `json:"node"`
	Edge *Edge `json:"edge,omitempty"`
	Hop  int   `json:"hop"`
}

// AttackPath is an ordered sequence of PathSteps describing a path through
// the graph from an origin node to a destination node.
type AttackPath []PathStep

// graphIndex provides O(1) node lookups and O(degree) neighbor enumeration.
// Built once after graph construction via BuildIndex.
type graphIndex struct {
	nodes    map[string]*Node
	outbound map[string][]*Edge
	inbound  map[string][]*Edge
}

// deadEndEdges are edge kinds that should not be followed during attack-path
// traversal because they lead to structural nodes (namespaces) that never
// connect onward to high-value targets.
var deadEndEdges = map[EdgeKind]bool{
	EdgeMemberOf: true,
}

// BuildIndex constructs the internal adjacency index for O(1) lookups.
// Must be called after all nodes and edges have been added to the graph.
func (g *Graph) BuildIndex() {
	idx := &graphIndex{
		nodes:    make(map[string]*Node, len(g.Nodes)),
		outbound: make(map[string][]*Edge, len(g.Nodes)),
		inbound:  make(map[string][]*Edge, len(g.Nodes)),
	}
	for i := range g.Nodes {
		idx.nodes[g.Nodes[i].ID] = &g.Nodes[i]
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		idx.outbound[e.From] = append(idx.outbound[e.From], e)
		idx.inbound[e.To] = append(idx.inbound[e.To], e)
	}
	g.idx = idx
}

// nodeByID returns a pointer to the Node in g.Nodes with the given ID,
// or nil if no such node exists. Uses the index when available.
func (g *Graph) nodeByID(id string) *Node {
	if g.idx != nil {
		return g.idx.nodes[id]
	}
	// Fallback: linear scan (used during graph construction before BuildIndex).
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

// Neighbors returns the nodes reachable from the node with the given ID,
// following edges in the specified direction.
// Returns nil if the node does not exist in the graph.
func (g *Graph) Neighbors(id string, direction EdgeDirection) []*Node {
	if g.nodeByID(id) == nil {
		return nil
	}

	seen := make(map[string]struct{})

	if g.idx != nil {
		switch direction {
		case Outbound:
			for _, e := range g.idx.outbound[id] {
				seen[e.To] = struct{}{}
			}
		case Inbound:
			for _, e := range g.idx.inbound[id] {
				seen[e.From] = struct{}{}
			}
		case Both:
			for _, e := range g.idx.outbound[id] {
				seen[e.To] = struct{}{}
			}
			for _, e := range g.idx.inbound[id] {
				seen[e.From] = struct{}{}
			}
		}
	} else {
		// Fallback: scan all edges.
		for i := range g.Edges {
			e := &g.Edges[i]
			switch direction {
			case Outbound:
				if e.From == id {
					seen[e.To] = struct{}{}
				}
			case Inbound:
				if e.To == id {
					seen[e.From] = struct{}{}
				}
			case Both:
				if e.From == id {
					seen[e.To] = struct{}{}
				}
				if e.To == id {
					seen[e.From] = struct{}{}
				}
			}
		}
	}

	var result []*Node
	for nid := range seen {
		if n := g.nodeByID(nid); n != nil {
			result = append(result, n)
		}
	}
	return result
}

// FindPaths returns all simple paths (no repeated nodes) from the node with
// ID `from` to the node with ID `to`, up to maxDepth hops.
//
// A "hop" is an edge traversal; a direct edge from→to is 1 hop.
// If maxDepth == 0, depth is unbounded (still bounded by graph size).
//
// Paths are returned in BFS order (shortest first).
// Dead-end edges (e.g. member_of → namespace) are automatically pruned.
// Returns an empty slice when no path exists or either node is not found.
func (g *Graph) FindPaths(from, to string, maxDepth int) []AttackPath {
	if g.nodeByID(from) == nil || g.nodeByID(to) == nil {
		return nil
	}
	if from == to {
		return nil
	}

	type queueEntry struct {
		path    AttackPath
		visited map[string]bool
	}

	startNode := g.nodeByID(from)
	initial := AttackPath{PathStep{Node: startNode, Edge: nil, Hop: 0}}
	initialVisited := map[string]bool{from: true}

	queue := []queueEntry{{path: initial, visited: initialVisited}}
	var results []AttackPath

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		lastStep := current.path[len(current.path)-1]
		currentID := lastStep.Node.ID
		nextHop := lastStep.Hop + 1

		if maxDepth > 0 && nextHop > maxDepth {
			continue
		}

		// Get outbound edges — use index when available, else scan.
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
			// Skip dead-end edges that lead to structural nodes.
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

			newPath := make(AttackPath, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = PathStep{Node: neighborNode, Edge: e, Hop: nextHop}

			if neighborID == to {
				results = append(results, newPath)
				continue
			}

			newVisited := make(map[string]bool, len(current.visited)+1)
			for k := range current.visited {
				newVisited[k] = true
			}
			newVisited[neighborID] = true

			queue = append(queue, queueEntry{path: newPath, visited: newVisited})
		}
	}

	return results
}
