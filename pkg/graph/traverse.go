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

// nodeByID returns a pointer to the Node in g.Nodes with the given ID,
// or nil if no such node exists.
func (g *Graph) nodeByID(id string) *Node {
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

	// Collect neighbor IDs, deduplicating via a set.
	seen := make(map[string]struct{})
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

	var result []*Node
	for i := range g.Nodes {
		if _, ok := seen[g.Nodes[i].ID]; ok {
			result = append(result, &g.Nodes[i])
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
// Returns an empty slice when no path exists or either node is not found.
func (g *Graph) FindPaths(from, to string, maxDepth int) []AttackPath {
	if g.nodeByID(from) == nil || g.nodeByID(to) == nil {
		return nil
	}
	// A node with no path to itself is the typical case; handle same-node
	// trivially by returning empty — a zero-hop "path" is not a useful attack path.
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

		// Enforce depth limit before expanding.
		if maxDepth > 0 && nextHop > maxDepth {
			continue
		}

		// Expand all outbound edges from the current node.
		for i := range g.Edges {
			e := &g.Edges[i]
			if e.From != currentID {
				continue
			}
			neighborID := e.To
			if current.visited[neighborID] {
				continue // skip: would create a cycle in this path
			}

			neighborNode := g.nodeByID(neighborID)
			if neighborNode == nil {
				continue // edge references a node not in the graph
			}

			// Build the extended path.
			newPath := make(AttackPath, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = PathStep{Node: neighborNode, Edge: e, Hop: nextHop}

			if neighborID == to {
				// Destination reached — record and do not extend further.
				results = append(results, newPath)
				continue
			}

			// Not yet at destination — enqueue with updated visited set.
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
