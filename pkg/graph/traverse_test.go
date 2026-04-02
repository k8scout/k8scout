package graph

import (
	"testing"
)

// makeGraph builds a Graph from a simple node/edge spec for testing.
// nodes is a list of node IDs; edges is a list of [from, to] pairs.
func makeGraph(nodeIDs []string, edgePairs [][2]string) Graph {
	var nodes []Node
	for _, id := range nodeIDs {
		nodes = append(nodes, Node{ID: id, Kind: KindServiceAccount, Name: id})
	}
	var edges []Edge
	for _, pair := range edgePairs {
		edges = append(edges, Edge{From: pair[0], To: pair[1], Kind: EdgeBoundTo})
	}
	return Graph{Nodes: nodes, Edges: edges}
}

// pathNodeIDs extracts node IDs from an AttackPath for easy assertion.
func pathNodeIDs(p AttackPath) []string {
	ids := make([]string, len(p))
	for i, step := range p {
		ids[i] = step.Node.ID
	}
	return ids
}

// ── nodeByID ─────────────────────────────────────────────────────────────────

func TestNodeByID_found(t *testing.T) {
	g := makeGraph([]string{"a", "b"}, nil)
	n := g.nodeByID("a")
	if n == nil {
		t.Fatal("expected node, got nil")
	}
	if n.ID != "a" {
		t.Fatalf("got ID %q, want %q", n.ID, "a")
	}
}

func TestNodeByID_notFound(t *testing.T) {
	g := makeGraph([]string{"a"}, nil)
	if n := g.nodeByID("z"); n != nil {
		t.Fatalf("expected nil, got node %q", n.ID)
	}
}

// ── Neighbors ────────────────────────────────────────────────────────────────

func TestNeighbors_outbound(t *testing.T) {
	// a → b, a → c, d → a
	g := makeGraph([]string{"a", "b", "c", "d"}, [][2]string{
		{"a", "b"}, {"a", "c"}, {"d", "a"},
	})
	got := g.Neighbors("a", Outbound)
	if len(got) != 2 {
		t.Fatalf("want 2 outbound neighbors, got %d", len(got))
	}
	ids := map[string]bool{}
	for _, n := range got {
		ids[n.ID] = true
	}
	if !ids["b"] || !ids["c"] {
		t.Fatalf("expected b and c, got %v", ids)
	}
}

func TestNeighbors_inbound(t *testing.T) {
	// a → b, c → b
	g := makeGraph([]string{"a", "b", "c"}, [][2]string{
		{"a", "b"}, {"c", "b"},
	})
	got := g.Neighbors("b", Inbound)
	if len(got) != 2 {
		t.Fatalf("want 2 inbound neighbors, got %d", len(got))
	}
}

func TestNeighbors_both(t *testing.T) {
	// a → b, c → a
	g := makeGraph([]string{"a", "b", "c"}, [][2]string{
		{"a", "b"}, {"c", "a"},
	})
	got := g.Neighbors("a", Both)
	if len(got) != 2 {
		t.Fatalf("want 2 neighbors (both directions), got %d", len(got))
	}
}

func TestNeighbors_deduplicatesMultipleEdges(t *testing.T) {
	// two edges a → b (different kinds would exist in real graphs)
	g := Graph{
		Nodes: []Node{
			{ID: "a", Kind: KindServiceAccount, Name: "a"},
			{ID: "b", Kind: KindServiceAccount, Name: "b"},
		},
		Edges: []Edge{
			{From: "a", To: "b", Kind: EdgeBoundTo},
			{From: "a", To: "b", Kind: EdgeGrants},
		},
	}
	got := g.Neighbors("a", Outbound)
	if len(got) != 1 {
		t.Fatalf("want 1 deduplicated neighbor, got %d", len(got))
	}
}

func TestNeighbors_unknownNode_returnsNil(t *testing.T) {
	g := makeGraph([]string{"a"}, nil)
	got := g.Neighbors("z", Outbound)
	if got != nil {
		t.Fatalf("expected nil for unknown node, got %v", got)
	}
}

func TestNeighbors_noEdges_returnsNil(t *testing.T) {
	g := makeGraph([]string{"a", "b"}, nil)
	got := g.Neighbors("a", Outbound)
	if len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

// ── FindPaths ────────────────────────────────────────────────────────────────

func TestFindPaths_directPath(t *testing.T) {
	// a → b (one hop)
	g := makeGraph([]string{"a", "b"}, [][2]string{{"a", "b"}})
	paths := g.FindPaths("a", "b", 0)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	ids := pathNodeIDs(paths[0])
	want := []string{"a", "b"}
	if !equalSlices(ids, want) {
		t.Fatalf("want path %v, got %v", want, ids)
	}
	// First step: Hop==0, Edge==nil
	if paths[0][0].Hop != 0 {
		t.Fatalf("first step Hop want 0, got %d", paths[0][0].Hop)
	}
	if paths[0][0].Edge != nil {
		t.Fatal("first step Edge should be nil")
	}
	// Second step: Hop==1, Edge non-nil
	if paths[0][1].Hop != 1 {
		t.Fatalf("second step Hop want 1, got %d", paths[0][1].Hop)
	}
	if paths[0][1].Edge == nil {
		t.Fatal("second step Edge should not be nil")
	}
}

func TestFindPaths_twoHopPath(t *testing.T) {
	// a → b → c
	g := makeGraph([]string{"a", "b", "c"}, [][2]string{
		{"a", "b"}, {"b", "c"},
	})
	paths := g.FindPaths("a", "c", 0)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	ids := pathNodeIDs(paths[0])
	want := []string{"a", "b", "c"}
	if !equalSlices(ids, want) {
		t.Fatalf("want %v, got %v", want, ids)
	}
	if paths[0][2].Hop != 2 {
		t.Fatalf("last step Hop want 2, got %d", paths[0][2].Hop)
	}
}

func TestFindPaths_noPath(t *testing.T) {
	// a → b, no path to c
	g := makeGraph([]string{"a", "b", "c"}, [][2]string{{"a", "b"}})
	paths := g.FindPaths("a", "c", 0)
	if len(paths) != 0 {
		t.Fatalf("want no paths, got %d", len(paths))
	}
}

func TestFindPaths_cycleDetection(t *testing.T) {
	// a → b → c → a (cycle), also b → d
	// Only valid simple path from a to d: a→b→d
	g := makeGraph([]string{"a", "b", "c", "d"}, [][2]string{
		{"a", "b"}, {"b", "c"}, {"c", "a"}, {"b", "d"},
	})
	paths := g.FindPaths("a", "d", 0)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d: %v", len(paths), debugPaths(paths))
	}
	ids := pathNodeIDs(paths[0])
	want := []string{"a", "b", "d"}
	if !equalSlices(ids, want) {
		t.Fatalf("want %v, got %v", want, ids)
	}
}

func TestFindPaths_maxDepthCutoff(t *testing.T) {
	// a → b → c → d (3 hops to d)
	g := makeGraph([]string{"a", "b", "c", "d"}, [][2]string{
		{"a", "b"}, {"b", "c"}, {"c", "d"},
	})
	// maxDepth=2 should not reach d (requires 3 hops)
	paths := g.FindPaths("a", "d", 2)
	if len(paths) != 0 {
		t.Fatalf("want no paths within depth 2, got %d", len(paths))
	}
	// maxDepth=3 should find it
	paths = g.FindPaths("a", "d", 3)
	if len(paths) != 1 {
		t.Fatalf("want 1 path within depth 3, got %d", len(paths))
	}
}

func TestFindPaths_maxDepthZeroMeansUnlimited(t *testing.T) {
	// a → b → c → d → e (4 hops)
	g := makeGraph([]string{"a", "b", "c", "d", "e"}, [][2]string{
		{"a", "b"}, {"b", "c"}, {"c", "d"}, {"d", "e"},
	})
	paths := g.FindPaths("a", "e", 0)
	if len(paths) != 1 {
		t.Fatalf("want 1 path with unlimited depth, got %d", len(paths))
	}
}

func TestFindPaths_multiplePaths_shortestFirst(t *testing.T) {
	// a → c (direct, 1 hop) and a → b → c (2 hops)
	g := makeGraph([]string{"a", "b", "c"}, [][2]string{
		{"a", "c"}, {"a", "b"}, {"b", "c"},
	})
	paths := g.FindPaths("a", "c", 0)
	if len(paths) != 2 {
		t.Fatalf("want 2 paths, got %d", len(paths))
	}
	// BFS guarantees shortest path comes first.
	if len(paths[0]) != 2 {
		t.Fatalf("first path should be length 2 (direct), got %d", len(paths[0]))
	}
	if len(paths[1]) != 3 {
		t.Fatalf("second path should be length 3 (2 hops), got %d", len(paths[1]))
	}
}

func TestFindPaths_unknownFromNode(t *testing.T) {
	g := makeGraph([]string{"a", "b"}, [][2]string{{"a", "b"}})
	paths := g.FindPaths("z", "b", 0)
	if paths != nil {
		t.Fatal("expected nil for unknown from-node")
	}
}

func TestFindPaths_unknownToNode(t *testing.T) {
	g := makeGraph([]string{"a", "b"}, [][2]string{{"a", "b"}})
	paths := g.FindPaths("a", "z", 0)
	if paths != nil {
		t.Fatal("expected nil for unknown to-node")
	}
}

func TestFindPaths_sameNode(t *testing.T) {
	g := makeGraph([]string{"a"}, nil)
	paths := g.FindPaths("a", "a", 0)
	if len(paths) != 0 {
		t.Fatalf("expected no paths for same from/to node, got %d", len(paths))
	}
}

func TestFindPaths_edgePointerIsCorrect(t *testing.T) {
	// Verify that the Edge pointer in PathStep points into g.Edges, not a copy.
	g := makeGraph([]string{"a", "b"}, [][2]string{{"a", "b"}})
	paths := g.FindPaths("a", "b", 0)
	if len(paths) != 1 {
		t.Fatal("expected 1 path")
	}
	step := paths[0][1]
	if step.Edge == nil {
		t.Fatal("edge should not be nil")
	}
	if step.Edge.From != "a" || step.Edge.To != "b" {
		t.Fatalf("edge From/To mismatch: %+v", step.Edge)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func debugPaths(paths []AttackPath) [][]string {
	out := make([][]string, len(paths))
	for i, p := range paths {
		out[i] = pathNodeIDs(p)
	}
	return out
}
