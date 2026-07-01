package graph

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)

// WhatIfScenario describes a hypothetical graph mutation for impact analysis.
type WhatIfScenario struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Mutations   []GraphMutation `json:"mutations"`
}

// GraphMutation describes a single change to apply to the graph.
type GraphMutation struct {
	Action   string `json:"action"` // "add_edge", "remove_edge", "remove_node", "add_node"
	NodeID   string `json:"node_id,omitempty"`
	NodeKind string `json:"node_kind,omitempty"`
	EdgeFrom string `json:"edge_from,omitempty"`
	EdgeTo   string `json:"edge_to,omitempty"`
	EdgeKind string `json:"edge_kind,omitempty"`
}

// WhatIfResult describes the impact of a scenario on attack paths.
type WhatIfResult struct {
	Scenario     WhatIfScenario `json:"scenario"`
	PathsBefore  int            `json:"paths_before"`
	PathsAfter   int            `json:"paths_after"`
	PathsRemoved int            `json:"paths_removed"`
	PathsAdded   int            `json:"paths_added"`
	ScoreBefore  float64        `json:"max_score_before"`
	ScoreAfter   float64        `json:"max_score_after"`
	ChokePoints  []ChokePoint   `json:"choke_points,omitempty"`
}

// ChokePoint identifies a node that appears in many attack paths.
type ChokePoint struct {
	NodeID     string  `json:"node_id"`
	PathCount  int     `json:"path_count"`
	Percentage float64 `json:"percentage"`
}

// LoadWhatIfScenario reads a scenario from a JSON file.
func LoadWhatIfScenario(path string) (*WhatIfScenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scenario file: %w", err)
	}
	var scenario WhatIfScenario
	if err := json.Unmarshal(data, &scenario); err != nil {
		return nil, fmt.Errorf("parsing scenario JSON: %w", err)
	}
	return &scenario, nil
}

// RunWhatIf applies a scenario to a deep copy of the graph and compares attack paths.
func RunWhatIf(g *Graph, r *kube.EnumerationResult, scenario WhatIfScenario, log *zap.Logger) WhatIfResult {
	goals := HighValueTargets(g, r)

	// Compute paths before mutation.
	var pathsBefore []ScoredPath
	for _, goal := range goals {
		for _, n := range g.Nodes {
			if n.Kind == KindPod || n.Kind == KindWorkload || n.Kind == KindIdentity {
				paths := g.FindWeightedPaths(n.ID, goal.NodeID, MaxAttackPathDepth, 5)
				pathsBefore = append(pathsBefore, paths...)
			}
		}
	}

	// Deep copy and mutate.
	mutated := deepCopyGraph(g)
	applyMutations(mutated, scenario.Mutations)
	mutated.BuildIndex()

	// Compute paths after mutation.
	var pathsAfter []ScoredPath
	for _, goal := range goals {
		for _, n := range mutated.Nodes {
			if n.Kind == KindPod || n.Kind == KindWorkload || n.Kind == KindIdentity {
				paths := mutated.FindWeightedPaths(n.ID, goal.NodeID, MaxAttackPathDepth, 5)
				pathsAfter = append(pathsAfter, paths...)
			}
		}
	}

	maxBefore := float64(0)
	for _, p := range pathsBefore {
		s := ScoreByWeight(ClassifyPath(p.Path), 10.0, p.Weight)
		if s > maxBefore {
			maxBefore = s
		}
	}
	maxAfter := float64(0)
	for _, p := range pathsAfter {
		s := ScoreByWeight(ClassifyPath(p.Path), 10.0, p.Weight)
		if s > maxAfter {
			maxAfter = s
		}
	}

	result := WhatIfResult{
		Scenario:    scenario,
		PathsBefore: len(pathsBefore),
		PathsAfter:  len(pathsAfter),
		ScoreBefore: maxBefore,
		ScoreAfter:  maxAfter,
	}

	if len(pathsAfter) < len(pathsBefore) {
		result.PathsRemoved = len(pathsBefore) - len(pathsAfter)
	}
	if len(pathsAfter) > len(pathsBefore) {
		result.PathsAdded = len(pathsAfter) - len(pathsBefore)
	}

	// Compute choke points from the before-paths.
	result.ChokePoints = findChokePoints(pathsBefore)

	log.Info("what-if analysis complete",
		zap.String("scenario", scenario.Name),
		zap.Int("paths_before", result.PathsBefore),
		zap.Int("paths_after", result.PathsAfter),
		zap.Float64("max_score_before", result.ScoreBefore),
		zap.Float64("max_score_after", result.ScoreAfter))

	return result
}

func deepCopyGraph(g *Graph) *Graph {
	nodes := make([]Node, len(g.Nodes))
	for i, n := range g.Nodes {
		nodes[i] = n
		if n.Metadata != nil {
			m := make(map[string]string, len(n.Metadata))
			for k, v := range n.Metadata {
				m[k] = v
			}
			nodes[i].Metadata = m
		}
		if n.Labels != nil {
			l := make(map[string]string, len(n.Labels))
			for k, v := range n.Labels {
				l[k] = v
			}
			nodes[i].Labels = l
		}
	}
	edges := make([]Edge, len(g.Edges))
	copy(edges, g.Edges)
	return &Graph{Nodes: nodes, Edges: edges}
}

func applyMutations(g *Graph, mutations []GraphMutation) {
	for _, m := range mutations {
		switch m.Action {
		case "remove_node":
			var filtered []Node
			for _, n := range g.Nodes {
				if n.ID != m.NodeID {
					filtered = append(filtered, n)
				}
			}
			g.Nodes = filtered
			var filteredEdges []Edge
			for _, e := range g.Edges {
				if e.From != m.NodeID && e.To != m.NodeID {
					filteredEdges = append(filteredEdges, e)
				}
			}
			g.Edges = filteredEdges

		case "remove_edge":
			var filtered []Edge
			for _, e := range g.Edges {
				if !(e.From == m.EdgeFrom && e.To == m.EdgeTo && (m.EdgeKind == "" || string(e.Kind) == m.EdgeKind)) {
					filtered = append(filtered, e)
				}
			}
			g.Edges = filtered

		case "add_node":
			kind := NodeKind(m.NodeKind)
			if kind == "" {
				kind = KindWorkload
			}
			g.Nodes = append(g.Nodes, Node{
				ID:   m.NodeID,
				Kind: kind,
				Name: m.NodeID,
			})

		case "add_edge":
			kind := EdgeKind(m.EdgeKind)
			if kind == "" {
				kind = EdgeInferred
			}
			g.Edges = append(g.Edges, Edge{
				From:     m.EdgeFrom,
				To:       m.EdgeTo,
				Kind:     kind,
				Reason:   "what-if scenario",
				Inferred: true,
			})
		}
	}
}

func findChokePoints(paths []ScoredPath) []ChokePoint {
	if len(paths) == 0 {
		return nil
	}

	nodeCounts := make(map[string]int)
	for _, sp := range paths {
		seen := make(map[string]bool)
		for _, step := range sp.Path {
			if !seen[step.Node.ID] {
				seen[step.Node.ID] = true
				nodeCounts[step.Node.ID]++
			}
		}
	}

	total := len(paths)
	threshold := float64(total) * 0.5

	var chokePoints []ChokePoint
	for nodeID, count := range nodeCounts {
		if float64(count) >= threshold {
			chokePoints = append(chokePoints, ChokePoint{
				NodeID:     nodeID,
				PathCount:  count,
				Percentage: float64(count) / float64(total) * 100,
			})
		}
	}

	// Sort by path count descending.
	for i := 1; i < len(chokePoints); i++ {
		for j := i; j > 0 && chokePoints[j].PathCount > chokePoints[j-1].PathCount; j-- {
			chokePoints[j], chokePoints[j-1] = chokePoints[j-1], chokePoints[j]
		}
	}

	if len(chokePoints) > 10 {
		chokePoints = chokePoints[:10]
	}

	return chokePoints
}

// ── Built-in scenario generators ─────────────────────────────────────────────

// ScenarioRemoveBinding creates a what-if scenario that removes a specific binding.
func ScenarioRemoveBinding(bindingID string) WhatIfScenario {
	return WhatIfScenario{
		Name:        "Remove binding " + bindingID,
		Description: "What if this role binding were removed?",
		Mutations: []GraphMutation{
			{Action: "remove_node", NodeID: bindingID},
		},
	}
}

// ScenarioCompromisePod creates a what-if scenario simulating pod compromise.
func ScenarioCompromisePod(podID string) WhatIfScenario {
	return WhatIfScenario{
		Name:        "Compromise " + podID,
		Description: "What if this pod were compromised by an attacker?",
		Mutations: []GraphMutation{
			{Action: "add_node", NodeID: "attacker:foothold", NodeKind: "Identity"},
			{Action: "add_edge", EdgeFrom: "attacker:foothold", EdgeTo: podID, EdgeKind: "can_exec"},
		},
	}
}

// ScenarioDenyAllNetpol creates a what-if scenario enabling default-deny in a namespace.
func ScenarioDenyAllNetpol(namespace string) WhatIfScenario {
	return WhatIfScenario{
		Name:        "Enable deny-all NetworkPolicy in " + namespace,
		Description: "What if a default-deny ingress NetworkPolicy were applied?",
		Mutations:   []GraphMutation{},
	}
}
