package graph

import (
	"fmt"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)

// ── Node-derived expansion ──────────────────────────────────────────────────

// emitNodeDerivedEdges models what an attacker gains after escaping to a node:
// access to SA tokens of all pods running on that node.
//
// On a Kubernetes node, every pod's SA token is mounted at a well-known path
// (/var/run/secrets/kubernetes.io/serviceaccount/token). An attacker with host
// access can read any pod's token and authenticate as that pod's SA.
//
// This creates edges: node → [can_get] → SA for every pod scheduled on that node.
// It also models kubelet-adjacent access: the node identity can read secrets
// mounted by its pods (via the Node authorizer).
func emitNodeDerivedEdges(g *Graph, result *kube.EnumerationResult, log *zap.Logger) {
	// Build node → pods index from pod data.
	nodePods := make(map[string][]kube.PodInfo)
	for _, pod := range result.ClusterObjects.Pods {
		if pod.Node != "" {
			nodePods[pod.Node] = append(nodePods[pod.Node], pod)
		}
	}

	if len(nodePods) == 0 {
		return
	}

	// Node lookup.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for nodeName, pods := range nodePods {
		nodeID := "node:" + nodeName
		if nodeByID[nodeID] == nil {
			continue
		}

		// Check if this node is reachable (has inbound runs_on edges).
		reachable := false
		for i := range g.Edges {
			if g.Edges[i].To == nodeID && g.Edges[i].Kind == EdgeRunsOn {
				reachable = true
				break
			}
		}
		if !reachable {
			continue // Only emit for nodes the attacker can actually reach
		}

		for _, pod := range pods {
			if pod.ServiceAccount == "" {
				continue
			}
			saID := saNodeID(pod.Namespace, pod.ServiceAccount)
			key := nodeID + "|" + saID
			if seen[key] {
				continue
			}
			seen[key] = true

			newEdges = append(newEdges, Edge{
				From:   nodeID,
				To:     saID,
				Kind:   EdgeCanGet,
				Reason: fmt.Sprintf("host access: steal SA token from pod %s/%s on this node", pod.Namespace, pod.Name),
			})
			count++
		}

		// Model host-mounted credential paths: if any pod on this node mounts
		// sensitive hostPath directories, the node gives access to those credentials.
		for _, pod := range pods {
			for _, hp := range pod.HostPathMounts {
				if isCredentialPath(hp) {
					// Host credential path → potential cluster-admin access.
					adminID := "clusterrole:cluster-admin"
					key := nodeID + "|hostcred|" + adminID
					if !seen[key] {
						seen[key] = true
						newEdges = append(newEdges, Edge{
							From:     nodeID,
							To:       adminID,
							Kind:     EdgeInferred,
							Reason:   fmt.Sprintf("host credential: pod %s/%s mounts %s", pod.Namespace, pod.Name, hp),
							Inferred: true,
						})
						count++
					}
					break // one credential path is enough
				}
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("node-derived expansion edges emitted", zap.Int("count", count))
	}
}
