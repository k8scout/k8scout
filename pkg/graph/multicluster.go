package graph

import (
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)

// MultiClusterResult holds enumeration results from multiple clusters.
type MultiClusterResult struct {
	Clusters []ClusterEnumerationResult `json:"clusters"`
}

// ClusterEnumerationResult pairs a cluster context with its enumeration data.
type ClusterEnumerationResult struct {
	ClusterName string                  `json:"cluster_name"`
	Server      string                  `json:"server,omitempty"`
	Result      *kube.EnumerationResult `json:"result"`
}

// BuildMultiCluster constructs a merged permission graph from multiple clusters.
// Node IDs are prefixed with the cluster name to avoid collisions.
// Cross-cluster edges are created via shared CloudIdentity nodes (same IAM role).
func BuildMultiCluster(clusters []ClusterEnumerationResult, log *zap.Logger) *Graph {
	nm := make(nodeMap)
	var edges []Edge

	// cloudRoleSAs tracks cloud identity → list of (clusterName, saID) for cross-cluster linking.
	type clusterSA struct {
		cluster string
		saID    string
	}
	cloudRoleSAs := make(map[string][]clusterSA)

	for _, cluster := range clusters {
		prefix := cluster.ClusterName + ":"
		result := cluster.Result

		// Build per-cluster graph using the standard builder.
		clusterGraph := Build(result, log)

		// Import all nodes with cluster prefix.
		for i := range clusterGraph.Nodes {
			n := clusterGraph.Nodes[i]
			n.ID = prefix + n.ID
			// Deep copy metadata map so clusters don't share map references.
			meta := make(map[string]string, len(n.Metadata)+1)
			for k, v := range n.Metadata {
				meta[k] = v
			}
			meta["cluster"] = cluster.ClusterName
			n.Metadata = meta
			// Deep copy labels.
			if n.Labels != nil {
				labels := make(map[string]string, len(n.Labels))
				for k, v := range n.Labels {
					labels[k] = v
				}
				n.Labels = labels
			}
			nm[n.ID] = &n
		}

		// Import all edges with cluster prefix.
		for _, e := range clusterGraph.Edges {
			edges = append(edges, Edge{
				From:     prefix + e.From,
				To:       prefix + e.To,
				Kind:     e.Kind,
				Reason:   e.Reason,
				Inferred: e.Inferred,
			})
		}

		// Track cloud role → SA mappings for cross-cluster edges.
		for _, sa := range result.ClusterObjects.ServiceAccounts {
			role := sa.IRSARole
			if role == "" {
				role = sa.GCPServiceAccount
			}
			if role == "" {
				role = sa.AzureIdentity
			}
			if role == "" {
				continue
			}
			saID := prefix + "sa:" + sa.Namespace + ":" + sa.Name
			cloudRoleSAs[role] = append(cloudRoleSAs[role], clusterSA{
				cluster: cluster.ClusterName,
				saID:    saID,
			})
		}
	}

	// Create cross-cluster edges via shared cloud IAM roles.
	for role, sas := range cloudRoleSAs {
		if len(sas) < 2 {
			continue
		}
		// Create a shared cloud identity node (not cluster-prefixed).
		cloudID := "cloud:shared:" + role
		if nm[cloudID] == nil {
			nm[cloudID] = &Node{
				ID:   cloudID,
				Kind: KindCloudIdentity,
				Name: role,
				Metadata: map[string]string{
					"cross_cluster": "true",
					"cloud_role":    role,
				},
				RiskScore: 9.5,
			}
		}
		for _, sa := range sas {
			edges = append(edges, Edge{
				From:   sa.saID,
				To:     cloudID,
				Kind:   EdgeAssumesCloudRole,
				Reason: "cross-cluster shared cloud identity " + role,
			})
		}
	}

	// Find shared imagePullSecrets across clusters.
	type secretKey struct {
		name    string
		cluster string
	}
	pullSecretClusters := make(map[string][]string) // secretName → []clusterName
	for _, cluster := range clusters {
		for _, sa := range cluster.Result.ClusterObjects.ServiceAccounts {
			for _, ips := range sa.ImagePullSecrets {
				pullSecretClusters[ips] = appendUnique(pullSecretClusters[ips], cluster.ClusterName)
			}
		}
	}
	for secretName, clusterNames := range pullSecretClusters {
		if len(clusterNames) < 2 {
			continue
		}
		// Shared registry cred — potential cross-cluster supply chain vector.
		sharedID := "shared:registry-cred:" + secretName
		if nm[sharedID] == nil {
			nm[sharedID] = &Node{
				ID:   sharedID,
				Kind: KindSecret,
				Name: secretName,
				Metadata: map[string]string{
					"cross_cluster":  "true",
					"shared_clusters": strings.Join(clusterNames, ","),
					"type":            "registry-credential",
				},
				RiskScore: 7.0,
			}
		}
	}

	// Materialize.
	nodes := make([]Node, 0, len(nm))
	for _, n := range nm {
		nodes = append(nodes, *n)
	}

	g := &Graph{Nodes: nodes, Edges: edges}
	g.BuildIndex()

	log.Info("multi-cluster graph built",
		zap.Int("clusters", len(clusters)),
		zap.Int("nodes", len(g.Nodes)),
		zap.Int("edges", len(g.Edges)))

	return g
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
