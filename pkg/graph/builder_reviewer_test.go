package graph

import (
	"sort"
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap/zaptest"
)

// Reviewer-mode tests: confirm Pass 9 (node-derived) and Pass 10 (mount-derived)
// produce the same edges in BuildReviewer() as they do in standard Build().
//
// Both passes are data-driven (identity-agnostic) and now run in reviewer mode.
// The equivalence test pins behavior so future drift is caught: any change to
// either pass must update both standard and reviewer output in the same way.

// edgeKey uniquely identifies an edge for set comparison.
type edgeKey struct {
	From, To string
	Kind     EdgeKind
}

// collectEdges returns the set of edges matching the predicate.
func collectEdges(edges []Edge, match func(*Edge) bool) map[edgeKey]bool {
	out := make(map[edgeKey]bool)
	for i := range edges {
		if match(&edges[i]) {
			e := edges[i]
			out[edgeKey{From: e.From, To: e.To, Kind: e.Kind}] = true
		}
	}
	return out
}

// sortedKeys returns the edge keys as a stable, sorted list for readable failure output.
func sortedKeys(m map[edgeKey]bool) []edgeKey {
	out := make([]edgeKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return string(out[i].Kind) < string(out[j].Kind)
	})
	return out
}

// commonClusterObjects builds a cluster fixture that exercises passes 9 and 10:
//   - node-1 has a privileged pod and a benign pod; pass 9 emits node→SA edges.
//   - sa-c has a workload that mounts my-secret; with no RBAC bindings it gets
//     mount-derived edges from pass 10.
func commonClusterObjects() kube.ClusterObjects {
	return kube.ClusterObjects{
		Namespaces: []kube.NSInfo{{Name: "ns1"}},
		ServiceAccounts: []kube.SAInfo{
			{Name: "sa-a", Namespace: "ns1"},
			{Name: "sa-b", Namespace: "ns1"},
			{Name: "sa-c", Namespace: "ns1"},
		},
		Nodes: []kube.NodeInfo{{Name: "node-1"}},
		Pods: []kube.PodInfo{
			// Privileged pod — triggers EdgeRunsOn to node-1.
			{
				Name: "pod-priv", Namespace: "ns1", Node: "node-1",
				ServiceAccount:       "sa-a",
				PrivilegedContainers: []string{"c1"},
			},
			// Benign pod on the same node — its SA becomes reachable via pass 9.
			{
				Name: "pod-other", Namespace: "ns1", Node: "node-1",
				ServiceAccount: "sa-b",
			},
		},
		Workloads: []kube.WorkloadInfo{
			// Workload using sa-c with a mounted secret. Pass 10 should connect
			// sa-c → [can_get] → secret:ns1:my-secret because sa-c has no RBAC edges.
			{
				Kind: "Deployment", Namespace: "ns1", Name: "app",
				ServiceAccount: "sa-c",
				Volumes: []kube.VolumeRef{
					{Name: "creds", SourceKind: "Secret", SourceName: "my-secret"},
				},
			},
		},
	}
}

// isPass9Edge recognises edges emitted by emitNodeDerivedEdges:
// node → SA (can_get) or node → clusterrole:cluster-admin (inferred host-cred).
func isPass9Edge(e *Edge) bool {
	if !startsWith(e.From, "node:") {
		return false
	}
	switch e.Kind {
	case EdgeCanGet:
		return startsWith(e.To, "sa:")
	case EdgeInferred:
		return e.To == "clusterrole:cluster-admin"
	}
	return false
}

// isPass10Edge recognises edges emitted by emitMountDerivedSAEdges:
// SA → Secret/ConfigMap (can_get) with reason prefix "mount-derived:".
func isPass10Edge(e *Edge) bool {
	if !startsWith(e.From, "sa:") || e.Kind != EdgeCanGet {
		return false
	}
	if !(startsWith(e.To, "secret:") || startsWith(e.To, "configmap:")) {
		return false
	}
	return startsWith(e.Reason, "mount-derived:")
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ── Pass 9 equivalence ───────────────────────────────────────────────────────

func TestBuildReviewer_Pass9_NodeDerivedMatchesStandard(t *testing.T) {
	objs := commonClusterObjects()

	standard := Build(&kube.EnumerationResult{
		Identity:       kube.IdentityInfo{Username: "alice"},
		Permissions:    kube.PermissionsInfo{SSRRByNamespace: map[string][]kube.PolicyRule{}},
		ClusterObjects: objs,
	}, zaptest.NewLogger(t))

	reviewer := BuildReviewer(&kube.ReviewerEnumerateResult{
		EnumerationResult: &kube.EnumerationResult{
			Identity:       kube.IdentityInfo{},
			Permissions:    kube.PermissionsInfo{SSRRByNamespace: map[string][]kube.PolicyRule{}},
			ClusterObjects: objs,
		},
		AllIdentityPerms: nil, // no per-SA rules; pass 10 can therefore enrich sa-c.
	}, zaptest.NewLogger(t))

	stdPass9 := collectEdges(standard.Edges, isPass9Edge)
	revPass9 := collectEdges(reviewer.Edges, isPass9Edge)

	if len(stdPass9) == 0 {
		t.Fatal("standard Build produced no pass-9 edges — fixture does not exercise the pass")
	}
	if len(stdPass9) != len(revPass9) {
		t.Errorf("pass-9 edge count differs: standard=%d reviewer=%d", len(stdPass9), len(revPass9))
	}
	for k := range stdPass9 {
		if !revPass9[k] {
			t.Errorf("reviewer missing pass-9 edge: %+v", k)
		}
	}
	for k := range revPass9 {
		if !stdPass9[k] {
			t.Errorf("reviewer has unexpected pass-9 edge: %+v", k)
		}
	}

	// Concrete spot check — node-1 should reach sa-b (co-located benign pod's SA).
	if !findEdge(reviewer.Edges, "node:node-1", "sa:ns1:sa-b", EdgeCanGet) {
		t.Errorf("expected node:node-1 → sa:ns1:sa-b can_get edge in reviewer mode; got keys: %v", sortedKeys(revPass9))
	}
}

// ── Pass 10 equivalence ──────────────────────────────────────────────────────

func TestBuildReviewer_Pass10_MountDerivedMatchesStandard(t *testing.T) {
	objs := commonClusterObjects()

	standard := Build(&kube.EnumerationResult{
		Identity:       kube.IdentityInfo{Username: "alice"},
		Permissions:    kube.PermissionsInfo{SSRRByNamespace: map[string][]kube.PolicyRule{}},
		ClusterObjects: objs,
	}, zaptest.NewLogger(t))

	reviewer := BuildReviewer(&kube.ReviewerEnumerateResult{
		EnumerationResult: &kube.EnumerationResult{
			Identity:       kube.IdentityInfo{},
			Permissions:    kube.PermissionsInfo{SSRRByNamespace: map[string][]kube.PolicyRule{}},
			ClusterObjects: objs,
		},
		AllIdentityPerms: nil,
	}, zaptest.NewLogger(t))

	stdPass10 := collectEdges(standard.Edges, isPass10Edge)
	revPass10 := collectEdges(reviewer.Edges, isPass10Edge)

	if len(stdPass10) == 0 {
		t.Fatal("standard Build produced no pass-10 edges — fixture does not exercise the pass")
	}
	if len(stdPass10) != len(revPass10) {
		t.Errorf("pass-10 edge count differs: standard=%d reviewer=%d", len(stdPass10), len(revPass10))
	}
	for k := range stdPass10 {
		if !revPass10[k] {
			t.Errorf("reviewer missing pass-10 edge: %+v", k)
		}
	}
	for k := range revPass10 {
		if !stdPass10[k] {
			t.Errorf("reviewer has unexpected pass-10 edge: %+v", k)
		}
	}

	// Concrete spot check — sa-c should reach my-secret via mount-derived edge.
	if !findEdge(reviewer.Edges, "sa:ns1:sa-c", "secret:ns1:my-secret", EdgeCanGet) {
		t.Errorf("expected sa:ns1:sa-c → secret:ns1:my-secret mount-derived edge in reviewer mode")
	}
}

// ── Pass 10 gating: SAs with RBAC-derived caps should be untouched ───────────

func TestBuildReviewer_Pass10_SkipsSAsWithCapabilities(t *testing.T) {
	objs := commonClusterObjects()

	// Give sa-c an explicit RBAC rule so pass-1-reviewer produces a capability
	// edge. Pass 10 is gated on "no existing caps" and must NOT add a mount-
	// derived edge for this SA.
	reviewer := BuildReviewer(&kube.ReviewerEnumerateResult{
		EnumerationResult: &kube.EnumerationResult{
			Identity:       kube.IdentityInfo{},
			Permissions:    kube.PermissionsInfo{SSRRByNamespace: map[string][]kube.PolicyRule{}},
			ClusterObjects: objs,
		},
		AllIdentityPerms: []kube.IdentityPermissions{{
			Subject: "system:serviceaccount:ns1:sa-c", SubjectKind: "ServiceAccount",
			Namespace: "ns1", Name: "sa-c",
			Rules: []kube.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}},
		}},
	}, zaptest.NewLogger(t))

	for _, e := range reviewer.Edges {
		if isPass10Edge(&e) && e.From == "sa:ns1:sa-c" {
			t.Errorf("sa-c has RBAC edges but pass 10 still fired: %+v", e)
		}
	}
}
