package graph

import (
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap/zaptest"
)

// Pass-level tests for pkg/graph/builder.go and its sub-pass files.
//
// These tests pin the behavior of each of the 4 graph-build passes:
//   Pass 1  — SSRR/SSAR direct permission edges (identity → resource)
//   Pass 2  — RBAC binding expansion (CRB/RB → role; SA ↔ binding)
//   Pass 3  — Workload → SA (runs_as) edges
//   Pass 4  — Volume mount edges (workload/pod → Secret / ConfigMap)
//   Pass 5  — Foothold anchoring (in-cluster pod synthesis + SA→identity bridge)
//
// Later passes (6-10) layer inference, transitive, and derived edges on top;
// those are exercised via the rule-level tests and not re-tested here.
//
// All tests call Build() end-to-end and assert the edge/node subset produced
// by the targeted pass. We intentionally avoid asserting the *full* edge count,
// because later passes add more edges and should not break pass-level expectations.

// findEdge returns true if any edge matches from/to/kind.
func findEdge(edges []Edge, from, to string, kind EdgeKind) bool {
	for _, e := range edges {
		if e.From == from && e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

// nodeIDs returns the set of node IDs in the graph for easier assertions.
func nodeIDs(g *Graph) map[string]bool {
	m := make(map[string]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		m[n.ID] = true
	}
	return m
}

// baseEnumeration returns a minimal EnumerationResult ready for per-test population.
func baseEnumeration(username, ns, sa string) *kube.EnumerationResult {
	return &kube.EnumerationResult{
		Identity: kube.IdentityInfo{
			Username:  username,
			Namespace: ns,
			SAName:    sa,
		},
		Permissions: kube.PermissionsInfo{
			SSRRByNamespace: map[string][]kube.PolicyRule{},
		},
	}
}

// ── Pass 1: SSRR direct edges ────────────────────────────────────────────────

func TestBuild_Pass1_SSRREdges(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.Permissions.SSRRByNamespace["default"] = []kube.PolicyRule{
		{Verbs: []string{"list"}, Resources: []string{"pods"}},
	}
	g := Build(r, zaptest.NewLogger(t))

	identity := "identity:alice"
	resource := "resource:default:pods"
	if !nodeIDs(g)[identity] {
		t.Fatalf("missing identity node %q", identity)
	}
	if !nodeIDs(g)[resource] {
		t.Fatalf("missing resource node %q", resource)
	}
	if !findEdge(g.Edges, identity, resource, EdgeCanList) {
		t.Errorf("missing SSRR edge: %s -[can_list]→ %s", identity, resource)
	}
}

// ── Pass 1b: SSAR overlay ────────────────────────────────────────────────────

func TestBuild_Pass1_SSAREdges(t *testing.T) {
	t.Run("SSAR allowed adds edge", func(t *testing.T) {
		r := baseEnumeration("alice", "default", "")
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "secrets", "default")}
		g := Build(r, zaptest.NewLogger(t))
		if !findEdge(g.Edges, "identity:alice", "resource:default:secrets", EdgeCanGet) {
			t.Errorf("missing SSAR edge for get secrets")
		}
	})
	t.Run("SSAR denied does not add edge", func(t *testing.T) {
		r := baseEnumeration("alice", "default", "")
		r.Permissions.SSARChecks = []kube.SSARCheck{denySSAR("get", "secrets", "default")}
		g := Build(r, zaptest.NewLogger(t))
		if findEdge(g.Edges, "identity:alice", "resource:default:secrets", EdgeCanGet) {
			t.Errorf("edge should not exist for denied SSAR")
		}
	})
	t.Run("SSAR subresource encoded in resource name", func(t *testing.T) {
		r := baseEnumeration("alice", "default", "")
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "exec", "ns1")}
		g := Build(r, zaptest.NewLogger(t))
		if !findEdge(g.Edges, "identity:alice", "resource:ns1:pods/exec", EdgeCanCreate) {
			t.Errorf("missing SSAR subresource edge")
		}
	})
}

// ── Pass 2: RBAC binding expansion ───────────────────────────────────────────

func TestBuild_Pass2_ClusterRoleBinding(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.ClusterObjects.ClusterRoles = []kube.RoleInfo{
		{Name: "admin-role", Rules: []kube.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}}},
	}
	r.ClusterObjects.ServiceAccounts = []kube.SAInfo{{Name: "deployer", Namespace: "ns1"}}
	r.ClusterObjects.ClusterRoleBindings = []kube.BindingInfo{{
		Name:    "admin-binding",
		RoleRef: kube.RoleRef{Kind: "ClusterRole", Name: "admin-role"},
		Subjects: []kube.Subject{
			{Kind: "ServiceAccount", Namespace: "ns1", Name: "deployer"},
		},
	}}
	g := Build(r, zaptest.NewLogger(t))

	ids := nodeIDs(g)
	for _, id := range []string{"clusterrole:admin-role", "crb:admin-binding", "sa:ns1:deployer"} {
		if !ids[id] {
			t.Errorf("missing node %q", id)
		}
	}
	if !findEdge(g.Edges, "crb:admin-binding", "clusterrole:admin-role", EdgeBoundTo) {
		t.Errorf("missing CRB → role edge")
	}
	if !findEdge(g.Edges, "crb:admin-binding", "sa:ns1:deployer", EdgeGrants) {
		t.Errorf("missing CRB → SA grants edge")
	}
	// Reverse edge for BFS (SA → binding).
	if !findEdge(g.Edges, "sa:ns1:deployer", "crb:admin-binding", EdgeGrantedBy) {
		t.Errorf("missing SA → CRB granted_by edge")
	}
}

func TestBuild_Pass2_RoleBinding(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.ClusterObjects.Roles = []kube.RoleInfo{
		{Name: "reader", Namespace: "ns1", Rules: []kube.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}}},
	}
	r.ClusterObjects.ServiceAccounts = []kube.SAInfo{{Name: "app-sa", Namespace: "ns1"}}
	r.ClusterObjects.RoleBindings = []kube.BindingInfo{{
		Name: "rb1", Namespace: "ns1",
		RoleRef:  kube.RoleRef{Kind: "Role", Name: "reader"},
		Subjects: []kube.Subject{{Kind: "ServiceAccount", Namespace: "ns1", Name: "app-sa"}},
	}}
	g := Build(r, zaptest.NewLogger(t))

	if !findEdge(g.Edges, "rb:ns1:rb1", "role:ns1:reader", EdgeBoundTo) {
		t.Errorf("missing RB → role edge")
	}
	if !findEdge(g.Edges, "rb:ns1:rb1", "sa:ns1:app-sa", EdgeGrants) {
		t.Errorf("missing RB → SA grants edge")
	}
	if !findEdge(g.Edges, "sa:ns1:app-sa", "rb:ns1:rb1", EdgeGrantedBy) {
		t.Errorf("missing SA → RB granted_by edge")
	}
}

// ── Pass 3: Workload → SA (runs_as) ──────────────────────────────────────────

func TestBuild_Pass3_WorkloadRunsAs(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.ClusterObjects.ServiceAccounts = []kube.SAInfo{{Name: "app-sa", Namespace: "ns1"}}
	r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
		Kind: "Deployment", Namespace: "ns1", Name: "app", ServiceAccount: "app-sa",
	}}
	g := Build(r, zaptest.NewLogger(t))

	if !nodeIDs(g)["workload:ns1:app"] {
		t.Fatalf("missing workload node")
	}
	if !findEdge(g.Edges, "workload:ns1:app", "sa:ns1:app-sa", EdgeRunsAs) {
		t.Errorf("missing workload → SA runs_as edge")
	}
}

// ── Pass 4: Volume mount edges (Secret, ConfigMap, envFrom) ──────────────────

func TestBuild_Pass4_SecretVolume(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
		Kind: "Deployment", Namespace: "ns1", Name: "app",
		Volumes: []kube.VolumeRef{{Name: "db", SourceKind: "Secret", SourceName: "db-creds"}},
	}}
	g := Build(r, zaptest.NewLogger(t))

	if !nodeIDs(g)["secret:ns1:db-creds"] {
		t.Errorf("missing secret node")
	}
	if !findEdge(g.Edges, "workload:ns1:app", "secret:ns1:db-creds", EdgeMounts) {
		t.Errorf("missing workload → secret mounts edge")
	}
}

func TestBuild_Pass4_ConfigMapVolume(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
		Kind: "Deployment", Namespace: "ns1", Name: "app",
		Volumes: []kube.VolumeRef{{Name: "cfg", SourceKind: "ConfigMap", SourceName: "app-config"}},
	}}
	g := Build(r, zaptest.NewLogger(t))

	if !nodeIDs(g)["configmap:ns1:app-config"] {
		t.Errorf("missing configmap node")
	}
	if !findEdge(g.Edges, "workload:ns1:app", "configmap:ns1:app-config", EdgeMounts) {
		t.Errorf("missing workload → configmap mounts edge")
	}
}

func TestBuild_Pass4_EnvSecretRef(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
		Kind: "Deployment", Namespace: "ns1", Name: "app",
		EnvSecretRefs: []kube.EnvSecretRef{{
			Container: "main", SecretName: "api-key", SecretKey: "token", EnvVar: "API_KEY",
		}},
	}}
	g := Build(r, zaptest.NewLogger(t))

	if !nodeIDs(g)["secret:ns1:api-key"] {
		t.Errorf("missing env-referenced secret node")
	}
	if !findEdge(g.Edges, "workload:ns1:app", "secret:ns1:api-key", EdgeMounts) {
		t.Errorf("missing workload → secret mounts edge via envSecretRef")
	}
}

// ── Pass 5a: in-cluster foothold anchoring ───────────────────────────────────

func TestBuild_Pass5_FootholdInCluster(t *testing.T) {
	r := baseEnumeration("system:serviceaccount:ns1:app-sa", "ns1", "app-sa")
	r.Identity.InCluster = true
	r.Identity.PodName = "app-abc123"
	r.Identity.NodeName = "node-1"
	r.Identity.OwnerWorkload = "app"
	r.Identity.OwnerWorkloadKind = "Deployment"

	g := Build(r, zaptest.NewLogger(t))

	ids := nodeIDs(g)
	podID := "pod:ns1:app-abc123"
	saID := "sa:ns1:app-sa"
	identityID := "identity:system:serviceaccount:ns1:app-sa"
	nodeHostID := "node:node-1"

	for _, id := range []string{podID, saID, identityID, nodeHostID} {
		if !ids[id] {
			t.Errorf("missing node %q", id)
		}
	}
	// The foothold pod is tagged.
	for _, n := range g.Nodes {
		if n.ID == podID && n.Metadata["is_foothold"] != "true" {
			t.Errorf("foothold pod missing is_foothold=true metadata, got %v", n.Metadata)
		}
		if n.ID == nodeHostID && n.Metadata["is_foothold_node"] != "true" {
			t.Errorf("foothold node missing is_foothold_node=true metadata, got %v", n.Metadata)
		}
	}
	if !findEdge(g.Edges, podID, saID, EdgeRunsAs) {
		t.Errorf("missing foothold pod → SA runs_as edge")
	}
	if !findEdge(g.Edges, saID, identityID, EdgeRunsAs) {
		t.Errorf("missing SA → identity runs_as edge")
	}
}

// ── Pass 5b: SA → identity bridge, out-of-cluster ────────────────────────────

func TestBuild_Pass5_OutOfClusterSABridge(t *testing.T) {
	r := baseEnumeration("alice", "default", "alice-sa")
	r.ClusterObjects.ServiceAccounts = []kube.SAInfo{{Name: "alice-sa", Namespace: "default"}}

	g := Build(r, zaptest.NewLogger(t))

	if !findEdge(g.Edges, "sa:default:alice-sa", "identity:alice", EdgeRunsAs) {
		t.Errorf("missing SA → identity bridge edge (out-of-cluster)")
	}
}

// ── Pass 5c: concrete pod exec edges ─────────────────────────────────────────

func TestBuild_Pass5_ConcreteExecEdges(t *testing.T) {
	r := baseEnumeration("alice", "default", "")
	r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "exec", "ns1")}
	r.ClusterObjects.Pods = []kube.PodInfo{{Name: "app-abc", Namespace: "ns1"}}

	g := Build(r, zaptest.NewLogger(t))

	// Concrete edge: identity → [can_exec] → pod:ns1:app-abc.
	if !findEdge(g.Edges, "identity:alice", "pod:ns1:app-abc", EdgeCanExec) {
		t.Errorf("missing concrete identity → pod can_exec edge")
	}
}
