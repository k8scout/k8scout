package graph

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap/zaptest"
)

// TestAttackPath_PodToNodeEscape validates chain 1:
//
//	pod → [runs_on] → node (container escape)
func TestAttackPath_PodToNodeEscape(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:pwned", Kind: KindPod, Name: "pwned", Namespace: "default",
				Metadata: map[string]string{"privileged_containers": "main"}},
			{ID: "node:worker-1", Kind: KindNode, Name: "worker-1"},
		},
		Edges: []Edge{
			{From: "pod:default:pwned", To: "node:worker-1", Kind: EdgeRunsOn,
				Reason: "container escape: privileged pod"},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:pwned", "node:worker-1", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected at least 1 path from pod to node")
	}
	if len(paths[0].Path) != 2 {
		t.Fatalf("expected 2-step path (pod → node), got %d steps", len(paths[0].Path))
	}
	if paths[0].Path[1].Edge.Kind != EdgeRunsOn {
		t.Fatalf("expected runs_on edge, got %s", paths[0].Path[1].Edge.Kind)
	}
	// Weight should be 1.0 (container escape)
	if paths[0].Weight != 1.0 {
		t.Fatalf("expected weight 1.0, got %f", paths[0].Weight)
	}
}

// TestAttackPath_ExecToSAToClusterAdmin validates chain 2:
//
//	pod → [can_exec] → target-pod → [runs_as] → SA → [granted_by] → CRB → [bound_to] → cluster-admin
func TestAttackPath_ExecToSAToClusterAdmin(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:attacker", Kind: KindPod, Name: "attacker"},
			{ID: "pod:kube-system:admin-pod", Kind: KindPod, Name: "admin-pod", Namespace: "kube-system"},
			{ID: "sa:kube-system:admin-sa", Kind: KindServiceAccount, Name: "admin-sa", Namespace: "kube-system"},
			{ID: "crb:admin-binding", Kind: KindClusterRoleBinding, Name: "admin-binding"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:default:attacker", To: "pod:kube-system:admin-pod", Kind: EdgeCanExec},
			{From: "pod:kube-system:admin-pod", To: "sa:kube-system:admin-sa", Kind: EdgeRunsAs},
			{From: "sa:kube-system:admin-sa", To: "crb:admin-binding", Kind: EdgeGrantedBy},
			{From: "crb:admin-binding", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:attacker", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected path: pod → exec → pod → SA → CRB → cluster-admin")
	}
	p := paths[0]
	if len(p.Path) != 5 {
		t.Fatalf("expected 5-step path, got %d: %v", len(p.Path), pathNodeIDs(p.Path))
	}
	want := []string{
		"pod:default:attacker",
		"pod:kube-system:admin-pod",
		"sa:kube-system:admin-sa",
		"crb:admin-binding",
		"clusterrole:cluster-admin",
	}
	got := pathNodeIDs(p.Path)
	if !equalSlices(got, want) {
		t.Fatalf("path mismatch:\n  want: %v\n  got:  %v", want, got)
	}
	// Verify weight: exec(1.0) + runs_as(0.1) + granted_by(0.1) + bound_to(0.1) = 1.3
	expectedWeight := 1.3
	if p.Weight < expectedWeight-0.01 || p.Weight > expectedWeight+0.01 {
		t.Fatalf("expected weight ~%.1f, got %f", expectedWeight, p.Weight)
	}
}

// TestAttackPath_SecretTokenToSA validates chain 4:
//
//	pod → [mounts] → secret → [authenticates_as] → SA → [granted_by] → CRB → cluster-admin
func TestAttackPath_SecretTokenToSA(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:app", Kind: KindPod, Name: "app"},
			{ID: "secret:default:admin-token", Kind: KindSecret, Name: "admin-token",
				Metadata: map[string]string{"type": "kubernetes.io/service-account-token"}},
			{ID: "sa:default:admin", Kind: KindServiceAccount, Name: "admin"},
			{ID: "crb:admin-crb", Kind: KindClusterRoleBinding, Name: "admin-crb"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:default:app", To: "secret:default:admin-token", Kind: EdgeMounts},
			{From: "secret:default:admin-token", To: "sa:default:admin", Kind: EdgeAuthenticatesAs},
			{From: "sa:default:admin", To: "crb:admin-crb", Kind: EdgeGrantedBy},
			{From: "crb:admin-crb", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:app", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected path: pod → secret → SA → CRB → cluster-admin")
	}
	p := paths[0]
	if len(p.Path) != 5 {
		t.Fatalf("expected 5-step path, got %d: %v", len(p.Path), pathNodeIDs(p.Path))
	}
	// Verify: mounts(0.3) + authenticates_as(0.5) + granted_by(0.1) + bound_to(0.1) = 1.0
	expectedWeight := 1.0
	if p.Weight < expectedWeight-0.01 || p.Weight > expectedWeight+0.01 {
		t.Fatalf("expected weight ~%.1f, got %f", expectedWeight, p.Weight)
	}
}

// TestAttackPath_WorkloadPatchToSA validates chain 5:
//
//	identity → [can_patch] → workload → [runs_as] → SA → [granted_by] → CRB → cluster-admin
//
// This verifies the shortcut removal: the full chain is visible, not identity → SA.
func TestAttackPath_WorkloadPatchToSA(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "identity:attacker", Kind: KindIdentity, Name: "attacker"},
			{ID: "workload:default:nginx", Kind: KindWorkload, Name: "nginx", Namespace: "default"},
			{ID: "sa:default:powerful-sa", Kind: KindServiceAccount, Name: "powerful-sa", Namespace: "default"},
			{ID: "crb:power-binding", Kind: KindClusterRoleBinding, Name: "power-binding"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "identity:attacker", To: "workload:default:nginx", Kind: EdgeCanPatch,
				Reason: "SSAR: can patch deployments"},
			{From: "workload:default:nginx", To: "sa:default:powerful-sa", Kind: EdgeRunsAs},
			{From: "sa:default:powerful-sa", To: "crb:power-binding", Kind: EdgeGrantedBy},
			{From: "crb:power-binding", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("identity:attacker", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected path: identity → workload → SA → CRB → cluster-admin")
	}
	p := paths[0]
	want := []string{
		"identity:attacker",
		"workload:default:nginx",
		"sa:default:powerful-sa",
		"crb:power-binding",
		"clusterrole:cluster-admin",
	}
	got := pathNodeIDs(p.Path)
	if !equalSlices(got, want) {
		t.Fatalf("path mismatch (shortcut was not removed?):\n  want: %v\n  got:  %v", want, got)
	}
}

// TestAttackPath_CloudIAMEscalation validates chain 6:
//
//	pod → [runs_as] → SA → [assumes_cloud_role] → cloud:aws:arn:...
func TestAttackPath_CloudIAMEscalation(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:app", Kind: KindPod, Name: "app"},
			{ID: "sa:default:irsa-sa", Kind: KindServiceAccount, Name: "irsa-sa",
				Metadata: map[string]string{"cloud_role": "arn:aws:iam::123:role/admin", "cloud_provider": "aws"}},
			{ID: "cloud:aws:arn:aws:iam::123:role/admin", Kind: KindCloudIdentity,
				Name: "arn:aws:iam::123:role/admin",
				Metadata: map[string]string{"cloud_provider": "aws"}},
		},
		Edges: []Edge{
			{From: "pod:default:app", To: "sa:default:irsa-sa", Kind: EdgeRunsAs},
			{From: "sa:default:irsa-sa", To: "cloud:aws:arn:aws:iam::123:role/admin", Kind: EdgeAssumesCloudRole},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:app", "cloud:aws:arn:aws:iam::123:role/admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected path: pod → SA → cloud IAM role")
	}
	if len(paths[0].Path) != 3 {
		t.Fatalf("expected 3-step path, got %d", len(paths[0].Path))
	}
	// Weight: runs_as(0.1) + assumes_cloud_role(0.2) = 0.3
	if paths[0].Weight < 0.29 || paths[0].Weight > 0.31 {
		t.Fatalf("expected weight ~0.3, got %f", paths[0].Weight)
	}
}

// TestAttackPath_ImpersonationChain validates chain 3:
//
//	identity → [can_impersonate] → SA → [granted_by] → CRB → cluster-admin
func TestAttackPath_ImpersonationChain(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "identity:attacker", Kind: KindIdentity, Name: "attacker"},
			{ID: "sa:kube-system:admin-sa", Kind: KindServiceAccount, Name: "admin-sa"},
			{ID: "crb:admin-crb", Kind: KindClusterRoleBinding, Name: "admin-crb"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "identity:attacker", To: "sa:kube-system:admin-sa", Kind: EdgeCanImpersonate},
			{From: "sa:kube-system:admin-sa", To: "crb:admin-crb", Kind: EdgeGrantedBy},
			{From: "crb:admin-crb", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("identity:attacker", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected impersonation path")
	}
	if len(paths[0].Path) != 4 {
		t.Fatalf("expected 4-step path, got %d: %v", len(paths[0].Path), pathNodeIDs(paths[0].Path))
	}
}

// TestAttackPath_WeightedOrdering verifies that FindWeightedPaths returns
// cheaper (more dangerous) paths before expensive ones.
func TestAttackPath_WeightedOrdering(t *testing.T) {
	// Two paths to cluster-admin:
	// Fast path: pod → SA → CRB → cluster-admin (weight: 0.1 + 0.1 + 0.1 = 0.3)
	// Slow path: pod → exec → pod2 → SA → CRB → cluster-admin (weight: 1.0 + 0.1 + 0.1 + 0.1 = 1.3)
	g := Graph{
		Nodes: []Node{
			{ID: "pod:a", Kind: KindPod, Name: "a"},
			{ID: "pod:b", Kind: KindPod, Name: "b"},
			{ID: "sa:direct", Kind: KindServiceAccount, Name: "direct"},
			{ID: "sa:indirect", Kind: KindServiceAccount, Name: "indirect"},
			{ID: "crb:fast", Kind: KindClusterRoleBinding, Name: "fast"},
			{ID: "crb:slow", Kind: KindClusterRoleBinding, Name: "slow"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			// Fast path
			{From: "pod:a", To: "sa:direct", Kind: EdgeRunsAs},
			{From: "sa:direct", To: "crb:fast", Kind: EdgeGrantedBy},
			{From: "crb:fast", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
			// Slow path
			{From: "pod:a", To: "pod:b", Kind: EdgeCanExec},
			{From: "pod:b", To: "sa:indirect", Kind: EdgeRunsAs},
			{From: "sa:indirect", To: "crb:slow", Kind: EdgeGrantedBy},
			{From: "crb:slow", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:a", "clusterrole:cluster-admin", 8, 10)
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 paths, got %d", len(paths))
	}
	if paths[0].Weight >= paths[1].Weight {
		t.Fatalf("first path (weight %.2f) should be cheaper than second (weight %.2f)",
			paths[0].Weight, paths[1].Weight)
	}
	// First path should be the direct one (3 hops, weight ~0.3)
	if len(paths[0].Path) != 4 {
		t.Fatalf("first path should be 4 steps (pod→SA→CRB→CA), got %d", len(paths[0].Path))
	}
}

// TestAttackPath_MemberOfPruned verifies dead-end edges are not followed.
func TestAttackPath_MemberOfPruned(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "sa:default:app", Kind: KindServiceAccount, Name: "app"},
			{ID: "ns:default", Kind: KindNamespace, Name: "default"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "sa:default:app", To: "ns:default", Kind: EdgeMemberOf},
			// No path from ns:default to cluster-admin — dead end.
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("sa:default:app", "clusterrole:cluster-admin", 8, 10)
	if len(paths) != 0 {
		t.Fatalf("expected no paths (member_of should be pruned), got %d", len(paths))
	}
}

// TestAttackPath_QueueBound verifies that the pathfinder doesn't explode
// on a dense graph. This creates a graph where BFS-all-paths would generate
// factorial paths but FindWeightedPaths stays bounded.
func TestAttackPath_QueueBound(t *testing.T) {
	// Create a layered graph: 5 layers of 10 nodes each, fully connected between layers.
	// BFS-all-paths: 10^4 = 10000 paths. Weighted search: finds best K quickly.
	var nodes []Node
	var edges []Edge
	for layer := 0; layer < 5; layer++ {
		for i := 0; i < 10; i++ {
			id := fmt.Sprintf("n:%d:%d", layer, i)
			nodes = append(nodes, Node{ID: id, Kind: KindServiceAccount, Name: id})
		}
	}
	for layer := 0; layer < 4; layer++ {
		for i := 0; i < 10; i++ {
			for j := 0; j < 10; j++ {
				from := fmt.Sprintf("n:%d:%d", layer, i)
				to := fmt.Sprintf("n:%d:%d", layer+1, j)
				edges = append(edges, Edge{From: from, To: to, Kind: EdgeGrantedBy})
			}
		}
	}

	g := Graph{Nodes: nodes, Edges: edges}
	g.BuildIndex()

	// Should complete quickly and return at most 50 paths.
	paths := g.FindWeightedPaths("n:0:0", "n:4:0", 8, 50)
	if len(paths) == 0 {
		t.Fatal("expected at least 1 path in dense graph")
	}
	if len(paths) > 50 {
		t.Fatalf("expected at most 50 paths, got %d", len(paths))
	}
}

// TestAttackPath_RoleImpersonationChain validates that a role granting impersonation
// creates a traversable path: SA → CRB → role → [can_impersonate] → target-SA → CRB → cluster-admin
func TestAttackPath_RoleImpersonationChain(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:foothold", Kind: KindPod, Name: "foothold"},
			{ID: "sa:default:weak-sa", Kind: KindServiceAccount, Name: "weak-sa"},
			{ID: "crb:impersonator-binding", Kind: KindClusterRoleBinding, Name: "impersonator-binding"},
			{ID: "clusterrole:impersonator", Kind: KindClusterRole, Name: "impersonator"},
			{ID: "sa:kube-system:admin-sa", Kind: KindServiceAccount, Name: "admin-sa"},
			{ID: "crb:admin-binding", Kind: KindClusterRoleBinding, Name: "admin-binding"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:default:foothold", To: "sa:default:weak-sa", Kind: EdgeRunsAs},
			{From: "sa:default:weak-sa", To: "crb:impersonator-binding", Kind: EdgeGrantedBy},
			{From: "crb:impersonator-binding", To: "clusterrole:impersonator", Kind: EdgeBoundTo},
			// Role grants impersonation of admin-sa
			{From: "clusterrole:impersonator", To: "sa:kube-system:admin-sa", Kind: EdgeCanImpersonate},
			// admin-sa has cluster-admin
			{From: "sa:kube-system:admin-sa", To: "crb:admin-binding", Kind: EdgeGrantedBy},
			{From: "crb:admin-binding", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:foothold", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected path: pod → SA → CRB → role → impersonate → SA → CRB → cluster-admin")
	}
	p := paths[0]
	if len(p.Path) != 7 {
		t.Fatalf("expected 7-step path, got %d: %v", len(p.Path), pathNodeIDs(p.Path))
	}
	// Weight: runs_as(0.1) + granted_by(0.1) + bound_to(0.1) + can_impersonate(1.5) + granted_by(0.1) + bound_to(0.1) = 2.0
	if p.Weight < 1.99 || p.Weight > 2.01 {
		t.Fatalf("expected weight ~2.0, got %f", p.Weight)
	}
}

// TestAttackPath_SATokenCreateChain validates that a role granting create serviceaccounts/token
// creates a traversable path through SA token creation.
func TestAttackPath_SATokenCreateChain(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:foothold", Kind: KindPod, Name: "foothold"},
			{ID: "sa:default:my-sa", Kind: KindServiceAccount, Name: "my-sa"},
			{ID: "rb:token-creator-binding", Kind: KindRoleBinding, Name: "token-creator-binding"},
			{ID: "role:default:token-creator", Kind: KindRole, Name: "token-creator"},
			{ID: "sa:kube-system:admin-sa", Kind: KindServiceAccount, Name: "admin-sa"},
			{ID: "crb:admin-binding", Kind: KindClusterRoleBinding, Name: "admin-binding"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:default:foothold", To: "sa:default:my-sa", Kind: EdgeRunsAs},
			{From: "sa:default:my-sa", To: "rb:token-creator-binding", Kind: EdgeGrantedBy},
			{From: "rb:token-creator-binding", To: "role:default:token-creator", Kind: EdgeBoundTo},
			// Role grants create SA tokens → can mint tokens for admin-sa
			{From: "role:default:token-creator", To: "sa:kube-system:admin-sa", Kind: EdgeCanCreate,
				Reason: "create serviceaccounts/token"},
			{From: "sa:kube-system:admin-sa", To: "crb:admin-binding", Kind: EdgeGrantedBy},
			{From: "crb:admin-binding", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:foothold", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected path through SA token creation")
	}
	p := paths[0]
	if len(p.Path) != 7 {
		t.Fatalf("expected 7-step path, got %d: %v", len(p.Path), pathNodeIDs(p.Path))
	}
}

// TestAttackPath_FullFootholdChain validates the complete realistic chain from
// a compromised pod foothold through SSRR-based permissions to cluster-admin.
// This is the primary offensive workflow: RCE in pod → SA → identity → capabilities → target.
func TestAttackPath_FullFootholdChain(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:foothold", Kind: KindPod, Name: "foothold",
				Metadata: map[string]string{"is_foothold": "true"}},
			{ID: "sa:default:app-sa", Kind: KindServiceAccount, Name: "app-sa"},
			{ID: "identity:system:serviceaccount:default:app-sa", Kind: KindIdentity, Name: "system:serviceaccount:default:app-sa"},
			{ID: "workload:kube-system:privileged-deploy", Kind: KindWorkload, Name: "privileged-deploy"},
			{ID: "sa:kube-system:admin-sa", Kind: KindServiceAccount, Name: "admin-sa"},
			{ID: "crb:admin-binding", Kind: KindClusterRoleBinding, Name: "admin-binding"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			// pod → SA → identity (foothold synthesis)
			{From: "pod:default:foothold", To: "sa:default:app-sa", Kind: EdgeRunsAs},
			{From: "sa:default:app-sa", To: "identity:system:serviceaccount:default:app-sa", Kind: EdgeRunsAs},
			// identity can patch workloads (SSAR confirmed)
			{From: "identity:system:serviceaccount:default:app-sa", To: "workload:kube-system:privileged-deploy", Kind: EdgeCanPatch},
			// patched workload runs as admin SA
			{From: "workload:kube-system:privileged-deploy", To: "sa:kube-system:admin-sa", Kind: EdgeRunsAs},
			// admin SA has cluster-admin
			{From: "sa:kube-system:admin-sa", To: "crb:admin-binding", Kind: EdgeGrantedBy},
			{From: "crb:admin-binding", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:foothold", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected full foothold chain: pod → SA → identity → patch workload → SA → CRB → cluster-admin")
	}
	p := paths[0]
	want := []string{
		"pod:default:foothold",
		"sa:default:app-sa",
		"identity:system:serviceaccount:default:app-sa",
		"workload:kube-system:privileged-deploy",
		"sa:kube-system:admin-sa",
		"crb:admin-binding",
		"clusterrole:cluster-admin",
	}
	got := pathNodeIDs(p.Path)
	if !equalSlices(got, want) {
		t.Fatalf("path mismatch:\n  want: %v\n  got:  %v", want, got)
	}
	// Weight: runs_as(0.1) + runs_as(0.1) + can_patch(2.0) + runs_as(0.1) + granted_by(0.1) + bound_to(0.1) = 2.5
	if p.Weight < 2.49 || p.Weight > 2.51 {
		t.Fatalf("expected weight ~2.5, got %f", p.Weight)
	}
}

// TestAttackPath_WeakFoothold verifies that when a pod has a weak SA with minimal
// permissions, the system correctly shows limited movement only.
func TestAttackPath_WeakFoothold(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:weak-pod", Kind: KindPod, Name: "weak-pod"},
			{ID: "sa:default:default", Kind: KindServiceAccount, Name: "default"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:default:weak-pod", To: "sa:default:default", Kind: EdgeRunsAs},
			// default SA has no bindings, no capabilities — dead end
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:weak-pod", "clusterrole:cluster-admin", 8, 10)
	if len(paths) != 0 {
		t.Fatalf("expected no paths from weak foothold, got %d", len(paths))
	}
}

// TestPathShape_FullChainWithNewEdges validates that new edge kinds produce
// correct PathShape classification.
func TestPathShape_FullChainWithNewEdges(t *testing.T) {
	tests := []struct {
		name      string
		path      AttackPath
		wantFull  bool
		wantCap   string
	}{
		{
			name: "container escape chain",
			path: AttackPath{
				{Node: &Node{ID: "pod:a", Kind: KindPod}, Hop: 0},
				{Node: &Node{ID: "sa:b", Kind: KindServiceAccount}, Edge: &Edge{Kind: EdgeRunsAs}, Hop: 1},
				{Node: &Node{ID: "crb:c", Kind: KindClusterRoleBinding}, Edge: &Edge{Kind: EdgeGrantedBy}, Hop: 2},
				{Node: &Node{ID: "clusterrole:cluster-admin", Kind: KindClusterRole}, Edge: &Edge{Kind: EdgeBoundTo}, Hop: 3},
			},
			wantFull: true,
			wantCap:  "cluster-admin authority",
		},
		{
			name: "cloud escalation chain",
			path: AttackPath{
				{Node: &Node{ID: "pod:a", Kind: KindPod}, Hop: 0},
				{Node: &Node{ID: "sa:b", Kind: KindServiceAccount}, Edge: &Edge{Kind: EdgeRunsAs}, Hop: 1},
				{Node: &Node{ID: "cloud:aws:role", Kind: KindCloudIdentity}, Edge: &Edge{Kind: EdgeAssumesCloudRole}, Hop: 2},
			},
			wantFull: true,
			wantCap:  "cloud role assumption",
		},
		{
			name: "token theft chain",
			path: AttackPath{
				{Node: &Node{ID: "pod:a", Kind: KindPod}, Hop: 0},
				{Node: &Node{ID: "secret:tok", Kind: KindSecret}, Edge: &Edge{Kind: EdgeMounts}, Hop: 1},
				{Node: &Node{ID: "sa:b", Kind: KindServiceAccount}, Edge: &Edge{Kind: EdgeAuthenticatesAs}, Hop: 2},
			},
			wantFull: true,
			wantCap:  "token theft",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shape := ClassifyPath(tt.path)
			if shape.FullChain != tt.wantFull {
				t.Errorf("FullChain = %v, want %v", shape.FullChain, tt.wantFull)
			}
			if shape.CapabilityLabel != tt.wantCap {
				t.Errorf("CapabilityLabel = %q, want %q", shape.CapabilityLabel, tt.wantCap)
			}
		})
	}
}

// TestTransitiveSAEdges validates that emitTransitiveSAEdges creates direct
// SA→target capability edges by resolving the RBAC chain.
func TestTransitiveSAEdges(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			{ID: "sa:default:app", Kind: KindServiceAccount, Name: "app", Namespace: "default"},
			{ID: "crb:app-binding", Kind: KindClusterRoleBinding, Name: "app-binding"},
			{ID: "clusterrole:secret-reader", Kind: KindClusterRole, Name: "secret-reader"},
			{ID: "secret:default:db-creds", Kind: KindSecret, Name: "db-creds", Namespace: "default"},
			{ID: "node:worker-1", Kind: KindNode, Name: "worker-1"},
		},
		Edges: []Edge{
			{From: "sa:default:app", To: "crb:app-binding", Kind: EdgeGrantedBy},
			{From: "crb:app-binding", To: "clusterrole:secret-reader", Kind: EdgeBoundTo},
			{From: "clusterrole:secret-reader", To: "secret:default:db-creds", Kind: EdgeCanGet},
			{From: "clusterrole:secret-reader", To: "node:worker-1", Kind: EdgeCanList},
		},
	}

	log := zaptest.NewLogger(t)
	emitTransitiveSAEdges(g, log)

	// Should have 2 new transitive edges: SA→secret (can_get) and SA→node (can_list).
	transitiveCount := 0
	for _, e := range g.Edges {
		if e.From == "sa:default:app" && strings.HasPrefix(e.Reason, "transitive:") {
			transitiveCount++
		}
	}
	if transitiveCount != 2 {
		t.Errorf("want 2 transitive edges from SA, got %d", transitiveCount)
		for _, e := range g.Edges {
			if e.From == "sa:default:app" {
				t.Logf("  edge: %s → %s (%s) reason=%s", e.From, e.To, e.Kind, e.Reason)
			}
		}
	}

	// Build index and verify path from SA→secret is 1 hop (direct).
	g.BuildIndex()
	paths := g.FindWeightedPaths("sa:default:app", "secret:default:db-creds", 8, 5)
	if len(paths) == 0 {
		t.Fatal("no path found from SA to secret after transitive edges")
	}
	if len(paths[0].Path) != 2 {
		t.Errorf("want 2-step path (SA→secret), got %d steps", len(paths[0].Path))
	}
}

// TestMultiLevelChain validates that a realistic multi-level attack chain
// is discoverable: pod → SA → identity → patch workload → SA₂ → secret.
func TestMultiLevelChain(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			{ID: "pod:ns:foothold", Kind: KindPod, Name: "foothold", Namespace: "ns"},
			{ID: "sa:ns:weak-sa", Kind: KindServiceAccount, Name: "weak-sa", Namespace: "ns"},
			{ID: "identity:system:serviceaccount:ns:weak-sa", Kind: KindIdentity, Name: "system:serviceaccount:ns:weak-sa"},
			{ID: "workload:ns:target-deploy", Kind: KindWorkload, Name: "target-deploy", Namespace: "ns"},
			{ID: "sa:ns:powerful-sa", Kind: KindServiceAccount, Name: "powerful-sa", Namespace: "ns"},
			{ID: "crb:power-binding", Kind: KindClusterRoleBinding, Name: "power-binding"},
			{ID: "clusterrole:secret-admin", Kind: KindClusterRole, Name: "secret-admin"},
			{ID: "secret:ns:crown-jewels", Kind: KindSecret, Name: "crown-jewels", Namespace: "ns"},
		},
		Edges: []Edge{
			{From: "pod:ns:foothold", To: "sa:ns:weak-sa", Kind: EdgeRunsAs},
			{From: "sa:ns:weak-sa", To: "identity:system:serviceaccount:ns:weak-sa", Kind: EdgeRunsAs},
			{From: "identity:system:serviceaccount:ns:weak-sa", To: "workload:ns:target-deploy", Kind: EdgeCanPatch},
			{From: "workload:ns:target-deploy", To: "sa:ns:powerful-sa", Kind: EdgeRunsAs},
			{From: "sa:ns:powerful-sa", To: "crb:power-binding", Kind: EdgeGrantedBy},
			{From: "crb:power-binding", To: "clusterrole:secret-admin", Kind: EdgeBoundTo},
			{From: "clusterrole:secret-admin", To: "secret:ns:crown-jewels", Kind: EdgeCanGet},
		},
	}

	log := zaptest.NewLogger(t)
	emitTransitiveSAEdges(g, log)
	g.BuildIndex()

	// Should find multi-level path.
	paths := g.FindWeightedPaths("pod:ns:foothold", "secret:ns:crown-jewels", 12, 5)
	if len(paths) == 0 {
		t.Fatal("no multi-level path found from foothold to secret")
	}

	// With transitive edges, shortest should be 6 steps (pod→SA→identity→workload→SA₂→secret).
	shortest := paths[0]
	if len(shortest.Path) > 6 {
		t.Errorf("want ≤6-step shortest path, got %d steps", len(shortest.Path))
		for _, step := range shortest.Path {
			if step.Edge != nil {
				t.Logf("  %s → [%s] → %s", step.Edge.From, step.Edge.Kind, step.Node.ID)
			} else {
				t.Logf("  START: %s", step.Node.ID)
			}
		}
	}

	// Weight: runs_as(0.1) + runs_as(0.1) + can_patch(2.0) + runs_as(0.1) + can_get(1.0) = 3.3
	expectedWeight := 3.3
	if shortest.Weight < expectedWeight-0.5 || shortest.Weight > expectedWeight+0.5 {
		t.Errorf("want weight ~%.1f, got %.2f", expectedWeight, shortest.Weight)
	}

	// Classify path stages.
	stages := classifyPathStages(shortest.Path)
	if len(stages) < 3 {
		t.Errorf("want ≥3 attack stages, got %d", len(stages))
		for _, s := range stages {
			t.Logf("  stage %d: %s — %s", s.Stage, s.Label, s.Description)
		}
	}
	if len(stages) > 0 && stages[0].Label != "Initial Foothold (Pod)" {
		t.Errorf("stage 0 label = %q, want 'Initial Foothold (Pod)'", stages[0].Label)
	}
}

// TestDerivedFootholdEdges validates that emitDerivedFootholdEdges creates
// edges for SAs reachable through workload takeover.
func TestDerivedFootholdEdges(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			{ID: "identity:system:serviceaccount:ns:my-sa", Kind: KindIdentity, Name: "system:serviceaccount:ns:my-sa"},
			{ID: "workload:ns:target", Kind: KindWorkload, Name: "target", Namespace: "ns"},
			{ID: "sa:ns:target-sa", Kind: KindServiceAccount, Name: "target-sa", Namespace: "ns"},
			{ID: "pod:ns:victim", Kind: KindPod, Name: "victim", Namespace: "ns"},
			{ID: "sa:ns:victim-sa", Kind: KindServiceAccount, Name: "victim-sa", Namespace: "ns"},
		},
		Edges: []Edge{
			{From: "identity:system:serviceaccount:ns:my-sa", To: "workload:ns:target", Kind: EdgeCanPatch},
			{From: "workload:ns:target", To: "sa:ns:target-sa", Kind: EdgeRunsAs},
			{From: "identity:system:serviceaccount:ns:my-sa", To: "pod:ns:victim", Kind: EdgeCanExec},
			{From: "pod:ns:victim", To: "sa:ns:victim-sa", Kind: EdgeRunsAs},
		},
	}

	result := &kube.EnumerationResult{
		Identity: kube.IdentityInfo{
			Username: "system:serviceaccount:ns:my-sa",
		},
	}

	log := zaptest.NewLogger(t)
	emitDerivedFootholdEdges(g, result, log)

	derivedEdges := 0
	for _, e := range g.Edges {
		if strings.Contains(e.Reason, "derived foothold") {
			derivedEdges++
		}
	}
	if derivedEdges < 1 {
		t.Errorf("want ≥1 derived foothold edges, got %d", derivedEdges)
	}

	// Check SA nodes are marked as derived footholds.
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.ID == "sa:ns:target-sa" || n.ID == "sa:ns:victim-sa" {
			if n.Metadata == nil || n.Metadata["derived_foothold"] != "true" {
				t.Errorf("SA %s should be marked as derived foothold", n.ID)
			}
		}
	}
}

// TestDerivedSSRREdges validates that emitDerivedSSRREdges creates concrete
// capability edges for SAs whose permissions were discovered via impersonation.
func TestDerivedSSRREdges(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			{ID: "pod:ns:foothold", Kind: KindPod, Name: "foothold", Namespace: "ns"},
			{ID: "sa:ns:weak-sa", Kind: KindServiceAccount, Name: "weak-sa", Namespace: "ns"},
			{ID: "identity:system:serviceaccount:ns:weak-sa", Kind: KindIdentity, Name: "system:serviceaccount:ns:weak-sa"},
			{ID: "workload:ns:target", Kind: KindWorkload, Name: "target", Namespace: "ns"},
			{ID: "sa:ns:powerful-sa", Kind: KindServiceAccount, Name: "powerful-sa", Namespace: "ns"},
			{ID: "secret:ns:crown-jewels", Kind: KindSecret, Name: "crown-jewels", Namespace: "ns"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:ns:foothold", To: "sa:ns:weak-sa", Kind: EdgeRunsAs},
			{From: "sa:ns:weak-sa", To: "identity:system:serviceaccount:ns:weak-sa", Kind: EdgeRunsAs},
			{From: "identity:system:serviceaccount:ns:weak-sa", To: "workload:ns:target", Kind: EdgeCanPatch},
			{From: "workload:ns:target", To: "sa:ns:powerful-sa", Kind: EdgeRunsAs},
			// Note: NO RBAC edges — powerful-sa has no bindings in the graph.
			// This simulates the scenario where RBAC objects can't be enumerated.
		},
	}

	// Simulate enrichment data: powerful-sa was discovered to have get secrets permission.
	result := &kube.EnumerationResult{
		Identity: kube.IdentityInfo{
			Username: "system:serviceaccount:ns:weak-sa",
		},
		ClusterObjects: kube.ClusterObjects{
			SecretsMeta: []kube.SecretMeta{
				{Name: "crown-jewels", Namespace: "ns", Type: "Opaque"},
			},
		},
		DerivedIdentities: []kube.DerivedIdentity{
			{
				SAName:    "powerful-sa",
				Namespace: "ns",
				Username:  "system:serviceaccount:ns:powerful-sa",
				How:       "patch workload ns/target",
				SSRRRules: map[string][]kube.PolicyRule{
					"ns": {
						{Verbs: []string{"get", "list"}, Resources: []string{"secrets"}, APIGroups: []string{""}},
						{Verbs: []string{"create", "patch"}, Resources: []string{"clusterrolebindings"}, APIGroups: []string{"rbac.authorization.k8s.io"}},
					},
				},
			},
		},
	}

	log := zaptest.NewLogger(t)
	emitDerivedSSRREdges(g, result, log)
	g.BuildIndex()

	// powerful-sa should now have edges to the secret and cluster-admin.
	var secretEdge, adminEdge bool
	for _, e := range g.Edges {
		if e.From == "sa:ns:powerful-sa" && e.To == "secret:ns:crown-jewels" && e.Kind == EdgeCanGet {
			secretEdge = true
		}
		if e.From == "sa:ns:powerful-sa" && e.To == "clusterrole:cluster-admin" && e.Kind == EdgeCanCreate {
			adminEdge = true
		}
	}
	if !secretEdge {
		t.Error("want enriched edge: powerful-sa → secret:ns:crown-jewels (can_get)")
	}
	if !adminEdge {
		t.Error("want enriched edge: powerful-sa → clusterrole:cluster-admin (can_create)")
	}

	// Full chain should now be discoverable.
	paths := g.FindWeightedPaths("pod:ns:foothold", "secret:ns:crown-jewels", 12, 5)
	if len(paths) == 0 {
		t.Fatal("no path found from foothold to secret after enrichment")
	}

	// Verify the path goes through the enriched SA.
	found := false
	for _, step := range paths[0].Path {
		if step.Node.ID == "sa:ns:powerful-sa" {
			found = true
			break
		}
	}
	if !found {
		t.Error("shortest path should traverse through enriched SA powerful-sa")
		for _, step := range paths[0].Path {
			t.Logf("  step: %s", step.Node.ID)
		}
	}

	t.Logf("path found: %d hops, weight %.2f", len(paths[0].Path)-1, paths[0].Weight)
	for _, step := range paths[0].Path {
		if step.Edge != nil {
			t.Logf("  %s → [%s] → %s", step.Edge.From, step.Edge.Kind, step.Node.ID)
		} else {
			t.Logf("  START: %s", step.Node.ID)
		}
	}
}

// TestStageClassification validates stage classification for different chain shapes.
func TestStageClassification(t *testing.T) {
	tests := []struct {
		name       string
		path       AttackPath
		wantStages int
		wantFirst  string
	}{
		{
			name: "pod → SA → identity → workload → SA₂ → secret",
			path: AttackPath{
				{Node: &Node{ID: "pod:ns:foot", Kind: KindPod, Name: "foot"}, Hop: 0},
				{Node: &Node{ID: "sa:ns:sa1", Kind: KindServiceAccount, Name: "sa1"}, Edge: &Edge{Kind: EdgeRunsAs}, Hop: 1},
				{Node: &Node{ID: "id:sa1", Kind: KindIdentity, Name: "sa1"}, Edge: &Edge{Kind: EdgeRunsAs}, Hop: 2},
				{Node: &Node{ID: "wl:ns:target", Kind: KindWorkload, Name: "target", Namespace: "ns"}, Edge: &Edge{Kind: EdgeCanPatch}, Hop: 3},
				{Node: &Node{ID: "sa:ns:sa2", Kind: KindServiceAccount, Name: "sa2"}, Edge: &Edge{Kind: EdgeRunsAs}, Hop: 4},
				{Node: &Node{ID: "secret:ns:db", Kind: KindSecret, Name: "db", Namespace: "ns"}, Edge: &Edge{Kind: EdgeCanGet}, Hop: 5},
			},
			wantStages: 5,
			wantFirst:  "Initial Foothold (Pod)",
		},
		{
			name: "pod → node (container escape)",
			path: AttackPath{
				{Node: &Node{ID: "pod:ns:priv", Kind: KindPod, Name: "priv"}, Hop: 0},
				{Node: &Node{ID: "node:worker", Kind: KindNode, Name: "worker"}, Edge: &Edge{Kind: EdgeRunsOn}, Hop: 1},
			},
			wantStages: 2,
			wantFirst:  "Initial Foothold (Pod)",
		},
		{
			name: "SA → cloud identity",
			path: AttackPath{
				{Node: &Node{ID: "sa:ns:cloud-sa", Kind: KindServiceAccount, Name: "cloud-sa"}, Hop: 0},
				{Node: &Node{ID: "cloud:aws:role", Kind: KindCloudIdentity, Name: "ProdRole"}, Edge: &Edge{Kind: EdgeAssumesCloudRole}, Hop: 1},
			},
			wantStages: 2,
			wantFirst:  "SA Entry Point",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stages := classifyPathStages(tt.path)
			if len(stages) != tt.wantStages {
				t.Errorf("want %d stages, got %d", tt.wantStages, len(stages))
				for _, s := range stages {
					t.Logf("  stage %d: %s — %s (%s)", s.Stage, s.Label, s.Description, s.NodeID)
				}
			}
			if len(stages) > 0 && stages[0].Label != tt.wantFirst {
				t.Errorf("first stage label = %q, want %q", stages[0].Label, tt.wantFirst)
			}
		})
	}
}

// TestWeakFootholdChain_TokenTheftWithoutImpersonation validates a chain
// starting from a low-privilege SA that reads a mounted SA-token secret
// (via the secret itself being in the pod's filesystem) and authenticates
// as the higher-privilege SA — no impersonation required.
func TestWeakFootholdChain_TokenTheftWithoutImpersonation(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:app:worker", Kind: KindPod, Name: "worker", Namespace: "app"},
			{ID: "sa:app:worker", Kind: KindServiceAccount, Name: "worker", Namespace: "app"},
			{ID: "secret:app:admin-token", Kind: KindSecret, Name: "admin-token", Namespace: "app",
				Metadata: map[string]string{"type": "kubernetes.io/service-account-token", "sa_name": "admin-sa"}},
			{ID: "sa:app:admin-sa", Kind: KindServiceAccount, Name: "admin-sa", Namespace: "app"},
			{ID: "crb:admin-cluster-admin", Kind: KindClusterRoleBinding, Name: "admin-cluster-admin"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:app:worker", To: "sa:app:worker", Kind: EdgeRunsAs},
			{From: "pod:app:worker", To: "secret:app:admin-token", Kind: EdgeMounts},
			{From: "secret:app:admin-token", To: "sa:app:admin-sa", Kind: EdgeAuthenticatesAs},
			{From: "sa:app:admin-sa", To: "crb:admin-cluster-admin", Kind: EdgeGrantedBy},
			{From: "crb:admin-cluster-admin", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:app:worker", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected a token-theft chain from weak foothold to cluster-admin")
	}
	got := pathNodeIDs(paths[0].Path)
	if !containsStr(got, "secret:app:admin-token") || !containsStr(got, "sa:app:admin-sa") {
		t.Fatalf("path did not traverse mounted SA-token → admin-sa: %v", got)
	}
}

// TestWeakFootholdChain_NodeEscapeStealsColocatedSAToken validates:
//
//	privileged pod → node → [can_get] → co-located pod's SA → cluster-admin
func TestWeakFootholdChain_NodeEscapeStealsColocatedSAToken(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:privileged", Kind: KindPod, Name: "privileged", Namespace: "default",
				Metadata: map[string]string{"privileged_containers": "main"}},
			{ID: "node:worker-1", Kind: KindNode, Name: "worker-1"},
			{ID: "sa:kube-system:kube-proxy", Kind: KindServiceAccount, Name: "kube-proxy", Namespace: "kube-system"},
			{ID: "crb:kube-proxy-admin", Kind: KindClusterRoleBinding, Name: "kube-proxy-admin"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "pod:default:privileged", To: "node:worker-1", Kind: EdgeRunsOn,
				Reason: "container escape: privileged pod"},
			{From: "node:worker-1", To: "sa:kube-system:kube-proxy", Kind: EdgeCanGet,
				Reason: "host access: steal SA token from pod on this node"},
			{From: "sa:kube-system:kube-proxy", To: "crb:kube-proxy-admin", Kind: EdgeGrantedBy},
			{From: "crb:kube-proxy-admin", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:privileged", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected node-escape chain to cluster-admin")
	}
	got := pathNodeIDs(paths[0].Path)
	want := []string{
		"pod:default:privileged",
		"node:worker-1",
		"sa:kube-system:kube-proxy",
		"crb:kube-proxy-admin",
		"clusterrole:cluster-admin",
	}
	if !equalSlices(got, want) {
		t.Fatalf("path mismatch:\n  want: %v\n  got:  %v", want, got)
	}

	// Validate that the node pivot stage is classified.
	stages := classifyPathStages(paths[0].Path)
	foundNodePivot := false
	foundEscape := false
	for _, s := range stages {
		if s.Label == "Node Pivot" {
			foundNodePivot = true
		}
		if s.Label == "Container Escape" {
			foundEscape = true
		}
	}
	if !foundEscape {
		t.Errorf("expected Container Escape stage, got %v", stages)
	}
	if !foundNodePivot {
		t.Errorf("expected Node Pivot stage, got %v", stages)
	}
}

// TestWeakFootholdChain_WorkloadTakeoverMountedSecretNewIdentity validates:
//
//	identity → [can_patch] → workload → [mounts] → secret → [authenticates_as] → SA₂ → admin
func TestWeakFootholdChain_WorkloadTakeoverMountedSecretNewIdentity(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "identity:weak", Kind: KindIdentity, Name: "weak"},
			{ID: "workload:default:app", Kind: KindWorkload, Name: "app", Namespace: "default"},
			{ID: "secret:default:app-token", Kind: KindSecret, Name: "app-token", Namespace: "default",
				Metadata: map[string]string{"type": "kubernetes.io/service-account-token", "sa_name": "app-sa"}},
			{ID: "sa:default:app-sa", Kind: KindServiceAccount, Name: "app-sa", Namespace: "default"},
			{ID: "crb:app-admin", Kind: KindClusterRoleBinding, Name: "app-admin"},
			{ID: "clusterrole:cluster-admin", Kind: KindClusterRole, Name: "cluster-admin"},
		},
		Edges: []Edge{
			{From: "identity:weak", To: "workload:default:app", Kind: EdgeCanPatch,
				Reason: "patch deployment → inject code → run as workload's SA"},
			{From: "workload:default:app", To: "secret:default:app-token", Kind: EdgeMounts},
			{From: "secret:default:app-token", To: "sa:default:app-sa", Kind: EdgeAuthenticatesAs},
			{From: "sa:default:app-sa", To: "crb:app-admin", Kind: EdgeGrantedBy},
			{From: "crb:app-admin", To: "clusterrole:cluster-admin", Kind: EdgeBoundTo},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("identity:weak", "clusterrole:cluster-admin", 8, 10)
	if len(paths) == 0 {
		t.Fatal("expected workload-takeover → mounted secret → new identity chain")
	}
	got := pathNodeIDs(paths[0].Path)
	if !containsStr(got, "workload:default:app") ||
		!containsStr(got, "secret:default:app-token") ||
		!containsStr(got, "sa:default:app-sa") {
		t.Fatalf("path missing expected hops: %v", got)
	}
}

// containsStr reports whether s contains target.
func containsStr(s []string, target string) bool {
	for _, x := range s {
		if x == target {
			return true
		}
	}
	return false
}

// TestAttackPath_WebhookBackendTakeover validates the admission controller attack chain:
//
//	pod → [can_exec] → webhook-backend → [serves_webhook] → webhook → [can_mutate_workloads] → target-workload
//
// An attacker who can exec into the webhook backend workload controls all future pod mutations.
func TestAttackPath_WebhookBackendTakeover(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:attacker", Kind: KindPod, Name: "attacker", Namespace: "default"},
			{ID: "workload:webhook-ns:admission-controller", Kind: KindWorkload, Name: "admission-controller", Namespace: "webhook-ns"},
			{ID: "webhook:my-mutator/pod-injector", Kind: KindWebhook, Name: "my-mutator/pod-injector",
				Metadata: map[string]string{
					"webhook_kind":    "Mutating",
					"intercepts_pods": "true",
					"service_name":    "admission-controller",
					"service_ns":      "webhook-ns",
				}},
			{ID: "workload:prod:api-server", Kind: KindWorkload, Name: "api-server", Namespace: "prod"},
		},
		Edges: []Edge{
			{From: "pod:default:attacker", To: "workload:webhook-ns:admission-controller", Kind: EdgeCanExec},
			{From: "workload:webhook-ns:admission-controller", To: "webhook:my-mutator/pod-injector", Kind: EdgeServesWebhook,
				Reason: "workload backs webhook via Service"},
			{From: "webhook:my-mutator/pod-injector", To: "workload:prod:api-server", Kind: EdgeCanMutateWorkloads,
				Reason: "mutating webhook intercepts pod creation", Inferred: true},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:attacker", "workload:prod:api-server", MaxAttackPathDepth, 10)
	if len(paths) == 0 {
		t.Fatal("expected path: pod → exec → backend-workload → serves_webhook → webhook → can_mutate_workloads → target")
	}
	p := paths[0]
	if len(p.Path) != 4 {
		t.Fatalf("expected 4-step path, got %d: %v", len(p.Path), pathNodeIDs(p.Path))
	}
	want := []string{
		"pod:default:attacker",
		"workload:webhook-ns:admission-controller",
		"webhook:my-mutator/pod-injector",
		"workload:prod:api-server",
	}
	got := pathNodeIDs(p.Path)
	for i, w := range want {
		if got[i] != w {
			t.Errorf("step %d: want %q, got %q", i, w, got[i])
		}
	}
	// Weight: can_exec(1.0) + serves_webhook(0.1) + can_mutate_workloads(3.0) = 4.1
	expectedWeight := 4.1
	if p.Weight < expectedWeight-0.01 || p.Weight > expectedWeight+0.01 {
		t.Fatalf("expected weight ~%.1f, got %f", expectedWeight, p.Weight)
	}
}

// TestAttackPath_WebhookPatchToMutation validates the RBAC-based webhook attack chain:
//
//	pod → [runs_as] → SA → [granted_by] → CRB → [bound_to] → role → [can_patch] → webhook → [can_mutate_workloads] → target
//
// An identity with patch permissions on MutatingWebhookConfigurations can redirect the webhook endpoint.
func TestAttackPath_WebhookPatchToMutation(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "pod:default:foothold", Kind: KindPod, Name: "foothold", Namespace: "default"},
			{ID: "sa:default:app-sa", Kind: KindServiceAccount, Name: "app-sa", Namespace: "default"},
			{ID: "crb:webhook-admin", Kind: KindClusterRoleBinding, Name: "webhook-admin"},
			{ID: "clusterrole:webhook-manager", Kind: KindClusterRole, Name: "webhook-manager"},
			{ID: "webhook:istio-sidecar/injector", Kind: KindWebhook, Name: "istio-sidecar/injector",
				Metadata: map[string]string{
					"webhook_kind":    "Mutating",
					"intercepts_pods": "true",
				}},
			{ID: "workload:prod:payment-svc", Kind: KindWorkload, Name: "payment-svc", Namespace: "prod"},
		},
		Edges: []Edge{
			{From: "pod:default:foothold", To: "sa:default:app-sa", Kind: EdgeRunsAs},
			{From: "sa:default:app-sa", To: "crb:webhook-admin", Kind: EdgeGrantedBy},
			{From: "crb:webhook-admin", To: "clusterrole:webhook-manager", Kind: EdgeBoundTo},
			{From: "clusterrole:webhook-manager", To: "webhook:istio-sidecar/injector", Kind: EdgeCanPatch,
				Reason: "can patch mutating webhook"},
			{From: "webhook:istio-sidecar/injector", To: "workload:prod:payment-svc", Kind: EdgeCanMutateWorkloads,
				Reason: "mutating webhook intercepts pod creation", Inferred: true},
		},
	}
	g.BuildIndex()

	paths := g.FindWeightedPaths("pod:default:foothold", "workload:prod:payment-svc", MaxAttackPathDepth, 10)
	if len(paths) == 0 {
		t.Fatal("expected path through RBAC → webhook patch → mutation")
	}
	p := paths[0]
	got := pathNodeIDs(p.Path)
	if len(got) != 6 {
		t.Fatalf("expected 6-step path, got %d: %v", len(got), got)
	}
	if got[4] != "webhook:istio-sidecar/injector" {
		t.Errorf("expected webhook node at step 4, got %q", got[4])
	}
	if got[5] != "workload:prod:payment-svc" {
		t.Errorf("expected target workload at step 5, got %q", got[5])
	}
}

// TestAttackPath_WebhookBuildIntegration validates that Build() correctly creates
// serves_webhook and can_mutate_workloads edges from EnumerationResult data.
func TestAttackPath_WebhookBuildIntegration(t *testing.T) {
	log := zaptest.NewLogger(t)
	result := &kube.EnumerationResult{
		Identity: kube.IdentityInfo{
			Username:  "system:serviceaccount:default:test-sa",
			Namespace: "default",
			SAName:    "test-sa",
		},
		Permissions: kube.PermissionsInfo{
			SSRRByNamespace: map[string][]kube.PolicyRule{},
		},
		ClusterObjects: kube.ClusterObjects{
			Namespaces: []kube.NSInfo{{Name: "default"}, {Name: "webhook-ns"}},
			ServiceAccounts: []kube.SAInfo{
				{Name: "test-sa", Namespace: "default"},
				{Name: "webhook-sa", Namespace: "webhook-ns"},
			},
			Workloads: []kube.WorkloadInfo{
				{Kind: "Deployment", Name: "webhook-server", Namespace: "webhook-ns", ServiceAccount: "webhook-sa"},
				{Kind: "Deployment", Name: "target-app", Namespace: "default", ServiceAccount: "test-sa"},
			},
			Webhooks: []kube.WebhookInfo{
				{
					Name:           "my-injector/sidecar",
					Kind:           "Mutating",
					ServiceName:    "webhook-server",
					ServiceNS:      "webhook-ns",
					InterceptsPods: true,
					Rules:          []string{"*/pods"},
					Operations:     []string{"CREATE"},
				},
			},
		},
	}

	g := Build(result, log)

	// Check that serves_webhook edge was created.
	foundServesWebhook := false
	foundCanMutate := false
	for _, e := range g.Edges {
		if e.Kind == EdgeServesWebhook && e.From == "workload:webhook-ns:webhook-server" && e.To == "webhook:my-injector/sidecar" {
			foundServesWebhook = true
		}
		if e.Kind == EdgeCanMutateWorkloads && e.From == "webhook:my-injector/sidecar" && e.To == "workload:default:target-app" {
			foundCanMutate = true
		}
	}
	if !foundServesWebhook {
		t.Error("missing serves_webhook edge from backend workload to webhook")
	}
	if !foundCanMutate {
		t.Error("missing can_mutate_workloads edge from webhook to target workload")
	}

	// Check that webhook node has intercepts_pods metadata.
	whNode := g.nodeByID("webhook:my-injector/sidecar")
	if whNode == nil {
		t.Fatal("webhook node not found in graph")
	}
	if whNode.Metadata["intercepts_pods"] != "true" {
		t.Errorf("webhook node missing intercepts_pods=true metadata, got %q", whNode.Metadata["intercepts_pods"])
	}
}

// ensure fmt/strings imports stay used in this file even if tests evolve.
var _ = fmt.Sprintf
var _ = strings.Join
