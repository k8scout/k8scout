package graph

import (
	"fmt"
	"testing"
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
