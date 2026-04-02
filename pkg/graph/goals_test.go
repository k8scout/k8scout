package graph

import (
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
)

// goalsByKind indexes a []GoalNode slice by GoalKind for easy assertion.
func goalsByKind(goals []GoalNode) map[GoalKind][]GoalNode {
	m := make(map[GoalKind][]GoalNode)
	for _, g := range goals {
		m[g.GoalKind] = append(m[g.GoalKind], g)
	}
	return m
}

// ── ClusterAdmin ─────────────────────────────────────────────────────────────

func TestHighValueTargets_ClusterAdmin_detected(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "crb:admin-binding", Kind: KindClusterRoleBinding, Name: "admin-binding"},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			ClusterRoleBindings: []kube.BindingInfo{
				{
					Name:    "admin-binding",
					RoleRef: kube.RoleRef{Name: "cluster-admin", Kind: "ClusterRole"},
				},
			},
		},
	}
	goals := HighValueTargets(&g, r)
	if len(goals) != 1 {
		t.Fatalf("want 1 goal, got %d", len(goals))
	}
	if goals[0].GoalKind != ClusterAdmin {
		t.Errorf("want GoalKind %q, got %q", ClusterAdmin, goals[0].GoalKind)
	}
	if goals[0].NodeID != "crb:admin-binding" {
		t.Errorf("want NodeID crb:admin-binding, got %q", goals[0].NodeID)
	}
	if goals[0].BaseScore != 10.0 {
		t.Errorf("want BaseScore 10.0, got %f", goals[0].BaseScore)
	}
	if goals[0].Description == "" {
		t.Error("Description must not be empty")
	}
}

func TestHighValueTargets_ClusterAdmin_notClusterAdmin(t *testing.T) {
	// CRB node exists but its RoleRef is NOT cluster-admin.
	g := Graph{
		Nodes: []Node{
			{ID: "crb:readonly-binding", Kind: KindClusterRoleBinding, Name: "readonly-binding"},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			ClusterRoleBindings: []kube.BindingInfo{
				{
					Name:    "readonly-binding",
					RoleRef: kube.RoleRef{Name: "view", Kind: "ClusterRole"},
				},
			},
		},
	}
	goals := HighValueTargets(&g, r)
	if len(goals) != 0 {
		t.Fatalf("want 0 goals for non-cluster-admin CRB, got %d: %+v", len(goals), goals)
	}
}

// ── NodeExec ─────────────────────────────────────────────────────────────────

func TestHighValueTargets_NodeExec_detected(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "node:worker-1", Kind: KindNode, Name: "worker-1"},
			{ID: "node:worker-2", Kind: KindNode, Name: "worker-2"},
		},
	}
	r := &kube.EnumerationResult{}

	goals := HighValueTargets(&g, r)
	if len(goals) != 2 {
		t.Fatalf("want 2 goals for 2 nodes, got %d", len(goals))
	}
	for _, goal := range goals {
		if goal.GoalKind != NodeExec {
			t.Errorf("want GoalKind %q, got %q", NodeExec, goal.GoalKind)
		}
		if goal.BaseScore != 9.0 {
			t.Errorf("want BaseScore 9.0, got %f", goal.BaseScore)
		}
	}
}

// ── SecretAccess ─────────────────────────────────────────────────────────────

func TestHighValueTargets_SecretAccess_capturedValues(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{
				ID: "secret:default:db-creds", Kind: KindSecret,
				Name: "db-creds", Namespace: "default",
				Metadata: map[string]string{
					"has_captured_values": "true",
					"type":                "Opaque",
				},
			},
		},
	}
	r := &kube.EnumerationResult{}
	goals := HighValueTargets(&g, r)
	if len(goals) != 1 || goals[0].GoalKind != SecretAccess {
		t.Fatalf("want 1 SecretAccess goal, got %+v", goals)
	}
}

func TestHighValueTargets_SecretAccess_saTokenType(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{
				ID: "secret:kube-system:default-token", Kind: KindSecret,
				Name: "default-token", Namespace: "kube-system",
				Metadata: map[string]string{
					"type": "kubernetes.io/service-account-token",
				},
			},
		},
	}
	r := &kube.EnumerationResult{}
	goals := HighValueTargets(&g, r)
	if len(goals) != 1 || goals[0].GoalKind != SecretAccess {
		t.Fatalf("want 1 SecretAccess goal for SA token, got %+v", goals)
	}
}

func TestHighValueTargets_SecretAccess_noMatch(t *testing.T) {
	// An ordinary Opaque secret with no captured values — should not be flagged.
	g := Graph{
		Nodes: []Node{
			{
				ID: "secret:default:ordinary", Kind: KindSecret,
				Name: "ordinary", Namespace: "default",
				Metadata: map[string]string{"type": "Opaque"},
			},
		},
	}
	r := &kube.EnumerationResult{}
	goals := HighValueTargets(&g, r)
	if len(goals) != 0 {
		t.Fatalf("want 0 goals for ordinary secret, got %d", len(goals))
	}
}

// ── IdentityTakeover ─────────────────────────────────────────────────────────

func TestHighValueTargets_IdentityTakeover_irsa(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{
				ID: "sa:prod:api-server", Kind: KindServiceAccount,
				Name: "api-server", Namespace: "prod",
				Metadata: map[string]string{
					"cloud_role":     "arn:aws:iam::123456789:role/ProdRole",
					"cloud_provider": "aws",
				},
			},
		},
	}
	r := &kube.EnumerationResult{}
	goals := HighValueTargets(&g, r)
	if len(goals) != 1 {
		t.Fatalf("want 1 goal, got %d", len(goals))
	}
	if goals[0].GoalKind != IdentityTakeover {
		t.Errorf("want GoalKind %q, got %q", IdentityTakeover, goals[0].GoalKind)
	}
	if goals[0].BaseScore != 9.5 {
		t.Errorf("want BaseScore 9.5, got %f", goals[0].BaseScore)
	}
}

func TestHighValueTargets_IdentityTakeover_noCloudRole(t *testing.T) {
	// SA without any cloud annotation — not a high-value target for IdentityTakeover.
	g := Graph{
		Nodes: []Node{
			{
				ID: "sa:default:plain-sa", Kind: KindServiceAccount,
				Name: "plain-sa", Namespace: "default",
			},
		},
	}
	r := &kube.EnumerationResult{}
	goals := HighValueTargets(&g, r)
	if len(goals) != 0 {
		t.Fatalf("want 0 goals for plain SA, got %d: %+v", len(goals), goals)
	}
}

// ── WorkloadTakeover ─────────────────────────────────────────────────────────

func TestHighValueTargets_WorkloadTakeover_privilegedContainer(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{
				ID: "workload:prod:agent", Kind: KindWorkload,
				Name: "agent", Namespace: "prod",
				Metadata: map[string]string{"workload_kind": "DaemonSet"},
			},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			Workloads: []kube.WorkloadInfo{
				{
					Name:                 "agent",
					Namespace:            "prod",
					Kind:                 "DaemonSet",
					PrivilegedContainers: []string{"agent-container"},
				},
			},
		},
	}
	goals := HighValueTargets(&g, r)
	if len(goals) != 1 || goals[0].GoalKind != WorkloadTakeover {
		t.Fatalf("want 1 WorkloadTakeover goal, got %+v", goals)
	}
}

func TestHighValueTargets_WorkloadTakeover_hostPID(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{
				ID: "workload:kube-system:monitor", Kind: KindWorkload,
				Name: "monitor", Namespace: "kube-system",
				Metadata: map[string]string{"workload_kind": "Deployment"},
			},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			Workloads: []kube.WorkloadInfo{
				{Name: "monitor", Namespace: "kube-system", Kind: "Deployment", HostPID: true},
			},
		},
	}
	goals := HighValueTargets(&g, r)
	if len(goals) != 1 || goals[0].GoalKind != WorkloadTakeover {
		t.Fatalf("want 1 WorkloadTakeover goal for hostPID workload, got %+v", goals)
	}
}

func TestHighValueTargets_WorkloadTakeover_normalWorkload_notFlagged(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{
				ID: "workload:default:webapp", Kind: KindWorkload,
				Name: "webapp", Namespace: "default",
				Metadata: map[string]string{"workload_kind": "Deployment"},
			},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			Workloads: []kube.WorkloadInfo{
				{Name: "webapp", Namespace: "default", Kind: "Deployment"},
			},
		},
	}
	goals := HighValueTargets(&g, r)
	if len(goals) != 0 {
		t.Fatalf("want 0 goals for normal workload, got %d: %+v", len(goals), goals)
	}
}

// ── CloudEscalation ──────────────────────────────────────────────────────────

func TestHighValueTargets_CloudEscalation_projectedToken(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{
				ID: "workload:prod:cloud-app", Kind: KindWorkload,
				Name: "cloud-app", Namespace: "prod",
				Metadata: map[string]string{"workload_kind": "Deployment"},
			},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			Workloads: []kube.WorkloadInfo{
				{
					Name:      "cloud-app",
					Namespace: "prod",
					Kind:      "Deployment",
					Volumes: []kube.VolumeRef{
						{Name: "token", SourceKind: "Projected", Audience: "sts.amazonaws.com"},
					},
				},
			},
		},
	}
	goals := HighValueTargets(&g, r)
	if len(goals) != 1 || goals[0].GoalKind != CloudEscalation {
		t.Fatalf("want 1 CloudEscalation goal, got %+v", goals)
	}
	if goals[0].BaseScore != 9.0 {
		t.Errorf("want BaseScore 9.0, got %f", goals[0].BaseScore)
	}
}

// ── Mixed graph / multi-goal ─────────────────────────────────────────────────

func TestHighValueTargets_MixedGraph(t *testing.T) {
	// A realistic graph with multiple node types: some high-value, some not.
	g := Graph{
		Nodes: []Node{
			// high-value: cluster-admin CRB
			{ID: "crb:admin", Kind: KindClusterRoleBinding, Name: "admin"},
			// high-value: node
			{ID: "node:worker-0", Kind: KindNode, Name: "worker-0"},
			// high-value: secret with values
			{
				ID: "secret:default:app-secret", Kind: KindSecret,
				Name: "app-secret", Namespace: "default",
				Metadata: map[string]string{"has_captured_values": "true", "type": "Opaque"},
			},
			// high-value: SA with IRSA
			{
				ID: "sa:prod:backend", Kind: KindServiceAccount,
				Name: "backend", Namespace: "prod",
				Metadata: map[string]string{"cloud_role": "arn:aws:iam::123:role/BackendRole", "cloud_provider": "aws"},
			},
			// high-value: privileged workload
			{
				ID: "workload:prod:agent", Kind: KindWorkload,
				Name: "agent", Namespace: "prod",
				Metadata: map[string]string{"workload_kind": "DaemonSet"},
			},
			// NOT high-value: plain CRB (view role)
			{ID: "crb:viewer", Kind: KindClusterRoleBinding, Name: "viewer"},
			// NOT high-value: plain SA
			{ID: "sa:default:plain", Kind: KindServiceAccount, Name: "plain", Namespace: "default"},
			// NOT high-value: ordinary secret
			{
				ID: "secret:default:boring", Kind: KindSecret,
				Name: "boring", Namespace: "default",
				Metadata: map[string]string{"type": "Opaque"},
			},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			ClusterRoleBindings: []kube.BindingInfo{
				{Name: "admin", RoleRef: kube.RoleRef{Name: "cluster-admin", Kind: "ClusterRole"}},
				{Name: "viewer", RoleRef: kube.RoleRef{Name: "view", Kind: "ClusterRole"}},
			},
			Workloads: []kube.WorkloadInfo{
				{Name: "agent", Namespace: "prod", Kind: "DaemonSet", PrivilegedContainers: []string{"agent"}},
			},
		},
	}

	goals := HighValueTargets(&g, r)
	byKind := goalsByKind(goals)

	// Expect exactly one of each of these kinds.
	for _, kind := range []GoalKind{ClusterAdmin, NodeExec, SecretAccess, IdentityTakeover, WorkloadTakeover} {
		if len(byKind[kind]) != 1 {
			t.Errorf("want 1 %q goal, got %d", kind, len(byKind[kind]))
		}
	}

	// Expect no CloudEscalation (no projected token volumes in this graph).
	if len(byKind[CloudEscalation]) != 0 {
		t.Errorf("want 0 CloudEscalation goals, got %d", len(byKind[CloudEscalation]))
	}

	// Total: 5.
	if len(goals) != 5 {
		t.Errorf("want 5 goals total, got %d: %+v", len(goals), goals)
	}
}

func TestHighValueTargets_EmptyGraph(t *testing.T) {
	g := Graph{}
	r := &kube.EnumerationResult{}
	goals := HighValueTargets(&g, r)
	if len(goals) != 0 {
		t.Fatalf("want 0 goals for empty graph, got %d", len(goals))
	}
}

func TestHighValueTargets_NegativeCase_noFalsePositives(t *testing.T) {
	// Graph with nodes that must NOT produce any goals.
	g := Graph{
		Nodes: []Node{
			{ID: "sa:default:plain", Kind: KindServiceAccount, Name: "plain", Namespace: "default"},
			{ID: "crb:viewer", Kind: KindClusterRoleBinding, Name: "viewer"},
			{ID: "secret:default:generic", Kind: KindSecret, Name: "generic", Namespace: "default",
				Metadata: map[string]string{"type": "Opaque"}},
			{ID: "workload:default:webapp", Kind: KindWorkload, Name: "webapp", Namespace: "default",
				Metadata: map[string]string{"workload_kind": "Deployment"}},
			{ID: "clusterrole:view", Kind: KindClusterRole, Name: "view"},
			{ID: "rb:default:webapp-rb", Kind: KindRoleBinding, Name: "webapp-rb", Namespace: "default"},
		},
	}
	r := &kube.EnumerationResult{
		ClusterObjects: kube.ClusterObjects{
			ClusterRoleBindings: []kube.BindingInfo{
				{Name: "viewer", RoleRef: kube.RoleRef{Name: "view", Kind: "ClusterRole"}},
			},
			Workloads: []kube.WorkloadInfo{
				{Name: "webapp", Namespace: "default", Kind: "Deployment"},
			},
		},
	}
	goals := HighValueTargets(&g, r)
	if len(goals) != 0 {
		t.Fatalf("want 0 goals (no high-value targets), got %d: %+v", len(goals), goals)
	}
}
