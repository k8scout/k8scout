// Package graph builds and analyzes the Kubernetes permission graph.
package graph

// NodeKind enumerates graph node types.
type NodeKind string

const (
	KindIdentity            NodeKind = "Identity"
	KindServiceAccount      NodeKind = "ServiceAccount"
	KindNamespace           NodeKind = "Namespace"
	KindRole                NodeKind = "Role"
	KindClusterRole         NodeKind = "ClusterRole"
	KindRoleBinding         NodeKind = "RoleBinding"
	KindClusterRoleBinding  NodeKind = "ClusterRoleBinding"
	KindWorkload            NodeKind = "Workload"
	KindPod                 NodeKind = "Pod"
	KindSecret              NodeKind = "Secret"
	KindConfigMap           NodeKind = "ConfigMap"
	KindNode                NodeKind = "Node"
	KindWebhook             NodeKind = "Webhook"
	KindCRD                 NodeKind = "CRD"
)

// EdgeKind enumerates directed edge relationship types.
type EdgeKind string

const (
	EdgeCanList        EdgeKind = "can_list"
	EdgeCanGet         EdgeKind = "can_get"
	EdgeCanCreate      EdgeKind = "can_create"
	EdgeCanPatch       EdgeKind = "can_patch"
	EdgeCanDelete      EdgeKind = "can_delete"
	EdgeCanExec        EdgeKind = "can_exec"
	EdgeCanImpersonate EdgeKind = "can_impersonate"
	// EdgeCanEscalate — can create/update roles with permissions the identity doesn't hold.
	EdgeCanEscalate EdgeKind = "can_escalate"
	// EdgeCanBind — can create role bindings for roles the identity doesn't hold.
	EdgeCanBind    EdgeKind = "can_bind"
	EdgeMounts     EdgeKind = "mounts"
	EdgeRunsAs     EdgeKind = "runs_as"
	EdgeBoundTo    EdgeKind = "bound_to"
	EdgeGrants     EdgeKind = "grants"
	EdgeMemberOf   EdgeKind = "member_of"
	EdgeInferred   EdgeKind = "inferred"
)

// Node represents a vertex in the permission graph.
type Node struct {
	ID        string            `json:"id"`
	Kind      NodeKind          `json:"kind"`
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels,omitempty"`
	RiskScore float64           `json:"risk_score"`
	// Metadata holds kind-specific extra fields (e.g., workload kind, secret type).
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Edge represents a directed relationship in the permission graph.
type Edge struct {
	From   string   `json:"from"`
	To     string   `json:"to"`
	Kind   EdgeKind `json:"kind"`
	Reason string   `json:"reason,omitempty"`
	// Inferred marks edges derived by the inference engine (not directly observed).
	Inferred bool `json:"inferred,omitempty"`
}

// Graph is the complete permission graph.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// nodeMap is an internal structure for deduplication and lookups.
type nodeMap map[string]*Node
