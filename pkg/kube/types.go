// Package kube — shared data types for enumeration results.
package kube

import "go.uber.org/zap"

// EnumerationResult is the raw, collected data from all collectors.
type EnumerationResult struct {
	Identity       IdentityInfo
	Permissions    PermissionsInfo
	ClusterObjects ClusterObjects
	AuditFootprint []AuditEntry `json:"audit_footprint,omitempty"`
}

// AuditEntry records a single API call category for the stealth audit footprint report.
type AuditEntry struct {
	Action     string `json:"action"`
	Count      int    `json:"count"`
	Skipped    bool   `json:"skipped"`
	NoiseLevel string `json:"noise_level"` // "high", "medium", "low"
}

// IdentityInfo describes the current authenticated identity.
type IdentityInfo struct {
	Username  string              `json:"username"`
	UID       string              `json:"uid,omitempty"`
	Groups    []string            `json:"groups,omitempty"`
	Namespace string              `json:"namespace,omitempty"`
	SAName    string              `json:"sa_name,omitempty"`
	Extra     map[string][]string `json:"extra,omitempty"`
}

// PermissionsInfo holds SSRR results and SSAR spot-checks.
type PermissionsInfo struct {
	// SSRRByNamespace maps namespace → policy rules from SelfSubjectRulesReview.
	SSRRByNamespace map[string][]PolicyRule `json:"ssrr_by_namespace"`
	SSARChecks      []SSARCheck             `json:"ssar_checks"`
}

// PolicyRule mirrors rbac.PolicyRule but is serialization-friendly.
type PolicyRule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"api_groups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	ResourceNames   []string `json:"resource_names,omitempty"`
	NonResourceURLs []string `json:"non_resource_urls,omitempty"`
}

// SSARCheck records the result of a single SelfSubjectAccessReview.
type SSARCheck struct {
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason,omitempty"`
}

// ClusterObjects holds metadata for all enumerated Kubernetes objects.
type ClusterObjects struct {
	Namespaces            []NSInfo      `json:"namespaces,omitempty"`
	ServiceAccounts       []SAInfo      `json:"service_accounts,omitempty"`
	ClusterRoles          []RoleInfo    `json:"cluster_roles,omitempty"`
	ClusterRoleBindings   []BindingInfo `json:"cluster_role_bindings,omitempty"`
	Roles                 []RoleInfo    `json:"roles,omitempty"`
	RoleBindings          []BindingInfo `json:"role_bindings,omitempty"`
	Workloads             []WorkloadInfo `json:"workloads,omitempty"`
	Pods                  []PodInfo     `json:"pods,omitempty"`
	SecretsMeta           []SecretMeta  `json:"secrets_meta,omitempty"`
	ConfigMapsMeta        []CMeta       `json:"configmaps_meta,omitempty"`
	Nodes                 []NodeInfo    `json:"nodes,omitempty"`
	Webhooks              []WebhookInfo `json:"webhooks,omitempty"`
	CRDs                  []CRDInfo     `json:"crds,omitempty"`
}

// CRDInfo describes a CustomResourceDefinition present in the cluster.
type CRDInfo struct {
	Group    string `json:"group"`
	Kind     string `json:"kind"`
	Resource string `json:"resource"` // plural resource name (for SSRR matching)
	Scope    string `json:"scope"`    // Namespaced or Cluster
}

// WebhookInfo — admission webhook metadata.
type WebhookInfo struct {
	Name                 string   `json:"name"`
	Kind                 string   `json:"kind"`                            // Mutating or Validating
	Rules                []string `json:"rules,omitempty"`                 // resources the webhook intercepts
	FailurePolicy        string   `json:"failure_policy,omitempty"`        // Fail or Ignore
	ServiceName          string   `json:"service_name,omitempty"`
	ServiceNS            string   `json:"service_namespace,omitempty"`
	URL                  string   `json:"url,omitempty"`
	HasNamespaceSelector bool     `json:"has_namespace_selector,omitempty"` // true if NamespaceSelector is set
	Operations           []string `json:"operations,omitempty"`             // CREATE, UPDATE, DELETE, CONNECT
}

// NSInfo — namespace metadata.
type NSInfo struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Labels map[string]string `json:"labels,omitempty"`
}

// SAInfo — ServiceAccount metadata.
type SAInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	// ImagePullSecrets names only (no data).
	ImagePullSecrets []string `json:"image_pull_secrets,omitempty"`
	// Cloud workload identity annotations (populated when present).
	IRSARole          string `json:"irsa_role,omitempty"`          // eks.amazonaws.com/role-arn
	AzureIdentity     string `json:"azure_identity,omitempty"`     // azure.workload.identity/client-id
	GCPServiceAccount string `json:"gcp_service_account,omitempty"` // iam.gke.io/gcp-service-account
}

// RoleInfo — Role or ClusterRole metadata + rules.
type RoleInfo struct {
	Name      string      `json:"name"`
	Namespace string      `json:"namespace,omitempty"` // empty for ClusterRole
	Labels    map[string]string `json:"labels,omitempty"`
	Rules     []PolicyRule `json:"rules"`
}

// BindingInfo — RoleBinding or ClusterRoleBinding metadata.
type BindingInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Subjects  []Subject         `json:"subjects"`
	RoleRef   RoleRef           `json:"role_ref"`
}

// Subject represents a binding subject (User, Group, ServiceAccount).
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	APIGroup  string `json:"api_group,omitempty"`
}

// RoleRef identifies the role referenced by a binding.
type RoleRef struct {
	APIGroup string `json:"api_group"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

// WorkloadInfo holds sanitized workload spec metadata (no data values).
type WorkloadInfo struct {
	Kind       string   `json:"kind"` // Deployment, DaemonSet, StatefulSet, Job, CronJob
	Name       string   `json:"name"`
	Namespace  string   `json:"namespace"`
	Labels     map[string]string `json:"labels,omitempty"`
	Replicas   *int32   `json:"replicas,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	// Volumes referencing secrets/configmaps (no data).
	Volumes               []VolumeRef       `json:"volumes,omitempty"`
	HostPID               bool              `json:"host_pid,omitempty"`
	HostIPC               bool              `json:"host_ipc,omitempty"`
	HostNetwork           bool              `json:"host_network,omitempty"`
	PrivilegedContainers  []string          `json:"privileged_containers,omitempty"`
	HostPathMounts        []string          `json:"host_path_mounts,omitempty"`
	AutomountSAToken      *bool             `json:"automount_sa_token,omitempty"`
	ImageNames            []string          `json:"image_names,omitempty"`
	// DangerousCapabilities lists container names that have one or more of
	// SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH in capabilities.Add.
	DangerousCapabilities []string          `json:"dangerous_capabilities,omitempty"`
	// EnvSecretRefs lists secrets injected as env vars (names only — no values).
	EnvSecretRefs         []EnvSecretRef    `json:"env_secret_refs,omitempty"`
	// PlaintextEnvVars lists environment variables whose names match sensitive patterns
	// and whose values are hardcoded (not from a SecretKeyRef). Values are captured
	// because they are already in the pod spec (no additional permission needed).
	PlaintextEnvVars      []PlaintextEnvVar `json:"plaintext_env_vars,omitempty"`
}

// PlaintextEnvVar records an environment variable whose name matches a sensitive pattern
// and whose value is hardcoded in the pod spec (not a SecretKeyRef / envFrom reference).
type PlaintextEnvVar struct {
	Container string `json:"container"`
	EnvName   string `json:"env_name"`
	Pattern   string `json:"pattern"` // which keyword matched (e.g. "password", "api_key")
	Value     string `json:"value"`   // actual value (present in pod spec — no extra permission needed)
}

// EnvSecretRef records a secret referenced as an environment variable in a container spec.
// Only names and keys are stored — never values.
type EnvSecretRef struct {
	Container  string `json:"container"`
	SecretName string `json:"secret_name"`
	// SecretKey is the key within the secret. Empty when the secret is mounted via envFrom
	// (all keys become env vars).
	SecretKey string `json:"secret_key,omitempty"`
	// EnvVar is the name of the environment variable. Empty for envFrom references.
	EnvVar string `json:"env_var,omitempty"`
}

// VolumeRef describes a volume source (Secret or ConfigMap reference).
type VolumeRef struct {
	Name       string `json:"name"`
	SourceKind string `json:"source_kind"` // Secret, ConfigMap, HostPath, Projected, etc.
	SourceName string `json:"source_name,omitempty"`
	HostPath   string `json:"host_path,omitempty"`
	// Audience is set for Projected serviceAccountToken volumes with a non-default audience.
	Audience string `json:"audience,omitempty"`
}

// PodInfo holds sanitized pod metadata.
type PodInfo struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Node              string            `json:"node,omitempty"`
	ServiceAccount    string            `json:"service_account,omitempty"`
	Phase             string            `json:"phase,omitempty"`
	HostPID           bool              `json:"host_pid,omitempty"`
	HostNetwork       bool              `json:"host_network,omitempty"`
	HostIPC           bool              `json:"host_ipc,omitempty"`
	PrivilegedContainers []string       `json:"privileged_containers,omitempty"`
	HostPathMounts    []string          `json:"host_path_mounts,omitempty"`
	Volumes           []VolumeRef       `json:"volumes,omitempty"`
	AutomountSAToken  *bool             `json:"automount_sa_token,omitempty"`
	ImageNames        []string          `json:"image_names,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	PlaintextEnvVars  []PlaintextEnvVar `json:"plaintext_env_vars,omitempty"`
	// DangerousCapabilities lists container names that have one or more of
	// SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH in capabilities.Add.
	DangerousCapabilities []string      `json:"dangerous_capabilities,omitempty"`
}

// SecretMeta — Secret metadata. When GET permission is confirmed, Values is populated.
type SecretMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type"`
	Labels    map[string]string `json:"labels,omitempty"`
	// DataKeys lists the key names present in the secret (not their values).
	DataKeys []string `json:"data_keys,omitempty"`
	// Values contains decoded secret data when GET access was confirmed during authorized assessment.
	Values map[string]string `json:"values,omitempty"`
}

// CMeta — ConfigMap metadata. When GET permission is confirmed, Data is populated.
type CMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	DataKeys  []string          `json:"data_keys,omitempty"`
	// Data contains configmap key-value pairs when GET permission was confirmed during authorized assessment.
	Data map[string]string `json:"data,omitempty"`
}

// NodeInfo — Node metadata only.
type NodeInfo struct {
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels,omitempty"`
	Taints   []string          `json:"taints,omitempty"`
	Capacity map[string]string `json:"capacity,omitempty"` // cpu, memory strings
	Roles    []string          `json:"roles,omitempty"`
}

// EnumerateOptions configures a full enumeration run.
type EnumerateOptions struct {
	Namespaces []string
	SkipSSAR   bool
	Stealth    bool // skip SSRR/SSAR to reduce audit log footprint
	Log        *zap.Logger
}

// IdentityPermissions represents computed effective RBAC permissions for a subject.
// Used in reviewer mode where SSRR/SSAR is not available (only works for the current identity).
type IdentityPermissions struct {
	Subject     string       `json:"subject"`               // e.g. "system:serviceaccount:kube-system:coredns"
	SubjectKind string       `json:"subject_kind"`          // "ServiceAccount", "User", "Group"
	Namespace   string       `json:"namespace,omitempty"`   // for ServiceAccount subjects
	Name        string       `json:"name"`
	BoundRoles  []string     `json:"bound_roles,omitempty"` // names of roles/bindings granting permissions
	Rules       []PolicyRule `json:"rules"`
}

// PodSecurityIssue describes a pod-level security misconfiguration found during reviewer analysis.
type PodSecurityIssue struct {
	Namespace    string   `json:"namespace"`
	WorkloadKind string   `json:"workload_kind"` // Deployment, DaemonSet, StatefulSet, Job, CronJob, Pod
	WorkloadName string   `json:"workload_name"`
	Issues       []string `json:"issues"`
	Severity     string   `json:"severity"` // HIGH, MEDIUM
}

// ReviewerEnumerateResult bundles the standard enumeration result with reviewer-mode extras.
type ReviewerEnumerateResult struct {
	EnumerationResult *EnumerationResult    `json:"enumeration"`
	AllIdentityPerms  []IdentityPermissions `json:"all_identity_perms"`
	PodSecurityIssues []PodSecurityIssue    `json:"pod_security_issues"`
}
