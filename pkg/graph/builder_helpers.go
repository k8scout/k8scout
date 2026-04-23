package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

func verbToEdgeKind(verb string) EdgeKind {
	switch verb {
	case "list", "watch":
		return EdgeCanList
	case "get":
		return EdgeCanGet
	case "create":
		return EdgeCanCreate
	case "patch", "update":
		return EdgeCanPatch
	case "delete", "deletecollection":
		return EdgeCanDelete
	case "impersonate":
		return EdgeCanImpersonate
	case "escalate":
		return EdgeCanEscalate
	case "bind":
		return EdgeCanBind
	case "*":
		return EdgeCanCreate // broad; will be enriched by inference
	}
	return ""
}

func resourceNodeID(resource, namespace string) string {
	if namespace == "" {
		return "resource:" + resource
	}
	return "resource:" + namespace + ":" + resource
}

func resourceToNodeKind(resource string) NodeKind {
	// Normalize subresource prefix.
	base := strings.Split(resource, "/")[0]
	switch base {
	case "secrets":
		return KindSecret
	case "configmaps":
		return KindConfigMap
	case "pods":
		return KindPod
	case "nodes":
		return KindNode
	case "serviceaccounts":
		return KindServiceAccount
	case "namespaces":
		return KindNamespace
	case "roles":
		return KindRole
	case "clusterroles":
		return KindClusterRole
	case "rolebindings":
		return KindRoleBinding
	case "clusterrolebindings":
		return KindClusterRoleBinding
	case "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs":
		return KindWorkload
	case "mutatingwebhookconfigurations", "validatingwebhookconfigurations":
		return KindWebhook
	}
	return KindWorkload // default
}

func saNodeID(ns, name string) string {
	return fmt.Sprintf("sa:%s:%s", ns, name)
}

func subjectNodeID(s kube.Subject) string {
	switch s.Kind {
	case "ServiceAccount":
		return saNodeID(s.Namespace, s.Name)
	case "User":
		return "identity:" + s.Name
	case "Group":
		return "group:" + s.Name
	}
	return ""
}

// resolveRoleRefID returns the graph node ID for a role reference.
// ns is the namespace of the binding — used only when the RoleRef targets a
// namespace-scoped Role (ClusterRoleBindings always reference ClusterRoles).
func resolveRoleRefID(ref kube.RoleRef, ns string) string {
	if ref.Kind == "ClusterRole" {
		return "clusterrole:" + ref.Name
	}
	return "role:" + ns + ":" + ref.Name
}

// reviewerIdentityNodeID returns the graph node ID for a computed identity.
func reviewerIdentityNodeID(ip kube.IdentityPermissions) string {
	if ip.SubjectKind == "ServiceAccount" {
		return saNodeID(ip.Namespace, ip.Name)
	}
	return "identity:" + ip.Name
}

// hasEdge returns true if edges already contains an edge from→to with the given kind.
func hasEdge(edges []Edge, from, to string, kind EdgeKind) bool {
	for i := range edges {
		if edges[i].From == from && edges[i].To == to && edges[i].Kind == kind {
			return true
		}
	}
	return false
}

// workloadBaseRisk returns a base risk score for a workload/pod node.
// All workloads are potential attacker footholds; dangerous security configs raise the score.
func workloadBaseRisk(privileged, hostPID, hostNetwork, hostIPC, dangerousCaps, hostPath bool) float64 {
	if privileged {
		return 9.0
	}
	if hostPID || hostNetwork || hostIPC {
		return 7.5
	}
	if dangerousCaps || hostPath {
		return 7.0
	}
	return 3.0 // base score: workloads are always potential footholds
}

// canEscapeToHost returns true if a pod's security configuration allows
// container escape to the underlying host node.
func canEscapeToHost(privilegedContainers []string, hostPID, hostNetwork, hostIPC bool,
	dangerousCaps []string, hostPathMounts []string) bool {
	return len(privilegedContainers) > 0 ||
		hostPID || hostNetwork || hostIPC ||
		len(dangerousCaps) > 0 ||
		len(hostPathMounts) > 0
}

// isCredentialPath returns true if a hostPath mount is a well-known credential location.
func isCredentialPath(path string) bool {
	credPaths := []string{
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/pki",
		"/root/.kube",
		"/home",
		"/var/lib/kubelet/kubeconfig",
	}
	for _, cp := range credPaths {
		if strings.HasPrefix(path, cp) {
			return true
		}
	}
	return false
}
