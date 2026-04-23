package graph

import (
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
)

// Rule-level tests for RBAC / escalation / takeover rules in inference_rules_rbac.go.
//
// Each rule has a positive case (fires on the minimal input that should trigger it)
// and a negative case (does not fire on empty / inverted input). Tests also pin
// the rule's identity metadata (ID / severity / score) so accidental drift is caught.

// ── PRIV-LIST-SECRETS ────────────────────────────────────────────────────────

func TestRuleListSecrets(t *testing.T) {
	t.Run("fires on SSAR allowed", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("list", "secrets", "default")}
		_, evidence, nodes := assertRuleFires(t, ruleListSecrets(), r, "PRIV-LIST-SECRETS", SeverityHigh, 7.5)
		assertAnyEvidenceContains(t, evidence, `"default"`)
		if len(nodes) != 1 || nodes[0] != "resource:default:secrets" {
			t.Errorf("affected nodes: got %v", nodes)
		}
	})
	t.Run("falls back to SSRR when no SSAR", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSRRByNamespace["team-a"] = []kube.PolicyRule{
			{Verbs: []string{"list"}, Resources: []string{"secrets"}},
		}
		_, evidence, _ := assertRuleFires(t, ruleListSecrets(), r, "PRIV-LIST-SECRETS", SeverityHigh, 7.5)
		assertAnyEvidenceContains(t, evidence, "team-a")
	})
	t.Run("silent on denied", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{denySSAR("list", "secrets", "default")}
		assertRuleSilent(t, ruleListSecrets(), r)
	})
}

// ── PRIV-GET-SECRETS ─────────────────────────────────────────────────────────

func TestRuleGetSecrets(t *testing.T) {
	t.Run("fires on SSAR get secrets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "secrets", "ns1")}
		assertRuleFires(t, ruleGetSecrets(), r, "PRIV-GET-SECRETS", SeverityCritical, 9.0)
	})
	t.Run("silent when not allowed", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{denySSAR("get", "secrets", "ns1")}
		assertRuleSilent(t, ruleGetSecrets(), r)
	})
}

// ── PRIVESC-CREATE-ROLEBINDING ───────────────────────────────────────────────

func TestRuleCreateRoleBindings(t *testing.T) {
	t.Run("fires on create rolebindings", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("create", "rolebindings", "ns1")}
		assertRuleFires(t, ruleCreateRoleBindings(), r, "PRIVESC-CREATE-ROLEBINDING", SeverityCritical, 9.5)
	})
	t.Run("silent otherwise", func(t *testing.T) {
		r := newEnumeration()
		assertRuleSilent(t, ruleCreateRoleBindings(), r)
	})
}

// ── PRIVESC-CREATE-CLUSTERROLEBINDING ────────────────────────────────────────

func TestRuleCreateClusterRoleBindings(t *testing.T) {
	t.Run("fires on create clusterrolebindings", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("create", "clusterrolebindings", "")}
		assertRuleFires(t, ruleCreateClusterRoleBindings(), r, "PRIVESC-CREATE-CLUSTERROLEBINDING", SeverityCritical, 10.0)
	})
	t.Run("silent otherwise", func(t *testing.T) {
		assertRuleSilent(t, ruleCreateClusterRoleBindings(), newEnumeration())
	})
}

// ── TAKEOVER-PATCH-DEPLOYMENT ────────────────────────────────────────────────

func TestRulePatchDeployments(t *testing.T) {
	t.Run("fires and reports affected workloads in namespace", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "deployments", "prod")}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{
			{Kind: "Deployment", Name: "api", Namespace: "prod"},
			{Kind: "Deployment", Name: "worker", Namespace: "stage"}, // different ns — not affected
			{Kind: "DaemonSet", Name: "ds", Namespace: "prod"},       // different kind — not affected
		}
		_, _, nodes := assertRuleFires(t, rulePatchDeployments(), r, "TAKEOVER-PATCH-DEPLOYMENT", SeverityHigh, 8.0)
		if len(nodes) != 1 || nodes[0] != "workload:prod:api" {
			t.Errorf("affected nodes: got %v, want [workload:prod:api]", nodes)
		}
	})
	t.Run("silent without permission", func(t *testing.T) {
		assertRuleSilent(t, rulePatchDeployments(), newEnumeration())
	})
}

// ── TAKEOVER-PATCH-DAEMONSET ─────────────────────────────────────────────────

func TestRulePatchDaemonSets(t *testing.T) {
	t.Run("fires on patch daemonsets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "daemonsets", "kube-system")}
		assertRuleFires(t, rulePatchDaemonSets(), r, "TAKEOVER-PATCH-DAEMONSET", SeverityHigh, 8.5)
	})
	t.Run("silent otherwise", func(t *testing.T) {
		assertRuleSilent(t, rulePatchDaemonSets(), newEnumeration())
	})
}

// ── ESCAPE-CREATE-POD ────────────────────────────────────────────────────────

func TestRuleCreatePods(t *testing.T) {
	t.Run("fires on create pods", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("create", "pods", "default")}
		assertRuleFires(t, ruleCreatePods(), r, "ESCAPE-CREATE-POD", SeverityHigh, 8.0)
	})
	t.Run("silent otherwise", func(t *testing.T) {
		assertRuleSilent(t, ruleCreatePods(), newEnumeration())
	})
}

// ── RUNTIME-EXEC-PODS ────────────────────────────────────────────────────────

func TestRuleExecPods(t *testing.T) {
	t.Run("fires on pods/exec create", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "exec", "prod")}
		assertRuleFires(t, ruleExecPods(), r, "RUNTIME-EXEC-PODS", SeverityHigh, 7.8)
	})
	t.Run("silent on non-exec subresource", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "log", "prod")}
		assertRuleSilent(t, ruleExecPods(), r)
	})
}

// ── PRIVESC-IMPERSONATE ──────────────────────────────────────────────────────

func TestRuleImpersonate(t *testing.T) {
	t.Run("fires on impersonate verb", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{{Verb: "impersonate", Resource: "users", Allowed: true}}
		assertRuleFires(t, ruleImpersonate(), r, "PRIVESC-IMPERSONATE", SeverityCritical, 9.8)
	})
	t.Run("silent without impersonate", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "pods", "default")}
		assertRuleSilent(t, ruleImpersonate(), r)
	})
}

// ── RUNTIME-PORTFORWARD ──────────────────────────────────────────────────────

func TestRuleCreatePodPortforward(t *testing.T) {
	t.Run("fires on pods/portforward", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "portforward", "prod")}
		assertRuleFires(t, ruleCreatePodPortforward(), r, "RUNTIME-PORTFORWARD", SeverityMedium, 5.5)
	})
	t.Run("silent otherwise", func(t *testing.T) {
		assertRuleSilent(t, ruleCreatePodPortforward(), newEnumeration())
	})
}

// ── CONFIG-WILDCARD-VERBS ────────────────────────────────────────────────────

func TestRuleWildcardVerbs(t *testing.T) {
	t.Run("fires on wildcard verb in Role", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Roles = []kube.RoleInfo{{
			Namespace: "ns1", Name: "all-verbs",
			Rules: []kube.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"pods"}}},
		}}
		_, _, nodes := assertRuleFires(t, ruleWildcardVerbs(), r, "CONFIG-WILDCARD-VERBS", SeverityHigh, 8.0)
		if len(nodes) != 1 || nodes[0] != "role:ns1:all-verbs" {
			t.Errorf("affected nodes: got %v", nodes)
		}
	})
	t.Run("fires on wildcard resource in ClusterRole", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ClusterRoles = []kube.RoleInfo{{
			Name:  "all-res",
			Rules: []kube.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"*"}}},
		}}
		_, _, nodes := assertRuleFires(t, ruleWildcardVerbs(), r, "CONFIG-WILDCARD-VERBS", SeverityHigh, 8.0)
		// ClusterRole has empty namespace so the concatenation yields three colons.
		if len(nodes) != 1 || nodes[0] != "clusterrole:::all-res" {
			t.Errorf("affected nodes: got %v", nodes)
		}
	})
	t.Run("silent without wildcards", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Roles = []kube.RoleInfo{{
			Namespace: "ns1", Name: "narrow",
			Rules: []kube.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}},
		}}
		assertRuleSilent(t, ruleWildcardVerbs(), r)
	})
}

// ── PRIVESC-CLUSTER-ADMIN-BINDING ────────────────────────────────────────────

func TestRuleClusterAdminBinding(t *testing.T) {
	t.Run("fires on SA bound to cluster-admin", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ClusterRoleBindings = []kube.BindingInfo{{
			Name:    "crb1",
			RoleRef: kube.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []kube.Subject{
				{Kind: "ServiceAccount", Namespace: "ns1", Name: "deployer"},
			},
		}}
		_, _, nodes := assertRuleFires(t, ruleClusterAdminBinding(), r, "PRIVESC-CLUSTER-ADMIN-BINDING", SeverityCritical, 10.0)
		if len(nodes) != 1 {
			t.Errorf("affected nodes: got %v", nodes)
		}
	})
	t.Run("ignores system:* users", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ClusterRoleBindings = []kube.BindingInfo{{
			Name:    "system-crb",
			RoleRef: kube.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []kube.Subject{
				{Kind: "User", Name: "system:kube-controller-manager"},
			},
		}}
		assertRuleSilent(t, ruleClusterAdminBinding(), r)
	})
	t.Run("silent when no cluster-admin binding", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ClusterRoleBindings = []kube.BindingInfo{{
			Name:     "crb-view",
			RoleRef:  kube.RoleRef{Kind: "ClusterRole", Name: "view"},
			Subjects: []kube.Subject{{Kind: "ServiceAccount", Namespace: "ns1", Name: "sa1"}},
		}}
		assertRuleSilent(t, ruleClusterAdminBinding(), r)
	})
}

// ── PRIVESC-PATCH-CLUSTERROLES ───────────────────────────────────────────────

func TestRulePatchClusterRoles(t *testing.T) {
	t.Run("fires on patch clusterroles", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "clusterroles", "")}
		assertRuleFires(t, rulePatchClusterRoles(), r, "PRIVESC-PATCH-CLUSTERROLES", SeverityCritical, 9.5)
	})
	t.Run("silent otherwise", func(t *testing.T) {
		assertRuleSilent(t, rulePatchClusterRoles(), newEnumeration())
	})
}

// ── PRIVESC-CREATE-SA-TOKEN ──────────────────────────────────────────────────

func TestRuleCreateSAToken(t *testing.T) {
	t.Run("fires on serviceaccounts/token create", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "serviceaccounts", "token", "ns1")}
		assertRuleFires(t, ruleCreateSAToken(), r, "PRIVESC-CREATE-SA-TOKEN", SeverityCritical, 9.0)
	})
	t.Run("silent without subresource", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("create", "serviceaccounts", "ns1")}
		assertRuleSilent(t, ruleCreateSAToken(), r)
	})
}

// ── PRIVESC-ESCALATE-BIND ────────────────────────────────────────────────────

func TestRuleEscalateBind(t *testing.T) {
	t.Run("fires on escalate via SSAR", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{{Verb: "escalate", Resource: "clusterroles", Allowed: true}}
		_, _, nodes := assertRuleFires(t, ruleEscalateBind(), r, "PRIVESC-ESCALATE-BIND", SeverityCritical, 9.5)
		if len(nodes) != 1 || nodes[0] != "clusterrole:cluster-admin" {
			t.Errorf("affected nodes: got %v, want [clusterrole:cluster-admin]", nodes)
		}
	})
	t.Run("fires on bind clusterrolebindings via SSAR", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{{Verb: "bind", Resource: "clusterrolebindings", Allowed: true}}
		assertRuleFires(t, ruleEscalateBind(), r, "PRIVESC-ESCALATE-BIND", SeverityCritical, 9.5)
	})
	t.Run("fires on escalate via SSRR fallback", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSRRByNamespace["ns1"] = []kube.PolicyRule{
			{Verbs: []string{"escalate"}, Resources: []string{"clusterroles"}},
		}
		assertRuleFires(t, ruleEscalateBind(), r, "PRIVESC-ESCALATE-BIND", SeverityCritical, 9.5)
	})
	t.Run("silent otherwise", func(t *testing.T) {
		assertRuleSilent(t, ruleEscalateBind(), newEnumeration())
	})
}
