package graph

import (
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
)

// Rule-level tests for cloud / operator / webhook rules in inference_rules_advanced.go.

// ── CLOUD-IRSA-ESCALATION ────────────────────────────────────────────────────

func TestRuleCloudIRSAEscalation(t *testing.T) {
	t.Run("fires on SA with IRSA annotation", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ServiceAccounts = []kube.SAInfo{{
			Name: "app-sa", Namespace: "ns1", IRSARole: "arn:aws:iam::111:role/app",
		}}
		_, evidence, _ := assertRuleFires(t, ruleCloudIRSAEscalation(), r, "CLOUD-IRSA-ESCALATION", SeverityCritical, 9.5)
		assertAnyEvidenceContains(t, evidence, "AWS")
		assertAnyEvidenceContains(t, evidence, "dormant") // no workload bound
	})
	t.Run("reports bound SA without dormant tag", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ServiceAccounts = []kube.SAInfo{{
			Name: "app-sa", Namespace: "ns1", GCPServiceAccount: "sa@proj.iam.gserviceaccount.com",
		}}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app", ServiceAccount: "app-sa",
		}}
		_, evidence, _ := assertRuleFires(t, ruleCloudIRSAEscalation(), r, "CLOUD-IRSA-ESCALATION", SeverityCritical, 9.5)
		for _, e := range evidence {
			if contains(e, "dormant") {
				t.Errorf("bound SA should not be tagged dormant: %s", e)
			}
		}
	})
	t.Run("silent without cloud annotations", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ServiceAccounts = []kube.SAInfo{{Name: "sa", Namespace: "ns1"}}
		assertRuleSilent(t, ruleCloudIRSAEscalation(), r)
	})
}

// ── EXFIL-HELM-RELEASE ───────────────────────────────────────────────────────

func TestRuleHelmReleaseSecrets(t *testing.T) {
	t.Run("fires on helm release secret", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.SecretsMeta = []kube.SecretMeta{{
			Namespace: "ns1", Name: "sh.helm.release.v1.chart.v1",
			Type: "helm.sh/release.v1",
		}}
		assertRuleFires(t, ruleHelmReleaseSecrets(), r, "EXFIL-HELM-RELEASE", SeverityHigh, 8.0)
	})
	t.Run("silent on opaque secret", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.SecretsMeta = []kube.SecretMeta{{Namespace: "ns1", Name: "db", Type: "Opaque"}}
		assertRuleSilent(t, ruleHelmReleaseSecrets(), r)
	})
}

// ── PRIVESC-MUTATING-WEBHOOK ─────────────────────────────────────────────────

func TestRuleMutatingWebhookPrivesc(t *testing.T) {
	t.Run("fires on SSAR patch", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "mutatingwebhookconfigurations", "")}
		assertRuleFires(t, ruleMutatingWebhookPrivesc(), r, "PRIVESC-MUTATING-WEBHOOK", SeverityCritical, 9.5)
	})
	t.Run("fires on SSRR fallback", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSRRByNamespace["ns1"] = []kube.PolicyRule{
			{Verbs: []string{"create"}, Resources: []string{"mutatingwebhookconfigurations"}},
		}
		assertRuleFires(t, ruleMutatingWebhookPrivesc(), r, "PRIVESC-MUTATING-WEBHOOK", SeverityCritical, 9.5)
	})
	t.Run("silent on unrelated SSAR", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "pods", "ns1")}
		assertRuleSilent(t, ruleMutatingWebhookPrivesc(), r)
	})
}

// ── CLOUD-PROJECTED-TOKEN-AUDIENCE ───────────────────────────────────────────

func TestRuleProjectedTokenAudience(t *testing.T) {
	t.Run("fires on projected token with audience", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			Volumes: []kube.VolumeRef{{
				Name: "aws-iam", SourceKind: "Projected", Audience: "sts.amazonaws.com",
			}},
		}}
		assertRuleFires(t, ruleProjectedTokenAudience(), r, "CLOUD-PROJECTED-TOKEN-AUDIENCE", SeverityHigh, 8.0)
	})
	t.Run("silent on default audience (empty)", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			Volumes: []kube.VolumeRef{{Name: "token", SourceKind: "Projected"}},
		}}
		assertRuleSilent(t, ruleProjectedTokenAudience(), r)
	})
}

// ── ESCAPE-NODE-COMPROMISE ───────────────────────────────────────────────────

func TestRuleNodeCompromise(t *testing.T) {
	t.Run("fires on exec + critical hostPath", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "exec", "ns1")}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "kubelet-agent",
			HostPathMounts: []string{"/var/lib/kubelet"},
		}}
		assertRuleFires(t, ruleNodeCompromise(), r, "ESCAPE-NODE-COMPROMISE", SeverityCritical, 9.8)
	})
	t.Run("silent without exec", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "kubelet-agent",
			HostPathMounts: []string{"/var/lib/kubelet"},
		}}
		assertRuleSilent(t, ruleNodeCompromise(), r)
	})
	t.Run("silent with exec but no critical mount", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "exec", "ns1")}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			HostPathMounts: []string{"/opt/app"},
		}}
		assertRuleSilent(t, ruleNodeCompromise(), r)
	})
}

// ── PRIVESC-NODE-PROXY ───────────────────────────────────────────────────────

func TestRuleNodeProxy(t *testing.T) {
	t.Run("fires on SSAR nodes/proxy", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "nodes", "proxy", "")}
		assertRuleFires(t, ruleNodeProxy(), r, "PRIVESC-NODE-PROXY", SeverityCritical, 9.5)
	})
	t.Run("silent on nodes without proxy subresource", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "nodes", "")}
		assertRuleSilent(t, ruleNodeProxy(), r)
	})
}

// ── PRIVESC-PATCH-SECRETS ────────────────────────────────────────────────────

func TestRulePatchSecrets(t *testing.T) {
	t.Run("fires on patch secrets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "secrets", "ns1")}
		assertRuleFires(t, rulePatchSecrets(), r, "PRIVESC-PATCH-SECRETS", SeverityCritical, 9.0)
	})
	t.Run("fires on update secrets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("update", "secrets", "ns1")}
		assertRuleFires(t, rulePatchSecrets(), r, "PRIVESC-PATCH-SECRETS", SeverityCritical, 9.0)
	})
	t.Run("silent on get secrets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "secrets", "ns1")}
		assertRuleSilent(t, rulePatchSecrets(), r)
	})
}

// ── LATERAL-EXEC-SECRET-MOUNT ────────────────────────────────────────────────

func TestRuleLateralExecSecretMount(t *testing.T) {
	t.Run("fires on exec + secret volume", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "exec", "ns1")}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "api",
			Volumes: []kube.VolumeRef{{Name: "creds", SourceKind: "Secret", SourceName: "db-creds"}},
		}}
		assertRuleFires(t, ruleLateralExecSecretMount(), r, "LATERAL-EXEC-SECRET-MOUNT", SeverityHigh, 8.5)
	})
	t.Run("silent without exec", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "api",
			Volumes: []kube.VolumeRef{{Name: "creds", SourceKind: "Secret"}},
		}}
		assertRuleSilent(t, ruleLateralExecSecretMount(), r)
	})
	t.Run("silent with exec but no secret volume", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSARSub("create", "pods", "exec", "ns1")}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "api",
			Volumes: []kube.VolumeRef{{Name: "data", SourceKind: "ConfigMap"}},
		}}
		assertRuleSilent(t, ruleLateralExecSecretMount(), r)
	})
}

// ── PRIVESC-CREATE-DAEMONSETS ────────────────────────────────────────────────

func TestRuleCreateDaemonsets(t *testing.T) {
	t.Run("fires on create daemonsets SSAR", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("create", "daemonsets", "ns1")}
		assertRuleFires(t, ruleCreateDaemonsets(), r, "PRIVESC-CREATE-DAEMONSETS", SeverityCritical, 9.0)
	})
	t.Run("silent on list daemonsets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("list", "daemonsets", "ns1")}
		assertRuleSilent(t, ruleCreateDaemonsets(), r)
	})
}

// ── LATERAL-PATCH-SA ─────────────────────────────────────────────────────────

func TestRulePatchServiceAccounts(t *testing.T) {
	t.Run("fires on patch serviceaccounts", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "serviceaccounts", "ns1")}
		assertRuleFires(t, rulePatchServiceAccounts(), r, "LATERAL-PATCH-SA", SeverityHigh, 8.5)
	})
	t.Run("silent on get serviceaccounts", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "serviceaccounts", "ns1")}
		assertRuleSilent(t, rulePatchServiceAccounts(), r)
	})
}

// ── PRIV-WATCH-SECRETS ───────────────────────────────────────────────────────

func TestRuleWatchSecrets(t *testing.T) {
	t.Run("fires on watch secrets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("watch", "secrets", "ns1")}
		assertRuleFires(t, ruleWatchSecrets(), r, "PRIV-WATCH-SECRETS", SeverityHigh, 7.5)
	})
	t.Run("silent on list secrets only", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("list", "secrets", "ns1")}
		assertRuleSilent(t, ruleWatchSecrets(), r)
	})
}

// ── PRIVESC-PATCH-NODES ──────────────────────────────────────────────────────

func TestRulePatchNodes(t *testing.T) {
	t.Run("fires on patch nodes", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "nodes", "")}
		assertRuleFires(t, rulePatchNodes(), r, "PRIVESC-PATCH-NODES", SeverityMedium, 6.5)
	})
	t.Run("silent on get nodes", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("get", "nodes", "")}
		assertRuleSilent(t, rulePatchNodes(), r)
	})
}

// ── PRIVESC-PATCH-STATEFULSETS ───────────────────────────────────────────────

func TestRulePatchStatefulSets(t *testing.T) {
	t.Run("fires on patch statefulsets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "statefulsets", "ns1")}
		assertRuleFires(t, rulePatchStatefulSets(), r, "PRIVESC-PATCH-STATEFULSETS", SeverityHigh, 8.0)
	})
	t.Run("silent on list statefulsets", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("list", "statefulsets", "ns1")}
		assertRuleSilent(t, rulePatchStatefulSets(), r)
	})
}

// ── LATERAL-ARGOCD-OPERATOR ──────────────────────────────────────────────────

func TestRuleArgoCDOperatorAbuse(t *testing.T) {
	t.Run("fires on ArgoCD CRD + patch applications", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.CRDs = []kube.CRDInfo{{Group: "argoproj.io", Kind: "Application", Resource: "applications", Scope: "Namespaced"}}
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "applications", "argocd")}
		assertRuleFires(t, ruleArgoCDOperatorAbuse(), r, "LATERAL-ARGOCD-OPERATOR", SeverityCritical, 9.5)
	})
	t.Run("silent without ArgoCD CRDs", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "applications", "argocd")}
		assertRuleSilent(t, ruleArgoCDOperatorAbuse(), r)
	})
	t.Run("silent with CRD but no permission", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.CRDs = []kube.CRDInfo{{Group: "argoproj.io", Resource: "applications"}}
		assertRuleSilent(t, ruleArgoCDOperatorAbuse(), r)
	})
}

// ── LATERAL-FLUX-OPERATOR ────────────────────────────────────────────────────

func TestRuleFluxOperatorAbuse(t *testing.T) {
	t.Run("fires on Flux CRD + patch kustomizations", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.CRDs = []kube.CRDInfo{{Group: "kustomize.toolkit.fluxcd.io", Kind: "Kustomization", Resource: "kustomizations"}}
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "kustomizations", "flux-system")}
		assertRuleFires(t, ruleFluxOperatorAbuse(), r, "LATERAL-FLUX-OPERATOR", SeverityCritical, 9.5)
	})
	t.Run("silent without Flux CRDs", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "kustomizations", "flux-system")}
		assertRuleSilent(t, ruleFluxOperatorAbuse(), r)
	})
}

// ── LATERAL-EXTERNAL-SECRETS ─────────────────────────────────────────────────

func TestRuleExternalSecretsAbuse(t *testing.T) {
	t.Run("fires on ESO CRD + create externalsecrets", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.CRDs = []kube.CRDInfo{{Group: "external-secrets.io", Kind: "ExternalSecret", Resource: "externalsecrets"}}
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("create", "externalsecrets", "ns1")}
		assertRuleFires(t, ruleExternalSecretsAbuse(), r, "LATERAL-EXTERNAL-SECRETS", SeverityHigh, 8.5)
	})
	t.Run("silent without ESO CRDs", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("create", "externalsecrets", "ns1")}
		assertRuleSilent(t, ruleExternalSecretsAbuse(), r)
	})
}

// ── LATERAL-VAULT-OPERATOR ───────────────────────────────────────────────────

func TestRuleVaultOperatorAbuse(t *testing.T) {
	t.Run("fires on Vault operator CRD + patch vaultstaticsecrets", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.CRDs = []kube.CRDInfo{{Group: "secrets.hashicorp.com", Kind: "VaultStaticSecret", Resource: "vaultstaticsecrets"}}
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "vaultstaticsecrets", "ns1")}
		assertRuleFires(t, ruleVaultOperatorAbuse(), r, "LATERAL-VAULT-OPERATOR", SeverityHigh, 8.0)
	})
	t.Run("silent without Vault operator CRDs", func(t *testing.T) {
		r := newEnumeration()
		r.Permissions.SSARChecks = []kube.SSARCheck{allowSSAR("patch", "vaultstaticsecrets", "ns1")}
		assertRuleSilent(t, ruleVaultOperatorAbuse(), r)
	})
}

// ── BYPASS-WEBHOOK-IGNORE-POLICY ─────────────────────────────────────────────

func TestRuleWebhookIgnorePolicy(t *testing.T) {
	t.Run("fires on mutating webhook with FailurePolicy=Ignore", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{
			Name: "wh1", Kind: "Mutating", FailurePolicy: "Ignore",
		}}
		assertRuleFires(t, ruleWebhookIgnorePolicy(), r, "BYPASS-WEBHOOK-IGNORE-POLICY", SeverityHigh, 8.0)
	})
	t.Run("silent on validating webhook (ignored by this rule)", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{
			Name: "vw", Kind: "Validating", FailurePolicy: "Ignore",
		}}
		assertRuleSilent(t, ruleWebhookIgnorePolicy(), r)
	})
	t.Run("silent on FailurePolicy=Fail", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{
			Name: "wh2", Kind: "Mutating", FailurePolicy: "Fail",
		}}
		assertRuleSilent(t, ruleWebhookIgnorePolicy(), r)
	})
}

// ── BYPASS-WEBHOOK-NAMESPACE-GAP ─────────────────────────────────────────────

func TestRuleWebhookNamespaceGap(t *testing.T) {
	t.Run("fires when webhook has namespaceSelector", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{
			Name: "wh1", Kind: "Mutating", HasNamespaceSelector: true,
		}}
		assertRuleFires(t, ruleWebhookNamespaceGap(), r, "BYPASS-WEBHOOK-NAMESPACE-GAP", SeverityMedium, 6.0)
	})
	t.Run("silent without selector", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{Name: "wh1", Kind: "Mutating"}}
		assertRuleSilent(t, ruleWebhookNamespaceGap(), r)
	})
}

// ── PRIVESC-WEBHOOK-BACKEND-TAKEOVER ─────────────────────────────────────────

func TestRuleWebhookBackendTakeover(t *testing.T) {
	t.Run("fires when mutating pod-intercepting webhook has reachable workload backend", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{
			Name: "policy-wh", Kind: "Mutating", InterceptsPods: true,
			ServiceName: "policy-agent", ServiceNS: "security",
		}}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "security", Name: "policy-agent",
		}}
		_, _, nodes := assertRuleFires(t, ruleWebhookBackendTakeover(), r, "PRIVESC-WEBHOOK-BACKEND-TAKEOVER", SeverityHigh, 8.5)
		if len(nodes) == 0 {
			t.Error("expected affected nodes (workload + webhook)")
		}
	})
	t.Run("silent on non-pod-intercepting webhook", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{
			Name: "other", Kind: "Mutating", InterceptsPods: false,
			ServiceName: "other-svc", ServiceNS: "security",
		}}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "security", Name: "other-svc",
		}}
		assertRuleSilent(t, ruleWebhookBackendTakeover(), r)
	})
	t.Run("silent when backend workload is not in same namespace", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Webhooks = []kube.WebhookInfo{{
			Name: "wh", Kind: "Mutating", InterceptsPods: true,
			ServiceName: "svc", ServiceNS: "security",
		}}
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "default", Name: "svc",
		}}
		assertRuleSilent(t, ruleWebhookBackendTakeover(), r)
	})
}

// contains is a local helper to avoid pulling strings into this test's top import block
// when only used for one assertion.
func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
