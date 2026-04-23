package graph

import (
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
)

// Rule-level tests for pod/workload security-config rules in inference_rules_security.go.

// boolPtr returns a pointer to b — used for AutomountSAToken which is *bool in the spec.
func boolPtr(b bool) *bool { return &b }

// ── CONFIG-PRIVILEGED-CONTAINER ──────────────────────────────────────────────

func TestRulePrivilegedContainers(t *testing.T) {
	t.Run("fires on workload with privileged container", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			PrivilegedContainers: []string{"side"},
		}}
		_, _, nodes := assertRuleFires(t, rulePrivilegedContainers(), r, "CONFIG-PRIVILEGED-CONTAINER", SeverityHigh, 8.5)
		if len(nodes) != 1 || nodes[0] != "workload:ns1:app" {
			t.Errorf("nodes: %v", nodes)
		}
	})
	t.Run("fires on standalone pod", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Pods = []kube.PodInfo{{
			Namespace: "ns1", Name: "pod1",
			PrivilegedContainers: []string{"c1"},
		}}
		_, _, nodes := assertRuleFires(t, rulePrivilegedContainers(), r, "CONFIG-PRIVILEGED-CONTAINER", SeverityHigh, 8.5)
		if len(nodes) != 1 || nodes[0] != "pod:ns1:pod1" {
			t.Errorf("nodes: %v", nodes)
		}
	})
	t.Run("silent without privileged containers", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{Kind: "Deployment", Namespace: "ns1", Name: "app"}}
		assertRuleSilent(t, rulePrivilegedContainers(), r)
	})
}

// ── CONFIG-HOSTPATH-MOUNT ────────────────────────────────────────────────────

func TestRuleHostPathMounts(t *testing.T) {
	t.Run("fires on critical docker socket mount", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			HostPathMounts: []string{"/var/run/docker.sock"},
		}}
		_, evidence, nodes := assertRuleFires(t, ruleHostPathMounts(), r, "CONFIG-HOSTPATH-MOUNT", SeverityHigh, 7.5)
		assertAnyEvidenceContains(t, evidence, "Docker socket")
		if len(nodes) != 1 {
			t.Errorf("nodes: %v", nodes)
		}
	})
	t.Run("fires on high-risk path like /proc", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Pods = []kube.PodInfo{{
			Namespace: "ns1", Name: "pod1",
			HostPathMounts: []string{"/proc/1/root"},
		}}
		_, evidence, _ := assertRuleFires(t, ruleHostPathMounts(), r, "CONFIG-HOSTPATH-MOUNT", SeverityHigh, 7.5)
		assertAnyEvidenceContains(t, evidence, "sensitive host path")
	})
	t.Run("silent on benign path", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			HostPathMounts: []string{"/opt/app/data"},
		}}
		assertRuleSilent(t, ruleHostPathMounts(), r)
	})
}

// ── CONFIG-HOST-NAMESPACE ────────────────────────────────────────────────────

func TestRuleHostPIDorNetwork(t *testing.T) {
	t.Run("fires on hostPID", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app", HostPID: true,
		}}
		assertRuleFires(t, ruleHostPIDorNetwork(), r, "CONFIG-HOST-NAMESPACE", SeverityHigh, 8.0)
	})
	t.Run("fires on hostNetwork", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "DaemonSet", Namespace: "ns1", Name: "agent", HostNetwork: true,
		}}
		assertRuleFires(t, ruleHostPIDorNetwork(), r, "CONFIG-HOST-NAMESPACE", SeverityHigh, 8.0)
	})
	t.Run("silent on neither flag", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{Kind: "Deployment", Namespace: "ns1", Name: "app"}}
		assertRuleSilent(t, ruleHostPIDorNetwork(), r)
	})
}

// ── CONFIG-SECRETS-IN-ENV ────────────────────────────────────────────────────

func TestRuleSecretsInEnv(t *testing.T) {
	t.Run("fires on secretKeyRef env var", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "api",
			EnvSecretRefs: []kube.EnvSecretRef{{
				Container: "main", EnvVar: "DB_PASSWORD", SecretName: "db-creds", SecretKey: "password",
			}},
		}}
		_, _, nodes := assertRuleFires(t, ruleSecretsInEnv(), r, "CONFIG-SECRETS-IN-ENV", SeverityMedium, 5.0)
		if len(nodes) != 1 || nodes[0] != "workload:ns1:api" {
			t.Errorf("nodes: %v", nodes)
		}
	})
	t.Run("fires on envFrom (empty EnvVar)", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "api",
			EnvSecretRefs: []kube.EnvSecretRef{{Container: "main", SecretName: "bulk"}},
		}}
		_, evidence, _ := assertRuleFires(t, ruleSecretsInEnv(), r, "CONFIG-SECRETS-IN-ENV", SeverityMedium, 5.0)
		assertAnyEvidenceContains(t, evidence, "envFrom")
	})
	t.Run("silent without env refs", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{Kind: "Deployment", Namespace: "ns1", Name: "api"}}
		assertRuleSilent(t, ruleSecretsInEnv(), r)
	})
}

// ── CONFIG-AUTOMOUNT-SA-TOKEN ────────────────────────────────────────────────

func TestRuleAutomountSAToken(t *testing.T) {
	t.Run("fires when AutomountSAToken is nil (default true)", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app", AutomountSAToken: nil,
		}}
		assertRuleFires(t, ruleAutomountSAToken(), r, "CONFIG-AUTOMOUNT-SA-TOKEN", SeverityLow, 3.5)
	})
	t.Run("fires when explicitly true", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app", AutomountSAToken: boolPtr(true),
		}}
		assertRuleFires(t, ruleAutomountSAToken(), r, "CONFIG-AUTOMOUNT-SA-TOKEN", SeverityLow, 3.5)
	})
	t.Run("silent when explicitly false", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app", AutomountSAToken: boolPtr(false),
		}}
		assertRuleSilent(t, ruleAutomountSAToken(), r)
	})
}

// ── EXFIL-CAPTURED-SECRET-VALUES ─────────────────────────────────────────────

func TestRuleCapturedSecrets(t *testing.T) {
	t.Run("fires on captured SA token", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.SecretsMeta = []kube.SecretMeta{{
			Namespace: "ns1", Name: "sa-tok",
			Type:     "kubernetes.io/service-account-token",
			DataKeys: []string{"token", "ca.crt"},
			Values:   map[string]string{"token": "eyJ...", "ca.crt": "---"},
		}}
		_, evidence, _ := assertRuleFires(t, ruleCapturedSecrets(), r, "EXFIL-CAPTURED-SECRET-VALUES", SeverityCritical, 10.0)
		assertAnyEvidenceContains(t, evidence, "SA TOKEN CAPTURED")
	})
	t.Run("fires on generic secret with values", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.SecretsMeta = []kube.SecretMeta{{
			Namespace: "ns1", Name: "db",
			Type:     "Opaque",
			DataKeys: []string{"password"},
			Values:   map[string]string{"password": "s3cret"},
		}}
		assertRuleFires(t, ruleCapturedSecrets(), r, "EXFIL-CAPTURED-SECRET-VALUES", SeverityCritical, 10.0)
	})
	t.Run("silent without captured values", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.SecretsMeta = []kube.SecretMeta{{
			Namespace: "ns1", Name: "db",
			DataKeys: []string{"password"},
		}}
		assertRuleSilent(t, ruleCapturedSecrets(), r)
	})
}

// ── EXFIL-SENSITIVE-CONFIGMAP ────────────────────────────────────────────────

func TestRuleSensitiveConfigMaps(t *testing.T) {
	t.Run("fires on embedded kubeconfig", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ConfigMapsMeta = []kube.CMeta{{
			Namespace: "ns1", Name: "cm1",
			DataKeys: []string{"cfg"},
			Data:     map[string]string{"cfg": "apiVersion: v1\nclusters:\n- name: prod"},
		}}
		_, evidence, _ := assertRuleFires(t, ruleSensitiveConfigMaps(), r, "EXFIL-SENSITIVE-CONFIGMAP", SeverityHigh, 8.5)
		assertAnyEvidenceContains(t, evidence, "KUBECONFIG FILE")
	})
	t.Run("fires on password keyword in key name", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ConfigMapsMeta = []kube.CMeta{{
			Namespace: "ns1", Name: "cm2",
			DataKeys: []string{"db_password"},
			Data:     map[string]string{"db_password": "hunter2"},
		}}
		assertRuleFires(t, ruleSensitiveConfigMaps(), r, "EXFIL-SENSITIVE-CONFIGMAP", SeverityHigh, 8.5)
	})
	t.Run("silent when Data is empty", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.ConfigMapsMeta = []kube.CMeta{{
			Namespace: "ns1", Name: "cm1",
			DataKeys: []string{"log.level"},
		}}
		assertRuleSilent(t, ruleSensitiveConfigMaps(), r)
	})
}

// ── ESCAPE-CAP-DANGEROUS ─────────────────────────────────────────────────────

func TestRuleDangerousCapabilities(t *testing.T) {
	t.Run("fires on workload with SYS_ADMIN", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			DangerousCapabilities: []string{"main:SYS_ADMIN"},
		}}
		assertRuleFires(t, ruleDangerousCapabilities(), r, "ESCAPE-CAP-DANGEROUS", SeverityHigh, 8.5)
	})
	t.Run("fires on pod with NET_ADMIN", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Pods = []kube.PodInfo{{
			Namespace: "ns1", Name: "pod1",
			DangerousCapabilities: []string{"main:NET_ADMIN"},
		}}
		assertRuleFires(t, ruleDangerousCapabilities(), r, "ESCAPE-CAP-DANGEROUS", SeverityHigh, 8.5)
	})
	t.Run("silent on no dangerous caps", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{Kind: "Deployment", Namespace: "ns1", Name: "app"}}
		assertRuleSilent(t, ruleDangerousCapabilities(), r)
	})
}

// ── ESCAPE-HOST-IPC ──────────────────────────────────────────────────────────

func TestRuleHostIPC(t *testing.T) {
	t.Run("fires on workload with HostIPC", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app", HostIPC: true,
		}}
		assertRuleFires(t, ruleHostIPC(), r, "ESCAPE-HOST-IPC", SeverityHigh, 7.5)
	})
	t.Run("fires on pod with HostIPC", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Pods = []kube.PodInfo{{Namespace: "ns1", Name: "pod1", HostIPC: true}}
		assertRuleFires(t, ruleHostIPC(), r, "ESCAPE-HOST-IPC", SeverityHigh, 7.5)
	})
	t.Run("silent without HostIPC", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{Kind: "Deployment", Namespace: "ns1", Name: "app"}}
		assertRuleSilent(t, ruleHostIPC(), r)
	})
}

// ── CONFIG-PLAINTEXT-ENV-SECRET ──────────────────────────────────────────────

func TestRulePlaintextEnvSecret(t *testing.T) {
	t.Run("fires on workload with plaintext env", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{
			Kind: "Deployment", Namespace: "ns1", Name: "app",
			PlaintextEnvVars: []kube.PlaintextEnvVar{{
				Container: "main", EnvName: "API_KEY", Pattern: "api_key", Value: "sk_live_abc123",
			}},
		}}
		_, _, nodes := assertRuleFires(t, rulePlaintextEnvSecret(), r, "CONFIG-PLAINTEXT-ENV-SECRET", SeverityHigh, 8.0)
		if len(nodes) != 1 || nodes[0] != "workload:ns1:app" {
			t.Errorf("nodes: %v", nodes)
		}
	})
	t.Run("fires on pod with plaintext env", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Pods = []kube.PodInfo{{
			Namespace: "ns1", Name: "pod1",
			PlaintextEnvVars: []kube.PlaintextEnvVar{{
				Container: "main", EnvName: "PASSWORD", Pattern: "password", Value: "hunter2",
			}},
		}}
		assertRuleFires(t, rulePlaintextEnvSecret(), r, "CONFIG-PLAINTEXT-ENV-SECRET", SeverityHigh, 8.0)
	})
	t.Run("silent without plaintext vars", func(t *testing.T) {
		r := newEnumeration()
		r.ClusterObjects.Workloads = []kube.WorkloadInfo{{Kind: "Deployment", Namespace: "ns1", Name: "app"}}
		assertRuleSilent(t, rulePlaintextEnvSecret(), r)
	})
}
