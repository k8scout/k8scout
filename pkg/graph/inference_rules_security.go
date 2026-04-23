package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

func rulePrivilegedContainers() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-PRIVILEGED-CONTAINER",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Privileged containers detected in cluster",
		MITREIDs: []string{"T1611"},
		Mitigation: `• Replace privileged containers with specific Linux capabilities (CAP_NET_ADMIN etc.) as needed.
• Enforce Pod Security Admission 'restricted' or 'baseline' to prevent privileged containers.
• Audit why each privileged container requires elevated access and minimize.
• Use Falco to detect privileged container activity at runtime.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wl := range r.ClusterObjects.Workloads {
				if len(wl.PrivilegedContainers) > 0 {
					evidence = append(evidence, fmt.Sprintf("Workload %s/%s has privileged containers: %v",
						wl.Namespace, wl.Name, wl.PrivilegedContainers))
					nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
				}
			}
			for _, pod := range r.ClusterObjects.Pods {
				if len(pod.PrivilegedContainers) > 0 {
					evidence = append(evidence, fmt.Sprintf("Pod %s/%s has privileged containers: %v",
						pod.Namespace, pod.Name, pod.PrivilegedContainers))
					nodes = append(nodes, "pod:"+pod.Namespace+":"+pod.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d privileged container(s) detected. Privileged containers have full "+
				"access to the host kernel and can be used for container breakout.", len(evidence)), evidence, nodes
		},
	}
}

func ruleHostPathMounts() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-HOSTPATH-MOUNT",
		Severity: SeverityHigh,
		Score:    7.5,
		Title:    "HostPath volumes detected — host filesystem exposure",
		MITREIDs: []string{"T1611"},
		Mitigation: `• Replace hostPath mounts with PersistentVolumeClaims.
• If hostPath is required, use readOnly=true and restrict to the minimum path.
• Block hostPath via OPA/Gatekeeper or Kyverno policy.
• Especially dangerous paths: /, /etc, /var/run/docker.sock, /run/containerd, /etc/kubernetes/pki.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			// Critical paths enable credential theft or container escape.
			criticalPaths := []struct {
				prefix string
				label  string
			}{
				{"/var/run/docker.sock", "CRITICAL: Docker socket → container escape"},
				{"/run/containerd", "CRITICAL: containerd socket → container escape"},
				{"/etc/kubernetes/pki", "CRITICAL: cluster PKI → CA key theft"},
				{"/etc/kubernetes", "CRITICAL: cluster config → credential theft"},
				{"/var/lib/kubelet", "CRITICAL: kubelet data → credential theft"},
			}
			highPaths := []string{"/proc", "/sys", "/root", "/", "/etc", "/var/run", "/run"}
			var evidence []string
			var nodes []string
			seen := map[string]bool{}
			check := func(paths []string, label string) {
				for _, p := range paths {
					tag := ""
					for _, cp := range criticalPaths {
						if p == cp.prefix || strings.HasPrefix(p, cp.prefix+"/") {
							tag = cp.label
							break
						}
					}
					if tag == "" {
						for _, hp := range highPaths {
							if p == hp || strings.HasPrefix(p, hp+"/") {
								tag = "HIGH: sensitive host path"
								break
							}
						}
					}
					if tag != "" {
						evidence = append(evidence, fmt.Sprintf("%s mounts %q [%s]", label, p, tag))
						if !seen[label] {
							seen[label] = true
							nodes = append(nodes, label)
						}
					}
				}
			}
			for _, wl := range r.ClusterObjects.Workloads {
				check(wl.HostPathMounts, "workload:"+wl.Namespace+":"+wl.Name)
			}
			for _, pod := range r.ClusterObjects.Pods {
				check(pod.HostPathMounts, "pod:"+pod.Namespace+":"+pod.Name)
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d workload(s)/pod(s) mount sensitive hostPath volumes. "+
				"These grant containers read/write access to host filesystem paths, "+
				"enabling credential theft or container escape.", len(nodes)), evidence, nodes
		},
	}
}

func ruleHostPIDorNetwork() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-HOST-NAMESPACE",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Pods using host PID/Network namespace — container isolation bypass",
		Mitigation: `• Remove hostPID and hostNetwork from all workloads that don't require them.
• hostPID allows process inspection/signal of all host processes.
• hostNetwork exposes the host network stack and can bypass NetworkPolicies.
• Enforce via Pod Security Admission 'restricted' policy.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wl := range r.ClusterObjects.Workloads {
				if wl.HostPID || wl.HostNetwork {
					flags := []string{}
					if wl.HostPID {
						flags = append(flags, "hostPID")
					}
					if wl.HostNetwork {
						flags = append(flags, "hostNetwork")
					}
					evidence = append(evidence, fmt.Sprintf("Workload %s/%s: %s", wl.Namespace, wl.Name, strings.Join(flags, ",")))
					nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "Workloads are sharing host PID or network namespaces, significantly reducing " +
				"container isolation and enabling attacks against host processes.", evidence, nodes
		},
	}
}

func ruleSecretsInEnv() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-SECRETS-IN-ENV",
		Severity: SeverityMedium,
		Score:    5.0,
		Title:    "Secrets exposed as environment variables in workloads",
		Mitigation: `• Prefer volume mounts over environment variables for secrets — env vars appear in process
  listings (/proc/<pid>/environ), crash dumps, debug logs, and kubectl describe output.
• Use external secret stores (HashiCorp Vault, AWS Secrets Manager, ESO) with sidecar injection.
• If env vars are unavoidable, scope the secret to specific resourceNames in RBAC.
• Rotate secrets that have been visible as env vars in case of prior exposure.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			seen := make(map[string]bool) // deduplicate by workload ID
			var nodes []string
			for _, wl := range r.ClusterObjects.Workloads {
				if len(wl.EnvSecretRefs) == 0 {
					continue
				}
				wlID := "workload:" + wl.Namespace + ":" + wl.Name
				for _, ref := range wl.EnvSecretRefs {
					if ref.EnvVar != "" {
						evidence = append(evidence, fmt.Sprintf(
							"%s/%s [%s]: env var %q → secret %q key %q",
							wl.Namespace, wl.Name, ref.Container, ref.EnvVar, ref.SecretName, ref.SecretKey))
					} else {
						evidence = append(evidence, fmt.Sprintf(
							"%s/%s [%s]: envFrom secret %q (all keys injected as env vars)",
							wl.Namespace, wl.Name, ref.Container, ref.SecretName))
					}
				}
				if !seen[wlID] {
					seen[wlID] = true
					nodes = append(nodes, wlID)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf(
				"%d workload(s) inject secrets as environment variables. "+
					"Env vars are accessible to any process in the container, appear in process listings, "+
					"and may leak into logs or crash reports.", len(nodes))
			return desc, evidence, nodes
		},
	}
}

func ruleAutomountSAToken() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-AUTOMOUNT-SA-TOKEN",
		Severity: SeverityLow,
		Score:    3.5,
		Title:    "Workloads with automountServiceAccountToken not explicitly disabled",
		Mitigation: `• Set automountServiceAccountToken: false on all pods/SAs that don't need API access.
• This prevents the SA token from being injected into the pod filesystem, reducing SSRF blast radius.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wl := range r.ClusterObjects.Workloads {
				if wl.AutomountSAToken == nil || *wl.AutomountSAToken {
					evidence = append(evidence, fmt.Sprintf("Workload %s/%s does not disable automountServiceAccountToken", wl.Namespace, wl.Name))
					nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d workload(s) automatically mount a ServiceAccount token. "+
				"If these workloads don't need API access, the token is unnecessary attack surface.", len(evidence)), evidence, nodes
		},
	}
}

func ruleCapturedSecrets() inferenceRule {
	return inferenceRule{
		RuleID:   "EXFIL-CAPTURED-SECRET-VALUES",
		Severity: SeverityCritical,
		Score:    10.0,
		Title:    "Secret values captured — live credential material confirmed accessible",
		Mitigation: `• The scanning identity has confirmed GET access to secret values.
• Immediately rotate all captured secrets (tokens, passwords, certificates).
• Restrict secret GET to specific resourceNames via RBAC.
• Migrate credentials to an external secret store (Vault, AWS Secrets Manager).
• See cluster_objects.secrets_meta[*].values in the JSON report for captured data.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			tokenCount := 0
			for _, sm := range r.ClusterObjects.SecretsMeta {
				if len(sm.Values) == 0 {
					continue
				}
				isToken := sm.Type == "kubernetes.io/service-account-token" ||
					sm.Values["token"] != "" || sm.Values["ca.crt"] != ""
				if isToken {
					tokenCount++
					evidence = append(evidence, fmt.Sprintf(
						"Secret %s/%s (type=%s) — SA TOKEN CAPTURED (keys: %v)",
						sm.Namespace, sm.Name, sm.Type, sm.DataKeys))
				} else {
					evidence = append(evidence, fmt.Sprintf(
						"Secret %s/%s (type=%s, keys=%v) — values captured",
						sm.Namespace, sm.Name, sm.Type, sm.DataKeys))
				}
				nodes = append(nodes, "secret:"+sm.Namespace+":"+sm.Name)
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf(
				"%d secret(s) captured (%d service-account tokens). "+
					"The current identity confirmed GET access to plaintext secret data including JWTs, "+
					"passwords, and certificates. This confirms Chain 1 of the attack path: "+
					"list/get secrets → steal admin-token JWT → authenticate as target SA.",
				len(evidence), tokenCount)
			return desc, evidence, nodes
		},
	}
}

func ruleSensitiveConfigMaps() inferenceRule {
	return inferenceRule{
		RuleID:   "EXFIL-SENSITIVE-CONFIGMAP",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "ConfigMap data captured — check for leaked credentials or kubeconfig",
		Mitigation: `• ConfigMaps should never contain kubeconfig files, tokens, or credentials.
• Audit all captured ConfigMaps for sensitive data and migrate to Secrets or external stores.
• Restrict ConfigMap GET to specific resourceNames.
• See cluster_objects.configmaps_meta[*].data in the JSON report for captured content.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			sensitiveKeywords := []string{"kubeconfig", "kube-config", "token", "password", "credentials", "key", "cert", "secret"}
			kubeconfigCount := 0
			for _, cm := range r.ClusterObjects.ConfigMapsMeta {
				if len(cm.Data) == 0 {
					continue
				}
				for k, v := range cm.Data {
					kLower := strings.ToLower(k)
					vLower := strings.ToLower(v)
					isSensitive := false
					for _, kw := range sensitiveKeywords {
						if strings.Contains(kLower, kw) {
							isSensitive = true
							break
						}
					}
					// Detect kubeconfig content by value signature.
					if strings.Contains(vLower, "apiversion: v1") && strings.Contains(vLower, "clusters:") {
						isSensitive = true
						kubeconfigCount++
						evidence = append(evidence, fmt.Sprintf(
							"ConfigMap %s/%s key %q appears to contain a KUBECONFIG FILE — CRITICAL lateral movement vector",
							cm.Namespace, cm.Name, k))
					} else if isSensitive {
						preview := v
						if len(preview) > 80 {
							preview = preview[:80] + "..."
						}
						evidence = append(evidence, fmt.Sprintf(
							"ConfigMap %s/%s key %q has sensitive content: %s", cm.Namespace, cm.Name, k, preview))
					}
				}
				if len(cm.Data) > 0 && len(evidence) == 0 {
					evidence = append(evidence, fmt.Sprintf(
						"ConfigMap %s/%s data captured (keys: %v) — review for sensitive content",
						cm.Namespace, cm.Name, cm.DataKeys))
				}
				nodes = append(nodes, "configmap:"+cm.Namespace+":"+cm.Name)
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf(
				"%d ConfigMap(s) captured (%d potential kubeconfig files). "+
					"The current identity confirmed GET access to ConfigMap data. "+
					"This enables Chain 4 of the attack path: get configmaps → read leaked-kubeconfig → "+
					"kubectl --kubeconfig=<leaked> get secrets -A.",
				len(nodes), kubeconfigCount)
			return desc, evidence, nodes
		},
	}
}

func ruleDangerousCapabilities() inferenceRule {
	return inferenceRule{
		RuleID:   "ESCAPE-CAP-DANGEROUS",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Containers with dangerous Linux capabilities detected",
		MITREIDs: []string{"T1611"},
		Mitigation: `• Remove SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, and DAC_READ_SEARCH from container capability sets.
• SYS_ADMIN is nearly equivalent to running privileged — it enables mounting, namespace manipulation, and more.
• SYS_MODULE allows loading kernel modules, enabling rootkits.
• Apply Pod Security Admission 'restricted' profile which drops all capabilities.
• Use seccomp profiles to restrict syscalls even when capabilities are set.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wl := range r.ClusterObjects.Workloads {
				if len(wl.DangerousCapabilities) > 0 {
					evidence = append(evidence, fmt.Sprintf("Workload %s/%s has dangerous caps in containers: %v",
						wl.Namespace, wl.Name, wl.DangerousCapabilities))
					nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
				}
			}
			for _, pod := range r.ClusterObjects.Pods {
				if len(pod.DangerousCapabilities) > 0 {
					evidence = append(evidence, fmt.Sprintf("Pod %s/%s has dangerous caps in containers: %v",
						pod.Namespace, pod.Name, pod.DangerousCapabilities))
					nodes = append(nodes, "pod:"+pod.Namespace+":"+pod.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d workload(s)/pod(s) grant dangerous Linux capabilities "+
				"(SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, or DAC_READ_SEARCH). "+
				"These capabilities enable container escape, kernel module injection, and process introspection.", len(evidence)), evidence, nodes
		},
	}
}

func ruleHostIPC() inferenceRule {
	return inferenceRule{
		RuleID:   "ESCAPE-HOST-IPC",
		Severity: SeverityHigh,
		Score:    7.5,
		Title:    "Pods using host IPC namespace — cross-process memory introspection",
		MITREIDs: []string{"T1611"},
		Mitigation: `• Remove hostIPC from all workloads that do not have a documented requirement.
• hostIPC allows a container to attach to shared memory segments of host processes, enabling memory scraping.
• Enforce Pod Security Admission 'baseline' or 'restricted' to block hostIPC.
• Use Falco to detect container processes accessing host IPC namespaces.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wl := range r.ClusterObjects.Workloads {
				if wl.HostIPC {
					evidence = append(evidence, fmt.Sprintf("Workload %s/%s has hostIPC: true", wl.Namespace, wl.Name))
					nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
				}
			}
			for _, pod := range r.ClusterObjects.Pods {
				if pod.HostIPC {
					evidence = append(evidence, fmt.Sprintf("Pod %s/%s has hostIPC: true", pod.Namespace, pod.Name))
					nodes = append(nodes, "pod:"+pod.Namespace+":"+pod.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d workload(s)/pod(s) share the host IPC namespace. "+
				"This allows containers to inspect shared memory segments of host processes, "+
				"potentially exposing sensitive data or enabling inter-process attacks.", len(evidence)), evidence, nodes
		},
	}
}

func rulePlaintextEnvSecret() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-PLAINTEXT-ENV-SECRET",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Plaintext secret hardcoded in pod/workload environment variable",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• Move secret values into Kubernetes Secrets and reference via secretKeyRef or envFrom.
• Use an external secret store (HashiCorp Vault, AWS Secrets Manager, ESO) to eliminate hardcoded values.
• Scan pod specs in CI/CD with tools like detect-secrets or trivy to prevent future occurrences.
• Rotate any exposed credentials immediately.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			seen := map[string]bool{}
			for _, wl := range r.ClusterObjects.Workloads {
				for _, ev := range wl.PlaintextEnvVars {
					preview := ev.Value
					if len(preview) > 40 {
						preview = preview[:40] + "..."
					}
					evidence = append(evidence, fmt.Sprintf(
						"Workload %s/%s [%s] env %s (pattern: %q): %s",
						wl.Namespace, wl.Name, ev.Container, ev.EnvName, ev.Pattern, preview))
					nid := "workload:" + wl.Namespace + ":" + wl.Name
					if !seen[nid] {
						seen[nid] = true
						nodes = append(nodes, nid)
					}
				}
			}
			for _, pod := range r.ClusterObjects.Pods {
				for _, ev := range pod.PlaintextEnvVars {
					preview := ev.Value
					if len(preview) > 40 {
						preview = preview[:40] + "..."
					}
					evidence = append(evidence, fmt.Sprintf(
						"Pod %s/%s [%s] env %s (pattern: %q): %s",
						pod.Namespace, pod.Name, ev.Container, ev.EnvName, ev.Pattern, preview))
					nid := "pod:" + pod.Namespace + ":" + pod.Name
					if !seen[nid] {
						seen[nid] = true
						nodes = append(nodes, nid)
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("%d workload(s)/pod(s) contain plaintext secrets hardcoded in environment variables. "+
				"These values are visible to anyone with read access to pod specs, "+
				"stored unencrypted in etcd, and may appear in audit logs.", len(nodes))
			return desc, evidence, nodes
		},
	}
}
