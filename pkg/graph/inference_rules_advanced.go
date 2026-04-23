package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

// ── Phase 2 additions ─────────────────────────────────────────────────────────

func ruleCloudIRSAEscalation() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-IRSA-ESCALATION",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "ServiceAccount with cloud IAM role annotation — cross-cloud escalation path",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Audit all cloud IAM roles bound to Kubernetes service accounts.
• Apply least-privilege IAM policies to IRSA/Workload-Identity roles.
• Use IAM Conditions (AWS: aws:RequestedRegion, GCP: resource.name) to limit scope.
• Enable CloudTrail/Cloud Audit Logs for actions performed via workload identity.
• Revoke unused IRSA roles immediately; any pod running as this SA can call cloud APIs.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				var cloudRole, provider string
				switch {
				case sa.IRSARole != "":
					cloudRole = sa.IRSARole
					provider = "AWS"
				case sa.AzureIdentity != "":
					cloudRole = sa.AzureIdentity
					provider = "Azure"
				case sa.GCPServiceAccount != "":
					cloudRole = sa.GCPServiceAccount
					provider = "GCP"
				default:
					continue
				}
				// Check if this SA is actually bound to any workload.
				bound := false
				for _, wl := range r.ClusterObjects.Workloads {
					if wl.Namespace == sa.Namespace && wl.ServiceAccount == sa.Name {
						bound = true
						break
					}
				}
				if !bound {
					for _, pod := range r.ClusterObjects.Pods {
						if pod.Namespace == sa.Namespace && pod.ServiceAccount == sa.Name {
							bound = true
							break
						}
					}
				}
				ev := fmt.Sprintf("[%s] SA %s/%s → %s cloud role %q", provider, sa.Namespace, sa.Name, provider, cloudRole)
				if !bound {
					ev += " (no workload bound — dormant)"
				}
				evidence = append(evidence, ev)
				nodes = append(nodes, fmt.Sprintf("sa:%s:%s", sa.Namespace, sa.Name))
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("%d ServiceAccount(s) carry cloud IAM role annotations. "+
				"Any workload running as these SAs can call cloud APIs (S3, IAM, KMS, etc.) "+
				"using the pod's projected service account token — no secrets required. "+
				"Compromising these pods enables cross-cloud privilege escalation.", len(evidence))
			return desc, evidence, nodes
		},
	}
}

func ruleHelmReleaseSecrets() inferenceRule {
	return inferenceRule{
		RuleID:   "EXFIL-HELM-RELEASE",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Helm release secrets present — chart values may contain credentials",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• Helm release secrets (type=helm.sh/release.v1) store chart values including passwords, tokens, and keys.
• Restrict 'get secrets' RBAC to prevent reading Helm release data.
• Use Helm Secrets plugin or external secret stores to avoid embedding credentials in values.yaml.
• Rotate any credentials that appear in Helm chart values.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, sm := range r.ClusterObjects.SecretsMeta {
				if sm.Type == "helm.sh/release.v1" {
					ev := fmt.Sprintf("Helm release secret: %s/%s", sm.Namespace, sm.Name)
					if len(sm.Values) > 0 {
						ev += " [VALUES CAPTURED — check for embedded credentials]"
					}
					evidence = append(evidence, ev)
					nodes = append(nodes, "secret:"+sm.Namespace+":"+sm.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("%d Helm release secret(s) found (type=helm.sh/release.v1). "+
				"These store the full rendered chart values including any passwords, API keys, "+
				"or connection strings passed at deploy time. "+
				"An identity with 'get secrets' access can read all chart values.", len(evidence))
			return desc, evidence, nodes
		},
	}
}

func ruleMutatingWebhookPrivesc() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-MUTATING-WEBHOOK",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Identity can patch MutatingWebhookConfigurations → intercept any pod",
		MITREIDs: []string{"T1610"},
		Mitigation: `• Patching MutatingWebhookConfigurations allows redirecting all admission requests to an attacker-controlled endpoint.
• Restrict patch/create on mutatingwebhookconfigurations to platform-team break-glass accounts only.
• Use OPA/Gatekeeper to require webhook configurations to point to approved service endpoints.
• Alert on any change to MutatingWebhookConfigurations via audit policy.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if !c.Allowed {
					continue
				}
				if (c.Resource == "mutatingwebhookconfigurations") &&
					(c.Verb == "patch" || c.Verb == "create" || c.Verb == "update") {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s mutatingwebhookconfigurations = allowed", c.Verb))
				}
			}
			if len(evidence) == 0 {
				// Check SSRR as fallback.
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "mutatingwebhookconfigurations", "*") &&
							containsAny(rule.Verbs, "patch", "create", "update", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: patch/create mutatingwebhookconfigurations in %q", ns))
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := "The current identity can modify MutatingWebhookConfigurations. " +
				"An attacker can redirect admission requests to a rogue HTTPS endpoint, " +
				"mutating any new pod spec to inject malicious containers, steal SA tokens, " +
				"or add environment variables with exfiltration payloads. " +
				"Attack: patch the webhook to point to attacker.example.com, then wait for pod creation."
			return desc, evidence, nil
		},
	}
}

func ruleProjectedTokenAudience() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-PROJECTED-TOKEN-AUDIENCE",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Projected SA tokens with non-Kubernetes audience — usable outside cluster",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Projected tokens with custom audiences are designed for external service authentication.
• Ensure only intended services can receive these tokens (verify audience consumers).
• Apply short expiration times (ExpirationSeconds) to projected tokens.
• Audit which workloads mount non-standard audience tokens and verify necessity.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			seen := map[string]bool{}
			checkVols := func(vols []kube.VolumeRef, label string) {
				for _, vol := range vols {
					if vol.SourceKind == "Projected" && vol.Audience != "" {
						evidence = append(evidence, fmt.Sprintf(
							"%s: projected SA token with audience %q (usable by external service %q)",
							label, vol.Audience, vol.Audience))
						if !seen[label] {
							seen[label] = true
							nodes = append(nodes, label)
						}
					}
				}
			}
			for _, wl := range r.ClusterObjects.Workloads {
				checkVols(wl.Volumes, "workload:"+wl.Namespace+":"+wl.Name)
			}
			for _, pod := range r.ClusterObjects.Pods {
				checkVols(pod.Volumes, "pod:"+pod.Namespace+":"+pod.Name)
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("%d workload(s)/pod(s) mount projected ServiceAccount tokens with non-Kubernetes "+
				"audiences. These tokens are signed by the cluster but accepted by external services "+
				"(AWS STS, Vault, etc.). A container compromise yields a token usable outside the cluster.", len(nodes))
			return desc, evidence, nodes
		},
	}
}

func ruleNodeCompromise() inferenceRule {
	return inferenceRule{
		RuleID:   "ESCAPE-NODE-COMPROMISE",
		Severity: SeverityCritical,
		Score:    9.8,
		Title:    "Critical hostPath + exec access → node-level compromise path",
		MITREIDs: []string{"T1611"},
		Mitigation: `• Remove hostPath mounts to critical paths (/etc/kubernetes, /var/lib/kubelet, /etc/kubernetes/pki).
• Restrict pods/exec to break-glass accounts only; use ephemeral containers for debugging.
• Enable Pod Security Admission 'restricted' to block hostPath on production workloads.
• Use Falco to detect exec into pods that have critical hostPath mounts.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			criticalPaths := []string{
				"/etc/kubernetes", "/etc/kubernetes/pki",
				"/var/lib/kubelet", "/var/lib/etcd",
			}
			canExec := false
			for _, c := range r.Permissions.SSARChecks {
				if c.Allowed && c.Resource == "pods" && c.Subresource == "exec" {
					canExec = true
					break
				}
			}
			if !canExec {
				// Also check SSRR.
				for _, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "pods/exec", "*") && containsAny(rule.Verbs, "create", "*") {
							canExec = true
							break
						}
					}
					if canExec {
						break
					}
				}
			}
			if !canExec {
				return "", nil, nil
			}
			var evidence []string
			var nodes []string
			seen := map[string]bool{}
			checkPaths := func(paths []string, label string) {
				for _, p := range paths {
					for _, cp := range criticalPaths {
						if p == cp || strings.HasPrefix(p, cp+"/") {
							evidence = append(evidence, fmt.Sprintf(
								"%s mounts %q AND identity can exec → exec in → read node credentials", label, p))
							if !seen[label] {
								seen[label] = true
								nodes = append(nodes, label)
							}
						}
					}
				}
			}
			for _, wl := range r.ClusterObjects.Workloads {
				checkPaths(wl.HostPathMounts, "workload:"+wl.Namespace+":"+wl.Name)
			}
			for _, pod := range r.ClusterObjects.Pods {
				checkPaths(pod.HostPathMounts, "pod:"+pod.Namespace+":"+pod.Name)
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("CRITICAL: The current identity can exec into %d pod(s) that mount critical "+
				"host paths (/etc/kubernetes/pki, /var/lib/kubelet). "+
				"Attack: exec into pod → read kubelet client cert or cluster CA key → "+
				"forge credentials for any cluster identity.", len(nodes))
			return desc, evidence, nodes
		},
	}
}

// ── Batch 2 detection rules ───────────────────────────────────────────────────

func ruleNodeProxy() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-NODE-PROXY",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Identity can use nodes/proxy subresource — direct kubelet API access",
		MITREIDs: []string{"T1078.001"},
		Mitigation: `• Remove nodes/proxy from all non-system service accounts.
• nodes/proxy allows direct, unauthenticated-from-kubelet-perspective requests that bypass RBAC on the kubelet.
• Enable NodeRestriction admission plugin (default since k8s 1.17) and audit logs on kubelet access.
• Rotate any credential that has held this permission.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "nodes" && c.Subresource == "proxy" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s nodes/proxy in %q = allowed", c.Verb, c.Namespace))
				}
			}
			if len(evidence) == 0 {
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "nodes/proxy", "*") && containsAny(rule.Verbs, "create", "get", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: nodes/proxy access in namespace %q", ns))
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can use the nodes/proxy subresource, which tunnels arbitrary " +
				"HTTP requests directly to the kubelet API. This bypasses RBAC for kubelet endpoints, " +
				"enabling attackers to read pod logs, execute commands, and access node-level secrets.", evidence, nil
		},
	}
}

func rulePatchSecrets() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-PATCH-SECRETS",
		Severity: SeverityCritical,
		Score:    9.0,
		Title:    "Identity can patch/update Secrets — credential overwrite vector",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• patch/update on secrets is as dangerous as read access — an attacker can overwrite any credential.
• Restrict secret mutation to dedicated secret-management service accounts only.
• Enable audit logging for secret patch/update and alert immediately.
• Consider using external secret stores where mutation is controlled by the store's own ACL.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "secrets" && (c.Verb == "patch" || c.Verb == "update") && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s secrets in %q = allowed", c.Verb, c.Namespace))
					nodes = append(nodes, "resource:"+c.Namespace+":secrets")
				}
			}
			if len(evidence) == 0 {
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "secrets", "*") && containsAny(rule.Verbs, "patch", "update", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: patch/update secrets in %q", ns))
							nodes = append(nodes, "resource:"+ns+":secrets")
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("The current identity can patch or update Secrets in %d namespace(s). "+
				"An attacker can overwrite secret data values — replacing credentials with attacker-controlled "+
				"values or inserting malicious content consumed by workloads.", len(evidence)), evidence, nodes
		},
	}
}

func ruleLateralExecSecretMount() inferenceRule {
	return inferenceRule{
		RuleID:   "LATERAL-EXEC-SECRET-MOUNT",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Exec access + Secret-mounting pods — credential harvest via shell",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• Remove pods/exec from all non-administrative service accounts.
• Use ephemeral debug containers with time-limited RBAC as a safer alternative.
• Ensure secrets are mounted with read-only projections and short-TTL bound tokens.
• Alert on exec events into pods that mount Secrets (Falco rule: k8s_audit exec with secret volume).`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			canExec := false
			for _, c := range r.Permissions.SSARChecks {
				if c.Allowed && c.Resource == "pods" && c.Subresource == "exec" {
					canExec = true
					break
				}
			}
			if !canExec {
				for _, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "pods/exec", "*") && containsAny(rule.Verbs, "create", "*") {
							canExec = true
							break
						}
					}
					if canExec {
						break
					}
				}
			}
			if !canExec {
				return "", nil, nil
			}
			var evidence []string
			var nodes []string
			seen := map[string]bool{}
			checkSecretMounts := func(volumes []kube.VolumeRef, label string) {
				for _, v := range volumes {
					if v.SourceKind == "Secret" {
						evidence = append(evidence, fmt.Sprintf(
							"%s mounts Secret %q AND identity can exec → exec in → read mounted secret", label, v.SourceName))
						if !seen[label] {
							seen[label] = true
							nodes = append(nodes, label)
						}
						break
					}
				}
			}
			for _, wl := range r.ClusterObjects.Workloads {
				checkSecretMounts(wl.Volumes, "workload:"+wl.Namespace+":"+wl.Name)
			}
			for _, pod := range r.ClusterObjects.Pods {
				checkSecretMounts(pod.Volumes, "pod:"+pod.Namespace+":"+pod.Name)
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("The current identity can exec into pods AND %d pod(s)/workload(s) mount "+
				"Secret volumes. An attacker can exec into any such pod and directly read mounted secret "+
				"files from the container filesystem.", len(nodes)), evidence, nodes
		},
	}
}

func ruleCreateDaemonsets() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-CREATE-DAEMONSETS",
		Severity: SeverityCritical,
		Score:    9.0,
		Title:    "Identity can create DaemonSets — cluster-wide code execution",
		MITREIDs: []string{"T1609"},
		Mitigation: `• DaemonSets schedule pods on every node — creating one is equivalent to cluster-wide code execution.
• Restrict daemonsets create to cluster administrators only.
• Use admission webhooks (OPA/Gatekeeper, Kyverno) to enforce Pod Security Standards on new DaemonSets.
• Audit all DaemonSet creations and alert on any created outside standard CI/CD pipelines.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "daemonsets" && c.Verb == "create" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: create daemonsets in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "daemonsets", "*") && containsAny(rule.Verbs, "create", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: create daemonsets in %q", ns))
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can create DaemonSets. A DaemonSet schedules a pod on every node " +
				"simultaneously. An attacker can create a DaemonSet with a privileged container or hostPath " +
				"mount to achieve node-level code execution across the entire cluster.", evidence, nil
		},
	}
}

func rulePatchServiceAccounts() inferenceRule {
	return inferenceRule{
		RuleID:   "LATERAL-PATCH-SA",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Identity can patch ServiceAccounts — workload identity injection",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• patch/update on serviceaccounts allows adding IRSA/Workload Identity annotations to any SA.
• An attacker can annotate any SA with a high-privilege cloud IAM role ARN, then pods using that SA gain cloud access.
• Restrict serviceaccount mutation to dedicated identity management accounts.
• Enable audit logging and alert on annotation changes to service accounts.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "serviceaccounts" && (c.Verb == "patch" || c.Verb == "update") && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s serviceaccounts in %q = allowed", c.Verb, c.Namespace))
					nodes = append(nodes, "resource:"+c.Namespace+":serviceaccounts")
				}
			}
			if len(evidence) == 0 {
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "serviceaccounts", "*") && containsAny(rule.Verbs, "patch", "update", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: patch/update serviceaccounts in %q", ns))
							nodes = append(nodes, "resource:"+ns+":serviceaccounts")
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("The current identity can patch ServiceAccounts in %d namespace(s). "+
				"An attacker can inject IRSA/Azure Workload Identity/GKE Workload Identity annotations, "+
				"granting pods using that SA elevated cloud IAM permissions.", len(evidence)), evidence, nodes
		},
	}
}

func ruleWatchSecrets() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIV-WATCH-SECRETS",
		Severity: SeverityHigh,
		Score:    7.5,
		Title:    "Identity can watch Secrets — continuous credential streaming",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• watch on secrets streams all secret creation and update events in real time.
• This is equivalent to persistent read access — an attacker gets every secret change automatically.
• Revoke watch permission on secrets unless strictly required for a controller.
• Enable audit logging for secret watch events and alert on unexpected principals.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "secrets" && c.Verb == "watch" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: watch secrets in %q = allowed", c.Namespace))
					nodes = append(nodes, "resource:"+c.Namespace+":secrets")
				}
			}
			if len(evidence) == 0 {
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "secrets", "*") && containsAny(rule.Verbs, "watch", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: watch secrets in %q", ns))
							nodes = append(nodes, "resource:"+ns+":secrets")
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("The current identity can watch Secrets in %d namespace(s). "+
				"The watch verb opens a streaming connection that delivers every secret create/update event, "+
				"providing continuous access to all credential changes.", len(evidence)), evidence, nodes
		},
	}
}

func rulePatchNodes() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-PATCH-NODES",
		Severity: SeverityMedium,
		Score:    6.5,
		Title:    "Identity can patch/update Nodes — label manipulation and scheduling attacks",
		MITREIDs: []string{"T1609"},
		Mitigation: `• patch/update on nodes allows modifying labels and taints, influencing pod scheduling.
• An attacker can remove NoSchedule taints from sensitive nodes or add labels to steer workloads.
• Restrict node mutation to system:nodes group and dedicated node management controllers.
• Monitor for unexpected node label or taint changes via audit logging.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "nodes" && (c.Verb == "patch" || c.Verb == "update") && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s nodes = allowed", c.Verb))
				}
			}
			if len(evidence) == 0 {
				for _, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "nodes", "*") && containsAny(rule.Verbs, "patch", "update", "*") {
							evidence = append(evidence, "SSRR: patch/update nodes")
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can patch or update Node objects. An attacker can manipulate node " +
				"labels to influence pod scheduling, remove protective taints (e.g., NoSchedule), or corrupt " +
				"node status information used by the scheduler and controllers.", evidence, nil
		},
	}
}

func rulePatchStatefulSets() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-PATCH-STATEFULSETS",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Identity can patch/update StatefulSets — persistent volume access + SA lateral movement",
		MITREIDs: []string{"T1609"},
		Mitigation: `• patch/update on statefulsets enables injecting new containers, changing the service account, or modifying volume mounts.
• StatefulSets use PersistentVolumes — a patched container can access all existing persistent data.
• Restrict statefulset mutation to dedicated deployment accounts.
• Use admission webhooks to block SA changes in StatefulSet patches.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "statefulsets" && (c.Verb == "patch" || c.Verb == "update") && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s statefulsets in %q = allowed", c.Verb, c.Namespace))
				}
			}
			if len(evidence) == 0 {
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "statefulsets", "*") && containsAny(rule.Verbs, "patch", "update", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: patch/update statefulsets in %q", ns))
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can patch or update StatefulSets. An attacker can modify the pod " +
				"template to inject a malicious container or change the service account, gaining access to " +
				"persistent volumes and the permissions of the patched StatefulSet's SA.", evidence, nil
		},
	}
}

// ── Operator abuse and webhook bypass rules ───────────────────────────────────

func ruleArgoCDOperatorAbuse() inferenceRule {
	return inferenceRule{
		RuleID:   "LATERAL-ARGOCD-OPERATOR",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Can create/patch ArgoCD Applications — GitOps deployment hijack",
		MITREIDs: []string{"T1072"},
		Mitigation: `• Restrict create/patch on applications.argoproj.io to ArgoCD-dedicated service accounts only.
• Use AppProject RBAC to limit which repositories and destination namespaces are permitted.
• Enable ArgoCD SSO with RBAC policies; require human approval for Application changes.
• Alert on Application spec changes via ArgoCD notifications or Kubernetes audit logs.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			// Only fire if ArgoCD CRDs are present.
			hasArgo := false
			for _, crd := range r.ClusterObjects.CRDs {
				if crd.Group == "argoproj.io" {
					hasArgo = true
					break
				}
			}
			if !hasArgo {
				return "", nil, nil
			}
			var evidence []string
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					if containsAny(rule.Resources, "applications", "*") &&
						containsAny(rule.Verbs, "create", "patch", "update", "*") {
						evidence = append(evidence, fmt.Sprintf(
							"SSRR: create/patch applications.argoproj.io in %q", ns))
					}
				}
			}
			for _, c := range r.Permissions.SSARChecks {
				if c.Allowed && c.Resource == "applications" &&
					(c.Verb == "create" || c.Verb == "patch" || c.Verb == "update") {
					evidence = append(evidence, fmt.Sprintf(
						"SSAR: %s applications.argoproj.io in %q = allowed", c.Verb, c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := "The current identity can create or patch ArgoCD Application resources AND ArgoCD CRDs are present. " +
				"An attacker can modify an Application to sync from a malicious Git repository, " +
				"deploying arbitrary workloads with any service account in any permitted namespace."
			return desc, evidence, []string{"crd:argoproj.io/applications"}
		},
	}
}

func ruleFluxOperatorAbuse() inferenceRule {
	return inferenceRule{
		RuleID:   "LATERAL-FLUX-OPERATOR",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Can create/patch Flux Kustomizations or HelmReleases — GitOps pipeline hijack",
		MITREIDs: []string{"T1072"},
		Mitigation: `• Restrict create/patch on kustomizations.kustomize.toolkit.fluxcd.io and helmreleases.helm.toolkit.fluxcd.io.
• Use Flux RBAC policies and tenant isolation to limit which namespaces can be targeted.
• Enable Flux notifications and alert on Kustomization/HelmRelease changes.
• Pin source repositories with cosign verification to prevent supply-chain injection.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			fluxResources := []string{"kustomizations", "helmreleases"}
			fluxGroups := map[string]bool{
				"kustomize.toolkit.fluxcd.io": true,
				"helm.toolkit.fluxcd.io":      true,
			}
			hasFlux := false
			for _, crd := range r.ClusterObjects.CRDs {
				if fluxGroups[crd.Group] {
					hasFlux = true
					break
				}
			}
			if !hasFlux {
				return "", nil, nil
			}
			var evidence []string
			var nodes []string
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					if containsAny(rule.Resources, append(fluxResources, "*")...) &&
						containsAny(rule.Verbs, "create", "patch", "update", "*") {
						evidence = append(evidence, fmt.Sprintf(
							"SSRR: create/patch Flux CRs in %q", ns))
					}
				}
			}
			for _, c := range r.Permissions.SSARChecks {
				if c.Allowed && containsAny(fluxResources, c.Resource) &&
					(c.Verb == "create" || c.Verb == "patch" || c.Verb == "update") {
					evidence = append(evidence, fmt.Sprintf(
						"SSAR: %s %s in %q = allowed", c.Verb, c.Resource, c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			for _, crd := range r.ClusterObjects.CRDs {
				if fluxGroups[crd.Group] {
					nodes = append(nodes, "crd:"+crd.Group+"/"+crd.Resource)
				}
			}
			desc := "The current identity can create or patch Flux Kustomization or HelmRelease resources AND Flux CRDs are present. " +
				"An attacker can redirect a Kustomization to a malicious GitRepository or alter a HelmRelease to deploy arbitrary charts, " +
				"achieving code execution across all reconciled namespaces."
			return desc, evidence, nodes
		},
	}
}

func ruleExternalSecretsAbuse() inferenceRule {
	return inferenceRule{
		RuleID:   "LATERAL-EXTERNAL-SECRETS",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Can create ExternalSecrets/SecretStore — cross-namespace secret exfiltration via ESO",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Restrict create/patch on externalsecrets.external-secrets.io to dedicated ESO management accounts.
• Apply namespace-scoped SecretStore policies; avoid ClusterSecretStore unless strictly necessary.
• Enable ESO audit logging and alert on new ExternalSecret or SecretStore creation.
• Use OPA/Gatekeeper to enforce allowed secret backend paths and key patterns.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			esoResources := []string{"externalsecrets", "secretstores", "clustersecretstores"}
			hasESO := false
			for _, crd := range r.ClusterObjects.CRDs {
				if crd.Group == "external-secrets.io" {
					hasESO = true
					break
				}
			}
			if !hasESO {
				return "", nil, nil
			}
			var evidence []string
			var nodes []string
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					if containsAny(rule.Resources, append(esoResources, "*")...) &&
						containsAny(rule.Verbs, "create", "patch", "update", "*") {
						evidence = append(evidence, fmt.Sprintf(
							"SSRR: create/patch ESO CRs in %q", ns))
					}
				}
			}
			for _, c := range r.Permissions.SSARChecks {
				if c.Allowed && containsAny(esoResources, c.Resource) &&
					(c.Verb == "create" || c.Verb == "patch" || c.Verb == "update") {
					evidence = append(evidence, fmt.Sprintf(
						"SSAR: %s %s in %q = allowed", c.Verb, c.Resource, c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			for _, crd := range r.ClusterObjects.CRDs {
				if crd.Group == "external-secrets.io" {
					nodes = append(nodes, "crd:"+crd.Group+"/"+crd.Resource)
				}
			}
			desc := "The current identity can create ExternalSecret or SecretStore resources AND External Secrets Operator CRDs are present. " +
				"An attacker can create an ExternalSecret pointing to a high-privilege secret backend path, " +
				"causing ESO to pull and sync secrets from AWS Secrets Manager, Vault, or GCP into cluster Secrets."
			return desc, evidence, nodes
		},
	}
}

func ruleVaultOperatorAbuse() inferenceRule {
	return inferenceRule{
		RuleID:   "LATERAL-VAULT-OPERATOR",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Can create VaultStaticSecret — Vault secret exfiltration via Vault Secrets Operator",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• Restrict create/patch on vaultstaticsecrets.secrets.hashicorp.com to Vault operator management accounts.
• Apply Vault ACL policies to limit which paths the operator's Vault role can read.
• Enable audit logging for VaultStaticSecret creation events.
• Use namespace-scoped VaultAuth references to prevent cross-namespace secret access.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			vaultResources := []string{"vaultstaticsecrets", "vaultdynamicsecrets"}
			hasVault := false
			for _, crd := range r.ClusterObjects.CRDs {
				if crd.Group == "secrets.hashicorp.com" {
					hasVault = true
					break
				}
			}
			if !hasVault {
				return "", nil, nil
			}
			var evidence []string
			var nodes []string
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					if containsAny(rule.Resources, append(vaultResources, "*")...) &&
						containsAny(rule.Verbs, "create", "patch", "update", "*") {
						evidence = append(evidence, fmt.Sprintf(
							"SSRR: create/patch Vault Operator CRs in %q", ns))
					}
				}
			}
			for _, c := range r.Permissions.SSARChecks {
				if c.Allowed && containsAny(vaultResources, c.Resource) &&
					(c.Verb == "create" || c.Verb == "patch" || c.Verb == "update") {
					evidence = append(evidence, fmt.Sprintf(
						"SSAR: %s %s in %q = allowed", c.Verb, c.Resource, c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			for _, crd := range r.ClusterObjects.CRDs {
				if crd.Group == "secrets.hashicorp.com" {
					nodes = append(nodes, "crd:"+crd.Group+"/"+crd.Resource)
				}
			}
			desc := "The current identity can create VaultStaticSecret or VaultDynamicSecret resources AND Vault Secrets Operator CRDs are present. " +
				"An attacker can create a VaultStaticSecret referencing any Vault path accessible to the operator, " +
				"causing the operator to sync that path into a cluster Secret."
			return desc, evidence, nodes
		},
	}
}

func ruleWebhookIgnorePolicy() inferenceRule {
	return inferenceRule{
		RuleID:   "BYPASS-WEBHOOK-IGNORE-POLICY",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Mutating webhook with FailurePolicy=Ignore — security controls may be bypassed on outage",
		MITREIDs: []string{"T1562.001"},
		Mitigation: `• Set FailurePolicy=Fail on all security-critical webhooks (OPA, Kyverno, image admission).
• Accept that Fail policy means webhook outages block deployments — plan for availability accordingly.
• Use redundant webhook replicas (minReplicas≥2, PodDisruptionBudget) to reduce outage risk.
• Alert when webhook endpoints become unavailable (Prometheus probe or synthetic check).`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wh := range r.ClusterObjects.Webhooks {
				if wh.Kind == "Mutating" && wh.FailurePolicy == "Ignore" {
					evidence = append(evidence, fmt.Sprintf(
						"MutatingWebhookConfiguration %q: FailurePolicy=Ignore", wh.Name))
					nodes = append(nodes, "webhook:"+wh.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("%d mutating webhook(s) use FailurePolicy=Ignore. "+
				"If the webhook endpoint is unavailable (crash, network partition, cert expiry), "+
				"the admission controller is silently bypassed — allowing policy violations, "+
				"image pulls without scanning, or privilege escalation to pass undetected.", len(evidence))
			return desc, evidence, nodes
		},
	}
}

func ruleWebhookNamespaceGap() inferenceRule {
	return inferenceRule{
		RuleID:   "BYPASS-WEBHOOK-NAMESPACE-GAP",
		Severity: SeverityMedium,
		Score:    6.0,
		Title:    "Webhook with NamespaceSelector — some namespaces may be excluded from policy enforcement",
		MITREIDs: []string{"T1562.001"},
		Mitigation: `• Review NamespaceSelector logic to ensure security-critical namespaces are not excluded.
• Use negated selectors (matchExpressions with NotIn) carefully — they can create unintended gaps.
• Enumerate all namespaces not covered by each webhook and assess residual risk.
• Consider deploying per-namespace webhooks in addition to cluster-scoped ones for defense-in-depth.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wh := range r.ClusterObjects.Webhooks {
				if wh.HasNamespaceSelector {
					evidence = append(evidence, fmt.Sprintf(
						"%s webhook %q has NamespaceSelector — coverage may not include all namespaces",
						wh.Kind, wh.Name))
					nodes = append(nodes, "webhook:"+wh.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("%d webhook(s) use NamespaceSelector, meaning certain namespaces "+
				"may not be covered by admission policy. An attacker who can create or control "+
				"a namespace that is excluded from webhook enforcement can bypass security controls "+
				"(image scanning, mutation injection, policy validation).", len(evidence))
			return desc, evidence, nodes
		},
	}
}

func ruleWebhookBackendTakeover() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-WEBHOOK-BACKEND-TAKEOVER",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Webhook backend workload is reachable — compromising it controls admission mutations",
		MITREIDs: []string{"T1610", "T1525"},
		Mitigation: `• Run webhook backend workloads with minimal RBAC — they should only need TLS secrets.
• Isolate webhook backend pods in a dedicated namespace with NetworkPolicy restricting ingress.
• Ensure webhook pods run with read-only root filesystem and no privileged capabilities.
• Use separate ServiceAccounts for webhook backends with no additional RBAC bindings.
• Monitor webhook backend pod image digests and alert on unexpected changes.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wh := range r.ClusterObjects.Webhooks {
				if wh.Kind != "Mutating" || !wh.InterceptsPods {
					continue
				}
				if wh.ServiceName == "" || wh.ServiceNS == "" {
					continue
				}
				for _, wl := range r.ClusterObjects.Workloads {
					if wl.Namespace != wh.ServiceNS {
						continue
					}
					if wl.Name == wh.ServiceName || strings.HasPrefix(wl.Name, wh.ServiceName+"-") {
						evidence = append(evidence, fmt.Sprintf(
							"webhook %q backend: workload %s/%s (Service %s/%s)",
							wh.Name, wl.Namespace, wl.Name, wh.ServiceNS, wh.ServiceName))
						nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
						nodes = append(nodes, "webhook:"+wh.Name)
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("%d mutating webhook backend workload(s) identified. "+
				"If an attacker can compromise the backend workload (via exec, SA token theft, "+
				"or workload mutation), they control what mutations the webhook applies to all "+
				"future pod creations. This enables SA replacement, sidecar injection, "+
				"security context modification, and environment variable exfiltration in new workloads.", len(evidence))
			return desc, evidence, nodes
		},
	}
}
