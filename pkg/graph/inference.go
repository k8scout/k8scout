package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)

// Severity levels for risk findings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// RiskFinding represents a single identified risk, with evidence and mitigation.
type RiskFinding struct {
	ID            string   `json:"id"`
	RuleID        string   `json:"rule_id"`
	Severity      Severity `json:"severity"`
	Score         float64  `json:"score"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Evidence      []string `json:"evidence,omitempty"`
	Mitigation    string   `json:"mitigation"`
	AffectedNodes []string `json:"affected_nodes,omitempty"`
	// MITREIDs maps this finding to MITRE ATT&CK for Containers technique IDs.
	MITREIDs []string `json:"mitre_ids,omitempty"`
}

// inferenceRule defines a single detection rule applied to the graph + raw data.
type inferenceRule struct {
	RuleID     string
	Severity   Severity
	Score      float64
	Title      string
	Mitigation string
	// MITREIDs maps this rule to MITRE ATT&CK for Containers technique IDs.
	MITREIDs []string
	// check returns (description, evidence, affectedNodeIDs) or ("", nil, nil) if rule doesn't fire.
	check func(g *Graph, result *kube.EnumerationResult) (desc string, evidence []string, nodes []string)
}

// Infer runs all inference rules against the graph and returns risk findings.
// It also emits inferred edges back into the graph for recursive enrichment.
func Infer(g *Graph, result *kube.EnumerationResult, log *zap.Logger) []RiskFinding {
	rules := allRules()
	var findings []RiskFinding

	for i, rule := range rules {
		desc, evidence, nodes := rule.check(g, result)
		if desc == "" {
			continue
		}
		f := RiskFinding{
			ID:            fmt.Sprintf("finding-%03d", i+1),
			RuleID:        rule.RuleID,
			Severity:      rule.Severity,
			Score:         rule.Score,
			Title:         rule.Title,
			Description:   desc,
			Evidence:      evidence,
			Mitigation:    rule.Mitigation,
			AffectedNodes: nodes,
			MITREIDs:      rule.MITREIDs,
		}
		findings = append(findings, f)
		log.Info("risk finding",
			zap.String("rule", rule.RuleID),
			zap.String("severity", string(rule.Severity)),
			zap.Float64("score", rule.Score))
	}

	// Emit inferred edges from inference results.
	emitInferredEdges(g, result)

	return findings
}

// ── Rule definitions ──────────────────────────────────────────────────────────

func allRules() []inferenceRule {
	return []inferenceRule{
		ruleListSecrets(),
		ruleGetSecrets(),
		ruleCreateRoleBindings(),
		ruleCreateClusterRoleBindings(),
		rulePatchDeployments(),
		rulePatchDaemonSets(),
		ruleCreatePods(),
		ruleExecPods(),
		ruleImpersonate(),
		ruleCreatePodPortforward(),
		rulePrivilegedContainers(),
		ruleHostPathMounts(),
		ruleHostPIDorNetwork(),
		ruleCreateSAToken(),
		ruleWildcardVerbs(),
		ruleClusterAdminBinding(),
		rulePatchClusterRoles(),
		ruleSecretsInEnv(),
		ruleAutomountSAToken(),
		ruleEscalateBind(),
		ruleCapturedSecrets(),
		ruleSensitiveConfigMaps(),
		// New rules.
		ruleCloudIRSAEscalation(),
		ruleHelmReleaseSecrets(),
		ruleMutatingWebhookPrivesc(),
		ruleProjectedTokenAudience(),
		ruleNodeCompromise(),
		// New detection rules (batch 2).
		ruleNodeProxy(),
		rulePatchSecrets(),
		ruleDangerousCapabilities(),
		ruleLateralExecSecretMount(),
		ruleCreateDaemonsets(),
		ruleHostIPC(),
		rulePatchServiceAccounts(),
		ruleWatchSecrets(),
		rulePatchNodes(),
		rulePatchStatefulSets(),
		// Feature additions.
		rulePlaintextEnvSecret(),
		ruleArgoCDOperatorAbuse(),
		ruleFluxOperatorAbuse(),
		ruleExternalSecretsAbuse(),
		ruleVaultOperatorAbuse(),
		ruleWebhookIgnorePolicy(),
		ruleWebhookNamespaceGap(),
	}
}

// ── Individual rules ──────────────────────────────────────────────────────────

func ruleListSecrets() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIV-LIST-SECRETS",
		Severity: SeverityHigh,
		Score:    7.5,
		Title:    "Identity can list Secrets",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• Restrict Secret RBAC to specific resourceNames (least-privilege per SA).
• Migrate credentials to an external secret store (HashiCorp Vault, AWS Secrets Manager, ESO).
• Enable Kubernetes audit logging for secret access and alert on anomalies.
• Apply NetworkPolicies to limit which pods can reach the API server.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var affectedNodes []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "secrets" && c.Verb == "list" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: list secrets in namespace %q = allowed", c.Namespace))
					affectedNodes = append(affectedNodes, "resource:"+c.Namespace+":secrets")
				}
			}
			if len(evidence) == 0 {
				// Check SSRR as fallback.
				for ns, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "secrets", "*") && containsAny(rule.Verbs, "list", "*") {
							evidence = append(evidence, fmt.Sprintf("SSRR: list secrets in namespace %q", ns))
							affectedNodes = append(affectedNodes, "resource:"+ns+":secrets")
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := fmt.Sprintf("The current identity can list Secrets in %d namespace(s). "+
				"Any actor with this token can retrieve plaintext secret values directly via the Kubernetes API.", len(evidence))
			return desc, evidence, affectedNodes
		},
	}
}

func ruleGetSecrets() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIV-GET-SECRETS",
		Severity: SeverityCritical,
		Score:    9.0,
		Title:    "Identity can get/read Secret values",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• This is the highest-risk secret permission. Immediately audit who holds this binding.
• Remove direct secret get access; use projected service account tokens instead.
• Consider envelope encryption of etcd and rotation of any exposed secrets.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "secrets" && c.Verb == "get" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: get secrets in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can read individual Secret objects. " +
				"This allows retrieval of raw token, password, and certificate values.", evidence, nil
		},
	}
}

func ruleCreateRoleBindings() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-CREATE-ROLEBINDING",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Identity can create RoleBindings → privilege escalation path",
		MITREIDs: []string{"T1078.001"},
		Mitigation: `• Remove create/update on rolebindings unless strictly required.
• Apply escalate/bind restrictions (RBAC escalation prevention is built-in since k8s 1.12,
  but verify the identity does not already hold the target role).
• Alert on RoleBinding creation events via audit logs.
• Use OPA/Gatekeeper to restrict binding to pre-approved roles only.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "rolebindings" && c.Verb == "create" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: create rolebindings in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := "The current identity can create RoleBindings. An actor could bind a high-privilege " +
				"ClusterRole (e.g., cluster-admin) to an identity they control within any accessible namespace, " +
				"resulting in effective privilege escalation. (Note: k8s escalation prevention blocks binding " +
				"roles the creator doesn't already hold — verify this control is active.)"
			return desc, evidence, nil
		},
	}
}

func ruleCreateClusterRoleBindings() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-CREATE-CLUSTERROLEBINDING",
		Severity: SeverityCritical,
		Score:    10.0,
		Title:    "Identity can create ClusterRoleBindings → cluster-wide privilege escalation",
		MITREIDs: []string{"T1078.001"},
		Mitigation: `• This permission effectively grants cluster-admin to the holder.
• Restrict create/patch on clusterrolebindings to break-glass accounts only.
• Enforce MPA (Multi-Party Authorization) for CRB changes in production.
• Use audit policy to alert immediately on ClusterRoleBinding create/update events.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "clusterrolebindings" && c.Verb == "create" && c.Allowed {
					evidence = append(evidence, "SSAR: create clusterrolebindings (cluster-wide) = allowed")
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := "The current identity can create ClusterRoleBindings across the entire cluster. " +
				"This is the most dangerous RBAC permission: it enables cluster-wide privilege escalation " +
				"to any existing ClusterRole, including cluster-admin."
			return desc, evidence, nil
		},
	}
}

func rulePatchDeployments() inferenceRule {
	return inferenceRule{
		RuleID:   "TAKEOVER-PATCH-DEPLOYMENT",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Identity can patch Deployments → workload takeover / SA impersonation",
		MITREIDs: []string{"T1610"},
		Mitigation: `• Limit patch/update on deployments to CI/CD service accounts with narrow scope.
• Use admission controllers (OPA/Gatekeeper, Kyverno) to validate pod spec changes.
• Require image digest pinning to prevent image substitution.
• Alert on deployment spec changes outside of approved deployment pipelines.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var affectedNodes []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "deployments" && c.Verb == "patch" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: patch deployments in %q = allowed", c.Namespace))
					// Find workloads in this namespace that use sensitive SAs.
					for _, wl := range r.ClusterObjects.Workloads {
						if wl.Namespace == c.Namespace && wl.Kind == "Deployment" {
							affectedNodes = append(affectedNodes, "workload:"+wl.Namespace+":"+wl.Name)
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := "The current identity can patch Deployment objects. An actor can modify the pod template " +
				"to inject a privileged container, change the service account, or replace the image — " +
				"effectively assuming the identity of any service account bound to those deployments."
			return desc, evidence, affectedNodes
		},
	}
}

func rulePatchDaemonSets() inferenceRule {
	return inferenceRule{
		RuleID:   "TAKEOVER-PATCH-DAEMONSET",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Identity can patch DaemonSets → node-level code execution risk",
		MITREIDs: []string{"T1610"},
		Mitigation: `• DaemonSets run on every node — patching them is higher-risk than patching Deployments.
• Strictly limit who can modify DaemonSets; prefer dedicated CD accounts.
• Use Pod Security Admission to enforce baseline/restricted profiles on DaemonSet pods.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "daemonsets" && c.Verb == "patch" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: patch daemonsets in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "Patching a DaemonSet causes the new pod spec to roll out to every node in the cluster. " +
				"This is effectively node-level code execution at scale.", evidence, nil
		},
	}
}

func ruleCreatePods() inferenceRule {
	return inferenceRule{
		RuleID:   "ESCAPE-CREATE-POD",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Identity can create Pods → potential node escape vector",
		MITREIDs: []string{"T1610"},
		Mitigation: `• Enforce Pod Security Admission at 'restricted' level on all namespaces.
• Use OPA/Gatekeeper constraints to block hostPID, hostNetwork, privileged containers.
• Restrict which service accounts can create pods via RBAC + admission webhooks.
• Apply LimitRange and ResourceQuota to limit pod specifications.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "pods" && c.Verb == "create" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: create pods in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			desc := "The current identity can create Pods. Depending on Pod Security Admission policies, " +
				"an actor may be able to schedule pods with hostPID=true, hostNetwork=true, or privileged " +
				"containers, enabling container breakout to the host node."
			return desc, evidence, nil
		},
	}
}

func ruleExecPods() inferenceRule {
	return inferenceRule{
		RuleID:   "RUNTIME-EXEC-PODS",
		Severity: SeverityHigh,
		Score:    7.8,
		Title:    "Identity can exec into Pods → runtime access to running workloads",
		MITREIDs: []string{"T1609"},
		Mitigation: `• Remove pods/exec from all non-debugging service accounts.
• Use ephemeral debug containers as an alternative with time-limited RBAC.
• Enable audit logging for exec events and alert on production pod exec.
• Consider Falco rules to detect interactive shell spawning inside containers.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "pods" && c.Subresource == "exec" && c.Verb == "create" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: create pods/exec in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can exec into running pods. This provides direct shell access " +
				"to container filesystems, environment variables, and mounted secrets.", evidence, nil
		},
	}
}

func ruleImpersonate() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-IMPERSONATE",
		Severity: SeverityCritical,
		Score:    9.8,
		Title:    "Identity can impersonate Users/ServiceAccounts → full identity takeover",
		MITREIDs: []string{"T1550"},
		Mitigation: `• Impersonation is essentially privilege escalation to any identity.
• This permission must be restricted to extremely limited infrastructure components (e.g., aggregation layer).
• Audit and alert on all impersonation events (verb=impersonate in audit log).
• Remove impersonation from all non-system service accounts immediately.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Verb == "impersonate" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: impersonate %q = allowed", c.Resource))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can impersonate other users or service accounts. " +
				"This grants the ability to act as any identity in the cluster, including cluster-admin.", evidence, nil
		},
	}
}

func ruleCreatePodPortforward() inferenceRule {
	return inferenceRule{
		RuleID:   "RUNTIME-PORTFORWARD",
		Severity: SeverityMedium,
		Score:    5.5,
		Title:    "Identity can port-forward to Pods → lateral movement to internal services",
		Mitigation: `• Remove pods/portforward for non-developer service accounts.
• Use NetworkPolicies to restrict intra-cluster communication.
• Alert on portforward events in audit logs — they are rarely legitimate in production.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "pods" && c.Subresource == "portforward" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: create pods/portforward in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "Port-forwarding enables direct TCP tunneling to pod ports, bypassing NetworkPolicies " +
				"and allowing access to internal services (databases, management APIs) not exposed externally.", evidence, nil
		},
	}
}

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

func ruleCreateSAToken() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-CREATE-SA-TOKEN",
		Severity: SeverityCritical,
		Score:    9.0,
		Title:    "Identity can create ServiceAccount tokens → long-lived credential generation",
		Mitigation: `• Remove serviceaccounts/token create permission from non-administrative accounts.
• Audit all existing long-lived tokens (kubectl get secrets --field-selector=type=kubernetes.io/service-account-token).
• Migrate to projected service account tokens (bound tokens with short TTL).
• Enable BoundServiceAccountTokenVolume feature (default on k8s 1.22+).`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "serviceaccounts" && c.Subresource == "token" && c.Verb == "create" && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: create serviceaccounts/token in %q = allowed", c.Namespace))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can create ServiceAccount tokens for any SA it can access. " +
				"This enables generation of long-lived credentials impersonating any service account.", evidence, nil
		},
	}
}

func ruleWildcardVerbs() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-WILDCARD-VERBS",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Wildcard verb or resource grants detected in RBAC rules",
		Mitigation: `• Replace '*' verbs/resources with explicit lists following least-privilege.
• Audit each ClusterRole/Role with wildcards and replace with minimal permission sets.
• Use 'kubectl auth reconcile' to diff and apply minimal RBAC manifests.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			checkRoles := func(roles []kube.RoleInfo, prefix string) {
				for _, role := range roles {
					for _, rule := range role.Rules {
						if containsAny(rule.Verbs, "*") || containsAny(rule.Resources, "*") {
							evidence = append(evidence, fmt.Sprintf("Role %s/%s has wildcard: verbs=%v resources=%v",
								role.Namespace, role.Name, rule.Verbs, rule.Resources))
							nodes = append(nodes, prefix+role.Namespace+":"+role.Name)
						}
					}
				}
			}
			checkRoles(r.ClusterObjects.Roles, "role:")
			checkRoles(r.ClusterObjects.ClusterRoles, "clusterrole::")
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d RBAC role(s) contain wildcard verb or resource grants. "+
				"These are difficult to audit and often grant unintended permissions.", len(evidence)), evidence, nodes
		},
	}
}

func ruleClusterAdminBinding() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-CLUSTER-ADMIN-BINDING",
		Severity: SeverityCritical,
		Score:    10.0,
		Title:    "Non-system identity bound to cluster-admin ClusterRole",
		Mitigation: `• Immediately review and remove non-emergency cluster-admin bindings.
• Use namespace-scoped admin roles instead of cluster-admin wherever possible.
• Implement MPA or GitOps approval workflows for cluster-admin binding changes.
• Enable audit alerting on any cluster-admin role use.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, crb := range r.ClusterObjects.ClusterRoleBindings {
				if crb.RoleRef.Name == "cluster-admin" {
					for _, subj := range crb.Subjects {
						if subj.Kind == "ServiceAccount" || (subj.Kind == "User" && !strings.HasPrefix(subj.Name, "system:")) {
							evidence = append(evidence, fmt.Sprintf("CRB %q binds %s %q to cluster-admin",
								crb.Name, subj.Kind, subj.Name))
							nodes = append(nodes, subjectNodeID(subj))
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "Non-system identities are directly bound to the cluster-admin ClusterRole. " +
				"These identities have unrestricted access to all cluster resources.", evidence, nodes
		},
	}
}

func rulePatchClusterRoles() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-PATCH-CLUSTERROLES",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Identity can patch ClusterRoles → permission escalation via role modification",
		Mitigation: `• Patching ClusterRoles is equivalent to granting arbitrary permissions to oneself.
• Restrict patch/update on clusterroles to platform team break-glass accounts only.
• GitOps all RBAC definitions and reject out-of-band changes via admission webhook.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "clusterroles" && c.Verb == "patch" && c.Allowed {
					evidence = append(evidence, "SSAR: patch clusterroles = allowed")
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can modify ClusterRole definitions. An actor can add " +
				"arbitrary rules to any existing ClusterRole, immediately gaining those permissions " +
				"(since the escalation prevention only checks at binding time, not rule modification).", evidence, nil
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

func ruleEscalateBind() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-ESCALATE-BIND",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Identity has escalate/bind on ClusterRoles → can create arbitrary ClusterRoleBindings",
		Mitigation: `• The escalate verb allows creating/updating roles with permissions the actor doesn't hold.
• The bind verb allows creating bindings for roles the actor doesn't hold.
• Combined, these effectively grant the ability to self-bind to cluster-admin.
• Remove escalate/bind from all non-platform-team accounts immediately.
• Alert on any escalate/bind usage in audit logs.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			hasEscalate, hasBind := false, false
			for _, c := range r.Permissions.SSARChecks {
				if !c.Allowed {
					continue
				}
				if c.Verb == "escalate" && c.Resource == "clusterroles" {
					hasEscalate = true
					evidence = append(evidence, "SSAR: escalate clusterroles = allowed (can modify role rules beyond own permissions)")
				}
				if c.Verb == "bind" && (c.Resource == "clusterroles" || c.Resource == "clusterrolebindings") {
					hasBind = true
					evidence = append(evidence, fmt.Sprintf("SSAR: bind %s = allowed (can create bindings for roles not held)", c.Resource))
				}
			}
			// Also check SSRR as fallback.
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					if containsAny(rule.Resources, "clusterroles", "*") {
						if containsAny(rule.Verbs, "escalate") {
							hasEscalate = true
							evidence = append(evidence, fmt.Sprintf("SSRR: escalate clusterroles in %q", ns))
						}
						if containsAny(rule.Verbs, "bind") {
							hasBind = true
							evidence = append(evidence, fmt.Sprintf("SSRR: bind clusterroles in %q", ns))
						}
					}
				}
			}
			if !hasEscalate && !hasBind {
				return "", nil, nil
			}
			verbs := []string{}
			if hasEscalate {
				verbs = append(verbs, "escalate")
			}
			if hasBind {
				verbs = append(verbs, "bind")
			}
			desc := fmt.Sprintf("The current identity has [%s] permission on ClusterRoles. "+
				"This allows creating ClusterRoleBindings for roles it does not possess, "+
				"enabling self-binding to cluster-admin or any other ClusterRole. "+
				"Attack: kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=<ns>:<sa>",
				strings.Join(verbs, "+"))
			return desc, evidence, []string{"clusterrole:cluster-admin"}
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

// ── New rules (Phase 2 additions) ─────────────────────────────────────────────

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

// ── New detection rules (batch 2) ─────────────────────────────────────────────

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

// ── Feature additions (env secrets, operator abuse, webhook bypass) ────────────

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

// ── Inferred edges (Pass 5) ────────────────────────────────────────────────────

// emitInferredEdges adds inferred edges to the graph based on observed permissions.
func emitInferredEdges(g *Graph, r *kube.EnumerationResult) {
	identityID := "identity:" + r.Identity.Username

	for _, c := range r.Permissions.SSARChecks {
		if !c.Allowed {
			continue
		}
		switch {
		case c.Resource == "deployments" && c.Verb == "patch":
			// patch deployment → can assume SA of workloads in that namespace
			for _, wl := range r.ClusterObjects.Workloads {
				if wl.Namespace == c.Namespace && wl.ServiceAccount != "" {
					saID := "sa:" + wl.Namespace + ":" + wl.ServiceAccount
					g.Edges = append(g.Edges, Edge{
						From:     identityID,
						To:       saID,
						Kind:     EdgeInferred,
						Reason:   fmt.Sprintf("inferred: patch deployment %s → runs-as SA %s", wl.Name, wl.ServiceAccount),
						Inferred: true,
					})
				}
			}

		case c.Resource == "pods" && c.Verb == "create":
			// create pods → inferred node access (risk note only)
			for _, node := range r.ClusterObjects.Nodes {
				nodeID := "node:" + node.Name
				g.Edges = append(g.Edges, Edge{
					From:     identityID,
					To:       nodeID,
					Kind:     EdgeInferred,
					Reason:   "inferred: create pod capability may allow scheduling on node (subject to PSA/taints)",
					Inferred: true,
				})
			}

		case (c.Resource == "rolebindings" || c.Resource == "clusterrolebindings") && c.Verb == "create":
			// create bindings → inferred escalation to cluster-admin
			g.Edges = append(g.Edges, Edge{
				From:     identityID,
				To:       "clusterrole:cluster-admin",
				Kind:     EdgeInferred,
				Reason:   "inferred: create " + c.Resource + " → potential escalation to cluster-admin (subject to escalation prevention)",
				Inferred: true,
			})

		case c.Resource == "clusterroles" && (c.Verb == "escalate" || c.Verb == "bind"):
			// escalate/bind on clusterroles → inferred self-escalation to cluster-admin
			g.Edges = append(g.Edges, Edge{
				From:     identityID,
				To:       "clusterrole:cluster-admin",
				Kind:     EdgeInferred,
				Reason:   fmt.Sprintf("inferred: %s clusterroles → can bind self to cluster-admin", c.Verb),
				Inferred: true,
			})
		}
	}
}

// ── Reviewer-mode inference ───────────────────────────────────────────────────

// dangerousPerm describes a verb+resource combination that is high-risk for any SA that holds it.
type dangerousPerm struct {
	verb, resource string
	ruleID         string
	title          string
	severity       Severity
	score          float64
	desc           string
	mitigation     string
}

var reviewerDangerousPerms = []dangerousPerm{
	{
		"create", "clusterrolebindings",
		"REVIEW-SA-PRIVESC-CRB",
		"ServiceAccount can create ClusterRoleBindings — cluster-wide privilege escalation",
		SeverityCritical, 10.0,
		"can create ClusterRoleBindings, enabling binding to cluster-admin or any ClusterRole",
		"Remove create/patch on clusterrolebindings from this SA. Restrict to break-glass accounts only.",
	},
	{
		"create", "rolebindings",
		"REVIEW-SA-PRIVESC-RB",
		"ServiceAccount can create RoleBindings — namespace privilege escalation",
		SeverityCritical, 9.5,
		"can create RoleBindings, enabling namespace-scoped privilege escalation",
		"Restrict RoleBinding creation to dedicated CI/CD service accounts with audit alerting.",
	},
	{
		"impersonate", "users",
		"REVIEW-SA-IMPERSONATE",
		"ServiceAccount can impersonate users/SAs — identity takeover",
		SeverityCritical, 9.8,
		"has impersonate permission, allowing it to act as any other user or service account",
		"The impersonate verb should only be held by aggregated API server accounts. Remove immediately.",
	},
	{
		"patch", "clusterroles",
		"REVIEW-SA-PATCH-CR",
		"ServiceAccount can patch ClusterRoles — arbitrary permission escalation",
		SeverityCritical, 9.5,
		"can patch ClusterRole definitions, adding arbitrary rules to any existing cluster role",
		"Treat ClusterRole patch as equivalent to cluster-admin. Remove from non-platform-team accounts.",
	},
	{
		"create", "serviceaccounts/token",
		"REVIEW-SA-CREATE-TOKEN",
		"ServiceAccount can create SA tokens — long-lived credential generation",
		SeverityCritical, 9.0,
		"can generate ServiceAccount tokens for any SA, producing long-lived impersonation credentials",
		"Restrict serviceaccounts/token create to operator accounts. Prefer projected volumes.",
	},
	{
		"get", "secrets",
		"REVIEW-SA-GET-SECRETS",
		"ServiceAccount can get/read Secret values",
		SeverityCritical, 9.0,
		"can read raw Secret values (tokens, passwords, certificates) via GET",
		"Restrict secret get to specific resourceNames. Migrate to external secret stores.",
	},
	{
		"list", "secrets",
		"REVIEW-SA-LIST-SECRETS",
		"ServiceAccount can list Secrets",
		SeverityHigh, 7.5,
		"can enumerate all Secret names in accessible namespaces",
		"Restrict Secret list to specific resourceNames. Enable audit logging for list events.",
	},
	{
		"patch", "deployments",
		"REVIEW-SA-PATCH-DEPLOY",
		"ServiceAccount can patch Deployments — workload takeover / SA lateral movement",
		SeverityHigh, 8.0,
		"can patch Deployments, injecting containers, changing service accounts, or replacing images",
		"Limit deployment patch to dedicated CD service accounts. Use Kyverno/OPA for pod spec validation.",
	},
	{
		"patch", "daemonsets",
		"REVIEW-SA-PATCH-DS",
		"ServiceAccount can patch DaemonSets — node-level code execution",
		SeverityHigh, 8.5,
		"can patch DaemonSets; changes roll out to every node in the cluster simultaneously",
		"Strictly limit DaemonSet modifications. Apply Pod Security Admission baseline/restricted.",
	},
	{
		"create", "pods",
		"REVIEW-SA-CREATE-POD",
		"ServiceAccount can create Pods — potential node escape if PSA is permissive",
		SeverityHigh, 8.0,
		"can create Pods; with a permissive PSA profile this enables privileged pod / node escape",
		"Enforce Pod Security Admission at 'restricted' level. Block hostPID/hostNetwork via OPA.",
	},
	{
		"create", "pods/exec",
		"REVIEW-SA-EXEC-POD",
		"ServiceAccount can exec into Pods — direct container shell access",
		SeverityHigh, 7.8,
		"can exec into running containers, gaining direct shell access to workload environments",
		"Restrict pods/exec to break-glass accounts. Alert on exec events via audit policy.",
	},
	{
		"escalate", "clusterroles",
		"REVIEW-SA-ESCALATE-CLUSTERROLES",
		"ServiceAccount has escalate on ClusterRoles → can create rules beyond current permissions",
		SeverityCritical, 9.5,
		"has escalate permission on clusterroles, allowing creation/modification of roles with permissions it does not hold",
		"Remove escalate from all non-platform-team accounts. Alert on escalation events in audit logs.",
	},
	{
		"bind", "clusterroles",
		"REVIEW-SA-BIND-CLUSTERROLES",
		"ServiceAccount has bind on ClusterRoles → can create ClusterRoleBindings for any ClusterRole",
		SeverityCritical, 9.5,
		"has bind permission on clusterroles, allowing creation of ClusterRoleBindings for cluster-admin or any other ClusterRole",
		"Remove bind from all non-platform-team accounts. Combined with escalate this grants full cluster-admin.",
	},
}

// InferReviewer runs reviewer-mode risk analysis against all computed SA permissions
// and pod security issues. It supplements the standard Infer() cluster-object rules.
func InferReviewer(g *Graph, result *kube.ReviewerEnumerateResult, log *zap.Logger) []RiskFinding {
	var findings []RiskFinding
	idx := 1

	// ── Per-SA dangerous permission checks ────────────────────────────────────
	for _, ip := range result.AllIdentityPerms {
		// Skip node/kube-system component accounts to reduce noise.
		if strings.HasPrefix(ip.Subject, "system:node:") ||
			strings.HasPrefix(ip.Name, "kube-") && ip.Namespace == "kube-system" {
			continue
		}

		for _, dp := range reviewerDangerousPerms {
			if !ipHasPermission(ip, dp.verb, dp.resource) {
				continue
			}
			nodeID := reviewerFindingNodeID(ip)
			evidence := fmt.Sprintf("%s %s — bound via: %s",
				ip.Subject, dp.desc, strings.Join(ip.BoundRoles, ", "))
			findings = append(findings, RiskFinding{
				ID:       fmt.Sprintf("finding-%03d", idx),
				RuleID:   dp.ruleID,
				Severity: dp.severity,
				Score:    dp.score,
				Title:    fmt.Sprintf("[%s/%s] %s", ip.Namespace, ip.Name, dp.title),
				Description: fmt.Sprintf("ServiceAccount %q in namespace %q %s.",
					ip.Name, ip.Namespace, dp.desc),
				Evidence:      []string{evidence},
				Mitigation:    dp.mitigation,
				AffectedNodes: []string{nodeID},
			})
			idx++
			log.Info("reviewer finding",
				zap.String("subject", ip.Subject),
				zap.String("rule", dp.ruleID))
		}

		// Wildcard RBAC rule check.
		for _, rule := range ip.Rules {
			if containsAny(rule.Verbs, "*") || containsAny(rule.Resources, "*") {
				nodeID := reviewerFindingNodeID(ip)
				findings = append(findings, RiskFinding{
					ID:       fmt.Sprintf("finding-%03d", idx),
					RuleID:   "REVIEW-SA-WILDCARD",
					Severity: SeverityHigh,
					Score:    8.0,
					Title:    fmt.Sprintf("[%s/%s] Wildcard RBAC grant", ip.Namespace, ip.Name),
					Description: fmt.Sprintf("ServiceAccount %q in namespace %q has a wildcard RBAC rule "+
						"(verbs=%v, resources=%v). This grants broad and potentially unintended permissions.",
						ip.Name, ip.Namespace, rule.Verbs, rule.Resources),
					Evidence: []string{
						fmt.Sprintf("Rule: verbs=%v resources=%v apiGroups=%v", rule.Verbs, rule.Resources, rule.APIGroups),
						fmt.Sprintf("Bound via: %s", strings.Join(ip.BoundRoles, ", ")),
					},
					Mitigation:    "Replace wildcard grants with specific verb+resource combinations (least-privilege).",
					AffectedNodes: []string{nodeID},
				})
				idx++
				break // one wildcard finding per SA
			}
		}
	}

	// ── Pod security findings → risk findings ─────────────────────────────────
	for _, psf := range result.PodSecurityIssues {
		severity := SeverityMedium
		score := 5.0
		if psf.Severity == "HIGH" {
			severity = SeverityHigh
			score = 7.5
		}
		workloadNode := "workload:" + psf.Namespace + ":" + psf.WorkloadName
		findings = append(findings, RiskFinding{
			ID:       fmt.Sprintf("finding-%03d", idx),
			RuleID:   "REVIEW-POD-SECURITY",
			Severity: severity,
			Score:    score,
			Title: fmt.Sprintf("[%s/%s %s] Pod security misconfiguration",
				psf.Namespace, psf.WorkloadName, psf.WorkloadKind),
			Description: fmt.Sprintf("%s %q in namespace %q has %d security misconfiguration(s).",
				psf.WorkloadKind, psf.WorkloadName, psf.Namespace, len(psf.Issues)),
			Evidence:   psf.Issues,
			Mitigation: "Apply Pod Security Admission 'restricted' profile. Set securityContext.runAsNonRoot=true, " +
				"readOnlyRootFilesystem=true, drop all capabilities, disable hostPath/hostPID/hostNetwork/hostIPC.",
			AffectedNodes: []string{workloadNode},
		})
		idx++
	}

	// ── Standard cluster-object rules (privileged containers, wildcard roles, etc.) ──
	// These rules check ClusterObjects directly and don't depend on SSRR/SSAR,
	// so they work correctly in reviewer mode.
	standardFindings := Infer(g, result.EnumerationResult, log)
	for i := range standardFindings {
		standardFindings[i].ID = fmt.Sprintf("finding-%03d", idx)
		idx++
	}
	findings = append(findings, standardFindings...)

	log.Info("reviewer inference complete",
		zap.Int("total_findings", len(findings)))
	return findings
}

// ipHasPermission checks whether a computed IdentityPermissions grants verb on resource.
// Wildcard verbs ("*") and wildcard resources ("*") match anything.
func ipHasPermission(ip kube.IdentityPermissions, verb, resource string) bool {
	for _, rule := range ip.Rules {
		if containsAny(rule.Verbs, verb, "*") && containsAny(rule.Resources, resource, "*") {
			return true
		}
	}
	return false
}

// reviewerFindingNodeID returns the graph node ID for a computed identity's SA node.
func reviewerFindingNodeID(ip kube.IdentityPermissions) string {
	if ip.SubjectKind == "ServiceAccount" {
		return fmt.Sprintf("sa:%s:%s", ip.Namespace, ip.Name)
	}
	return "identity:" + ip.Name
}

// ── Utility ───────────────────────────────────────────────────────────────────

func containsAny(slice []string, vals ...string) bool {
	for _, s := range slice {
		for _, v := range vals {
			if s == v {
				return true
			}
		}
	}
	return false
}
