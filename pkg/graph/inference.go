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
	// AttackPath is the ordered sequence of graph steps for multi-hop findings.
	// Nil for single-step (non-traversal) findings.
	AttackPath []PathStep `json:"attack_path,omitempty"`
	// PathWeight is the cumulative attacker-effort weight of the attack path.
	// Lower weight = easier/more realistic path. Zero for non-traversal findings.
	PathWeight float64 `json:"path_weight,omitempty"`
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

	// Inferred edges are now emitted during Build (before the index is created),
	// so all traversable edges are already present in the graph.

	// Lateral movement: surface exec/portforward reachability from the current foothold.
	for j, lmf := range inferLateralMovementFindings(g, result, log) {
		lmf.ID = fmt.Sprintf("finding-lm-%03d", j+1)
		findings = append(findings, lmf)
	}

	// Multi-hop attack path analysis: one finding per discovered path.
	// Runs as a separate phase (not via allRules) because inferenceRule.check
	// produces exactly one finding per invocation, which cannot express
	// the one-finding-per-path requirement.
	for j, mhf := range inferMultiHopFindings(g, result, findings, log) {
		mhf.ID = fmt.Sprintf("finding-mh-%03d", j+1)
		findings = append(findings, mhf)
	}

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
		// Improvement batch.
		ruleNonResourceURLPrivesc(),
		ruleCRDPermissions(),
		ruleOrphanedSATokens(),
		ruleDanglingRoleBindings(),
		ruleKubeletExposed(),
		rulePriorityClassAbuse(),
		// Phase 1: NetworkPolicy + Service.
		ruleNoNetworkPolicyDefaultDeny(),
		ruleNetworkPolicyBypass(),
		ruleServiceExposure(),
		// Phase 2: Cloud metadata endpoints.
		ruleAWSIMDSv1Accessible(),
		ruleAWSIMDSv2Only(),
		ruleGKEMetadataReachable(),
		ruleAzureIMDSReachable(),
		ruleCloudRoleOverlyPermissive(),
		// Phase 3: PV + ImagePullSecret.
		ruleSharedPVCrossAccess(),
		ruleImagePullSecretExposure(),
		// Phase 5: Admission controller abuse.
		ruleWebhookBackendCompromise(),
		ruleWebhookPersistence(),
		ruleValidatingWebhookBypass(),
		// Cloud coverage improvements.
		ruleAWSAuthSystemMasters(),
		ruleAWSAuthWildcard(),
		ruleIRSACrossAccount(),
		ruleEKSPodIdentityDetected(),
		ruleAADPodIdentityLegacy(),
		ruleAzureKeyVaultCSI(),
		ruleAzureTenantMismatch(),
		ruleGKEAutopilotHardening(),
		ruleGKEConfigConnector(),
		ruleGKEMetadataConcealment(),
		ruleGCPSAKeysInSecrets(),
		ruleIRSATokenExpiration(),
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

			// isReadOnly returns true when path is in the read-only mount list.
			isReadOnly := func(path string, roPaths []string) bool {
				for _, ro := range roPaths {
					if ro == path {
						return true
					}
				}
				return false
			}

			check := func(paths []string, roPaths []string, label string) {
				for _, p := range paths {
					ro := isReadOnly(p, roPaths)
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
								if ro {
									// Read-only sensitive paths are informational, not escape vectors.
									tag = "INFO: sensitive host path (read-only)"
								} else {
									tag = "HIGH: sensitive host path (writable)"
								}
								break
							}
						}
					} else if ro {
						// Even critical socket paths are downgraded when read-only.
						tag = strings.Replace(tag, "CRITICAL", "HIGH (read-only)", 1)
					}
					if tag != "" {
						evidence = append(evidence, fmt.Sprintf("%s mounts %q [%s]", label, p, tag))
						if !seen[label] {
							seen[label] = true
							// Only add as affected node for writable or critical-even-if-RO paths.
							if !strings.Contains(tag, "INFO:") {
								nodes = append(nodes, label)
							}
						}
					}
				}
			}
			for _, wl := range r.ClusterObjects.Workloads {
				check(wl.HostPathMounts, wl.ReadOnlyHostPaths, "workload:"+wl.Namespace+":"+wl.Name)
			}
			for _, pod := range r.ClusterObjects.Pods {
				check(pod.HostPathMounts, pod.ReadOnlyHostPaths, "pod:"+pod.Namespace+":"+pod.Name)
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			writableCount := 0
			for _, ev := range evidence {
				if !strings.Contains(ev, "read-only") {
					writableCount++
				}
			}
			desc := fmt.Sprintf("%d hostPath volume issue(s) found (%d writable). "+
				"Writable mounts to sensitive host paths enable credential theft or container escape.",
				len(evidence), writableCount)
			return desc, evidence, nodes
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
			// sensitiveResources are the only ones where a wildcard verb or resource
			// grant is genuinely dangerous. Wildcards on events, endpoints, or namespaces
			// are noisy but not directly exploitable for privilege escalation.
			sensitiveResources := map[string]bool{
				"secrets": true, "pods": true, "deployments": true, "daemonsets": true,
				"statefulsets": true, "rolebindings": true, "clusterrolebindings": true,
				"clusterroles": true, "roles": true, "serviceaccounts": true,
				"nodes": true, "configmaps": true, "*": true,
			}
			var evidence []string
			var nodes []string
			checkRoles := func(roles []kube.RoleInfo, prefix string) {
				for _, role := range roles {
					for _, rule := range role.Rules {
						wildcardVerb := containsAny(rule.Verbs, "*")
						wildcardResource := containsAny(rule.Resources, "*")
						if !wildcardVerb && !wildcardResource {
							continue
						}
						// Only flag when a sensitive resource is in scope.
						affectsSensitive := wildcardResource // "*" resources = all resources
						if !affectsSensitive {
							for _, res := range rule.Resources {
								if sensitiveResources[res] {
									affectsSensitive = true
									break
								}
							}
						}
						if !affectsSensitive {
							continue
						}
						evidence = append(evidence, fmt.Sprintf("Role %s/%s has wildcard: verbs=%v resources=%v",
							role.Namespace, role.Name, rule.Verbs, rule.Resources))
						nodes = append(nodes, prefix+role.Namespace+":"+role.Name)
					}
				}
			}
			checkRoles(r.ClusterObjects.Roles, "role:")
			checkRoles(r.ClusterObjects.ClusterRoles, "clusterrole::")
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d RBAC role(s) contain wildcard grants on sensitive resources. "+
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
		RuleID:   "CLOUD-WORKLOAD-IDENTITY-ESCALATION",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "ServiceAccount with cloud IAM annotation (AWS IRSA / Azure WI / GCP WI) — cross-cloud escalation path",
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
			desc := fmt.Sprintf("%d ServiceAccount(s) carry cloud IAM role annotations (AWS IRSA / Azure Workload Identity / GCP Workload Identity). "+
				"Any workload running as these SAs can call cloud APIs (S3, IAM, KMS, Azure ARM, GCP APIs, etc.) "+
				"using the pod's projected service account token — no secrets required. "+
				"Compromising these pods enables cross-cloud privilege escalation. "+
				"NOTE: confidence is medium — the cloud-side trust policy must also allow the SA's OIDC sub-claim. "+
				"Validate IAM trust policies before treating as confirmed.", len(evidence))
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
			// capTierLabel maps tier strings to display labels with exploit context.
			capTierLabel := map[string]string{
				"CRITICAL": "CRITICAL — kernel/credential access (instant container escape)",
				"HIGH":     "HIGH — strong introspection or raw I/O",
				"MEDIUM":   "MEDIUM — network manipulation",
			}
			addCapEvidence := func(label string, details []kube.CapabilityDetail) {
				for _, cd := range details {
					tierLabel := capTierLabel[cd.Tier]
					if tierLabel == "" {
						tierLabel = cd.Tier
					}
					evidence = append(evidence, fmt.Sprintf("%s: container %q has %s [%s]",
						label, cd.Container, cd.Cap, tierLabel))
				}
			}
			for _, wl := range r.ClusterObjects.Workloads {
				if len(wl.CapabilityDetails) > 0 {
					addCapEvidence("Workload "+wl.Namespace+"/"+wl.Name, wl.CapabilityDetails)
					nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
				} else if len(wl.DangerousCapabilities) > 0 {
					// Fallback for data without granular details.
					evidence = append(evidence, fmt.Sprintf("Workload %s/%s has dangerous caps in containers: %v",
						wl.Namespace, wl.Name, wl.DangerousCapabilities))
					nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
				}
			}
			for _, pod := range r.ClusterObjects.Pods {
				if len(pod.CapabilityDetails) > 0 {
					addCapEvidence("Pod "+pod.Namespace+"/"+pod.Name, pod.CapabilityDetails)
					nodes = append(nodes, "pod:"+pod.Namespace+":"+pod.Name)
				} else if len(pod.DangerousCapabilities) > 0 {
					evidence = append(evidence, fmt.Sprintf("Pod %s/%s has dangerous caps in containers: %v",
						pod.Namespace, pod.Name, pod.DangerousCapabilities))
					nodes = append(nodes, "pod:"+pod.Namespace+":"+pod.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			// Escalate severity to CRITICAL if any CRITICAL-tier capability is present.
			// This is surfaced in the description so the caller can override the rule's static severity.
			hasCritical := false
			for _, wl := range r.ClusterObjects.Workloads {
				for _, cd := range wl.CapabilityDetails {
					if cd.Tier == "CRITICAL" {
						hasCritical = true
					}
				}
			}
			for _, pod := range r.ClusterObjects.Pods {
				for _, cd := range pod.CapabilityDetails {
					if cd.Tier == "CRITICAL" {
						hasCritical = true
					}
				}
			}
			severityNote := ""
			if hasCritical {
				severityNote = " At least one CRITICAL-tier capability (SYS_MODULE/SYS_ADMIN/DAC_READ_SEARCH) is present — treat as CRITICAL severity."
			}
			return fmt.Sprintf("%d workload(s)/pod(s) grant dangerous Linux capabilities. "+
				"These capabilities enable container escape, kernel module injection, and process introspection.%s",
				len(nodes), severityNote), evidence, nodes
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
	// Ensure clusterrole:cluster-admin exists as a traversal target.
	// The builder only adds nodes it can enumerate; if the identity lacks
	// list-clusterroles permission the node won't be present, but inferred
	// edges still target it and FindPaths requires the node to exist.
	const clusterAdminID = "clusterrole:cluster-admin"
	if g.nodeByID(clusterAdminID) == nil {
		g.Nodes = append(g.Nodes, Node{
			ID:   clusterAdminID,
			Kind: KindClusterRole,
			Name: "cluster-admin",
		})
	}

	identityID := "identity:" + r.Identity.Username

	// NOTE: Pod→SA and SA→identity bridges are now created by Build() in builder.go
	// using EdgeRunsAs (weight 0.1) — the realistic chain. The old EdgeInferred
	// shortcuts (weight 2.0) that bypassed intermediate nodes have been removed.
	//
	// Concrete identity → resource edges (patch workloads, get secrets,
	// impersonate SAs) are created by buildConcreteIdentityEdges in builder.go.
	//
	// Only true inferred escalations remain below: create bindings → cluster-admin,
	// escalate/bind → cluster-admin, create pods → node scheduling.
	for _, c := range r.Permissions.SSARChecks {
		if !c.Allowed {
			continue
		}
		switch {
		case c.Resource == "pods" && c.Verb == "create":
			// create pods → inferred node access (scheduling)
			for _, node := range r.ClusterObjects.Nodes {
				nodeID := "node:" + node.Name
				g.Edges = append(g.Edges, Edge{
					From:     identityID,
					To:       nodeID,
					Kind:     EdgeInferred,
					Reason:   "inferred: create pod → schedule on node (subject to PSA/taints)",
					Inferred: true,
				})
			}

		case (c.Resource == "rolebindings" || c.Resource == "clusterrolebindings") && c.Verb == "create":
			g.Edges = append(g.Edges, Edge{
				From:     identityID,
				To:       "clusterrole:cluster-admin",
				Kind:     EdgeInferred,
				Reason:   "inferred: create " + c.Resource + " → escalation to cluster-admin",
				Inferred: true,
			})

		case c.Resource == "clusterroles" && (c.Verb == "escalate" || c.Verb == "bind"):
			g.Edges = append(g.Edges, Edge{
				From:     identityID,
				To:       "clusterrole:cluster-admin",
				Kind:     EdgeInferred,
				Reason:   fmt.Sprintf("inferred: %s clusterroles → bind self to cluster-admin", c.Verb),
				Inferred: true,
			})
		}
	}
}

// ── SA usage index ────────────────────────────────────────────────────────────

// buildSAUsageIndex scans the graph for runs_as edges and returns a map from
// SA node ID to the list of workload/pod node IDs that run as that SA.
// Used to enrich reviewer findings with workload context and to distinguish
// "privilege in use" from "privilege with no execution foothold".
func buildSAUsageIndex(g *Graph) map[string][]string {
	idx := make(map[string][]string)
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Kind == EdgeRunsAs {
			idx[e.To] = append(idx[e.To], e.From)
		}
	}
	return idx
}

// buildWorkloadUsageEvidence returns human-readable evidence lines describing
// which workloads use a given SA, and whether any are privileged.
// If no workloads use the SA, returns a single line noting the lack of foothold.
func buildWorkloadUsageEvidence(g *Graph, workloadIDs []string) []string {
	if len(workloadIDs) == 0 {
		return []string{
			"No running pods or workloads use this ServiceAccount — " +
				"privilege exists but there is no direct execution foothold.",
		}
	}
	lines := make([]string, 0, len(workloadIDs)+1)
	lines = append(lines, fmt.Sprintf("Used by %d running workload/pod(s):", len(workloadIDs)))
	for _, wid := range workloadIDs {
		n := g.nodeByID(wid)
		if n == nil {
			continue
		}
		extra := ""
		if m := n.Metadata; m != nil {
			if m["privileged_containers"] != "" {
				extra += " [PRIVILEGED]"
			}
			if m["host_pid"] == "true" || m["host_network"] == "true" || m["host_ipc"] == "true" {
				extra += " [HOST-PID/NET/IPC]"
			}
		}
		lines = append(lines, fmt.Sprintf("  • %s (%s/%s)%s", wid, n.Namespace, n.Name, extra))
	}
	return lines
}

// isPrivilegedWorkload returns true if any workload in workloadIDs has privileged
// or host-namespace security properties.
func isPrivilegedWorkload(g *Graph, workloadIDs []string) bool {
	for _, wid := range workloadIDs {
		n := g.nodeByID(wid)
		if n == nil {
			continue
		}
		m := n.Metadata
		if m == nil {
			continue
		}
		if m["privileged_containers"] != "" || m["host_pid"] == "true" ||
			m["host_network"] == "true" || m["host_ipc"] == "true" {
			return true
		}
	}
	return false
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

	// Build SA → workload usage index so we can assess whether privileged SAs
	// are actually reachable via a running execution context.
	saUsage := buildSAUsageIndex(g)

	// ── Per-SA dangerous permission checks ────────────────────────────────────
	for _, ip := range result.AllIdentityPerms {
		// Skip node/kube-system component accounts to reduce noise.
		if strings.HasPrefix(ip.Subject, "system:node:") ||
			strings.HasPrefix(ip.Name, "kube-") && ip.Namespace == "kube-system" {
			continue
		}

		nodeID := reviewerFindingNodeID(ip)
		workloadIDs := saUsage[nodeID]
		workloadEvidence := buildWorkloadUsageEvidence(g, workloadIDs)
		hasWorkload := len(workloadIDs) > 0
		hasPrivilegedWorkload := isPrivilegedWorkload(g, workloadIDs)

		for _, dp := range reviewerDangerousPerms {
			if !ipHasPermission(ip, dp.verb, dp.resource) {
				continue
			}

			// Adjust score by execution-foothold reachability.
			// A highly privileged SA with no running workloads is a configuration risk
			// but not immediately exploitable — reduce its score to reflect that.
			// A SA used by a privileged workload has an amplified real-world impact.
			score := dp.score
			if !hasWorkload {
				score -= 1.5 // privilege without a foothold — lower exploitability
				if score < 1.0 {
					score = 1.0
				}
			} else if hasPrivilegedWorkload {
				score += 0.3 // privileged workload amplifies exploitability (cap at 10)
				if score > 10.0 {
					score = 10.0
				}
			}

			baseEvidence := fmt.Sprintf("%s %s — bound via: %s",
				ip.Subject, dp.desc, strings.Join(ip.BoundRoles, ", "))
			evidence := append([]string{baseEvidence}, workloadEvidence...)

			foothold := "no running workloads"
			if hasWorkload {
				foothold = fmt.Sprintf("%d running workload(s)", len(workloadIDs))
			}
			title := fmt.Sprintf("[%s/%s] %s", ip.Namespace, ip.Name, dp.title)
			if !hasWorkload {
				title += " (no active foothold)"
			}

			findings = append(findings, RiskFinding{
				ID:       fmt.Sprintf("finding-%03d", idx),
				RuleID:   dp.ruleID,
				Severity: severityFromScore(score),
				Score:    score,
				Title:    title,
				Description: fmt.Sprintf(
					"ServiceAccount %q in namespace %q %s. Foothold: %s.",
					ip.Name, ip.Namespace, dp.desc, foothold),
				Evidence:      evidence,
				Mitigation:    dp.mitigation,
				AffectedNodes: []string{nodeID},
			})
			idx++
			log.Info("reviewer finding",
				zap.String("subject", ip.Subject),
				zap.String("rule", dp.ruleID),
				zap.Bool("has_workload", hasWorkload),
				zap.Float64("score", score))
		}

		// Wildcard RBAC rule check.
		for _, rule := range ip.Rules {
			if containsAny(rule.Verbs, "*") || containsAny(rule.Resources, "*") {
				score := 8.0
				if !hasWorkload {
					score = 6.5
				}
				evidence := []string{
					fmt.Sprintf("Rule: verbs=%v resources=%v apiGroups=%v", rule.Verbs, rule.Resources, rule.APIGroups),
					fmt.Sprintf("Bound via: %s", strings.Join(ip.BoundRoles, ", ")),
				}
				evidence = append(evidence, workloadEvidence...)
				findings = append(findings, RiskFinding{
					ID:       fmt.Sprintf("finding-%03d", idx),
					RuleID:   "REVIEW-SA-WILDCARD",
					Severity: severityFromScore(score),
					Score:    score,
					Title:    fmt.Sprintf("[%s/%s] Wildcard RBAC grant", ip.Namespace, ip.Name),
					Description: fmt.Sprintf("ServiceAccount %q in namespace %q has a wildcard RBAC rule "+
						"(verbs=%v, resources=%v). This grants broad and potentially unintended permissions.",
						ip.Name, ip.Namespace, rule.Verbs, rule.Resources),
					Evidence:      evidence,
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

	// ── Reviewer multi-hop: workload-centric attack chains ────────────────────
	// Generates realistic paths from every pod/workload in the cluster to
	// high-value targets via the SA they run as. These show paths like:
	//   Pod → SA → ClusterRoleBinding → cluster-admin
	// rather than the reviewer's own identity's access.
	reviewerMHFindings := inferReviewerMultiHopFindings(g, result.EnumerationResult, findings, log)
	for i := range reviewerMHFindings {
		reviewerMHFindings[i].ID = fmt.Sprintf("finding-%03d", idx)
		idx++
	}
	findings = append(findings, reviewerMHFindings...)

	log.Info("reviewer inference complete",
		zap.Int("total_findings", len(findings)),
		zap.Int("reviewer_multihop", len(reviewerMHFindings)))
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

// ── Multi-hop attack path analysis ───────────────────────────────────────────
//
// This phase runs AFTER emitInferredEdges so that paths through inferred edges
// (e.g. identity → [inferred] → clusterrole:cluster-admin) are traversable.
// It cannot be expressed as an inferenceRule because that struct produces exactly
// one RiskFinding per check; multi-hop emits one finding per path.

// currentIdentityNodeID returns the graph node ID for the current identity.
// currentPodNodeID returns the graph node ID for the specific pod k8scout is
// currently running inside, or "" when not running in-cluster or pod name is unknown.
// This is the most concrete possible foothold — the exact execution context.
func currentPodNodeID(r *kube.EnumerationResult) string {
	if r.Identity.InCluster && r.Identity.PodName != "" && r.Identity.Namespace != "" {
		return "pod:" + r.Identity.Namespace + ":" + r.Identity.PodName
	}
	return ""
}

// goalKindMITRE maps a GoalKind to its relevant MITRE ATT&CK for Containers IDs.
func goalKindMITRE(kind GoalKind) []string {
	switch kind {
	case ClusterAdmin:
		return []string{"T1078.001"} // Valid Accounts: Local Accounts
	case NodeExec:
		return []string{"T1611"} // Escape to Host
	case SecretAccess:
		return []string{"T1552.007"} // Unsecured Credentials: Container API
	case IdentityTakeover:
		return []string{"T1078.004"} // Valid Accounts: Cloud Accounts
	case WorkloadTakeover:
		return []string{"T1610"} // Deploy Container
	case CloudEscalation:
		return []string{"T1078.004"} // Valid Accounts: Cloud Accounts
	default:
		return nil
	}
}

// severityFromScore converts a numeric score to a Severity label.
func severityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.5:
		return SeverityHigh
	case score >= 5.0:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// formatPathDescription builds a human-readable chain representation of a path:
//
//	sa:default:app → [can_create] → resource:default:clusterrolebindings → [inferred] → clusterrole:cluster-admin
func formatPathDescription(path AttackPath) string {
	if len(path) == 0 {
		return ""
	}
	var b strings.Builder
	for i, step := range path {
		if i > 0 && step.Edge != nil {
			b.WriteString(fmt.Sprintf(" → [%s] → ", step.Edge.Kind))
		}
		// Prefer name + kind label for readability; fall back to raw ID.
		if step.Node.Name != "" && step.Node.Name != step.Node.ID {
			b.WriteString(fmt.Sprintf("%s (%s)", step.Node.ID, step.Node.Kind))
		} else {
			b.WriteString(step.Node.ID)
		}
	}
	return b.String()
}

// buildPathEvidence returns one evidence string per hop (edge traversal).
func buildPathEvidence(path AttackPath) []string {
	if len(path) < 2 {
		return nil
	}
	evidence := make([]string, 0, len(path)-1)
	for i := 1; i < len(path); i++ {
		step := path[i]
		prev := path[i-1]
		edgeLabel := ""
		if step.Edge != nil {
			edgeLabel = string(step.Edge.Kind)
			if step.Edge.Reason != "" {
				edgeLabel += ": " + step.Edge.Reason
			}
		}
		evidence = append(evidence, fmt.Sprintf("%s --(%s)--> %s", prev.Node.ID, edgeLabel, step.Node.ID))
	}
	return evidence
}

// pathAffectedNodes extracts all node IDs from a path in traversal order.
func pathAffectedNodes(path AttackPath) []string {
	ids := make([]string, len(path))
	for i, step := range path {
		ids[i] = step.Node.ID
	}
	return ids
}

// isDuplicatePath returns true if the path's terminal node is already covered
// by an existing single-step finding. This prevents multi-hop from re-flagging
// goals that are directly surfaced by existing rules (e.g. ruleClusterAdminBinding
// already flags crb:* nodes; rulePrivilegedContainers already flags workload nodes).
// Paths with 2+ hops are never considered duplicates since no single-step rule
// covers a chained attack path.
func isDuplicatePath(path AttackPath, existing []RiskFinding) bool {
	if len(path) != 2 {
		// Only suppress 1-hop paths; multi-hop findings are always novel.
		return false
	}
	targetID := path[len(path)-1].Node.ID
	for _, f := range existing {
		for _, n := range f.AffectedNodes {
			if n == targetID {
				return true
			}
		}
	}
	return false
}

// footholdNodesForIdentity returns all realistic attacker-controlled start nodes for
// the current identity, ordered from most-concrete (workload/pod) to most-abstract
// (identity node). This drives realistic attack chains of the form:
//
//	Pod → SA → Binding → Role → Goal
//
// Priority order:
//  1. The specific pod k8scout is running in (when in-cluster) — the most concrete foothold.
//  2. All other pods/workloads running as the current SA — broader foothold set.
//  3. The SA node itself — identity pivot point.
//  4. The abstract identity node — fallback for non-SA identities.
func footholdNodesForIdentity(g *Graph, r *kube.EnumerationResult) []string {
	seen := make(map[string]bool)
	var starts []string

	addStart := func(id string) {
		if !seen[id] && g.nodeByID(id) != nil {
			seen[id] = true
			starts = append(starts, id)
		}
	}

	// Priority 1: the specific pod we are running inside (in-cluster mode only).
	// This is the most actionable foothold — paths starting here reflect what the
	// current binary can actually do right now.
	if podID := currentPodNodeID(r); podID != "" {
		addStart(podID)
	}

	// Priority 2 & 3: all pods/workloads running as the current SA + the SA itself.
	username := r.Identity.Username
	if strings.HasPrefix(username, "system:serviceaccount:") {
		parts := strings.SplitN(strings.TrimPrefix(username, "system:serviceaccount:"), ":", 2)
		if len(parts) == 2 {
			saID := saNodeID(parts[0], parts[1])
			// Pods and workloads that run_as this SA.
			for i := range g.Edges {
				e := &g.Edges[i]
				if e.Kind == EdgeRunsAs && e.To == saID {
					addStart(e.From) // workload:<ns>:<name> or pod:<ns>:<name>
				}
			}
			// The SA node itself (identity pivot).
			addStart(saID)
		}
	}

	// Priority 3.5: pods reachable via exec from the current identity or foothold pod.
	// These represent workloads the attacker can move into — exec gives shell access,
	// which is equivalent to running AS that pod's SA. Paths starting from these
	// pods score as foothold-anchored (pod-start) because the exec step is implicit.
	// This surfaces realistic chains: exec into privileged pod → steal SA token → escalate.
	execSources := []string{"identity:" + username}
	if podID := currentPodNodeID(r); podID != "" {
		execSources = append(execSources, podID)
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Kind != EdgeCanExec {
			continue
		}
		for _, src := range execSources {
			if e.From == src {
				addStart(e.To) // pod reachable via exec — treat as secondary foothold
				break
			}
		}
	}

	// Priority 4: abstract identity node — fallback for human users and non-SA identities.
	addStart("identity:" + username)

	return starts
}

// inferLateralMovementFindings surfaces exec and portforward reachability from the
// current foothold to other pods in the cluster. It emits at most one finding per
// lateral movement vector (exec vs portforward), listing all reachable pods.
//
// This is only meaningful when concrete reachability edges were added by
// buildConcreteReachabilityEdges — i.e. when SSAR confirmed exec/portforward access.
// The finding is separate from multi-hop because it represents direct lateral movement
// capability (one hop) rather than an escalation chain.
func inferLateralMovementFindings(g *Graph, r *kube.EnumerationResult, log *zap.Logger) []RiskFinding {
	if len(r.ClusterObjects.Pods) == 0 {
		return nil
	}

	// Determine foothold source nodes.
	var sourceIDs []string
	if podID := currentPodNodeID(r); podID != "" {
		sourceIDs = append(sourceIDs, podID)
	}
	sourceIDs = append(sourceIDs, "identity:"+r.Identity.Username)

	// Build index of (from,kind) → reachable pod IDs from the graph edges.
	execTargets := make(map[string]bool)   // pod IDs reachable via can_exec
	pfTargets := make(map[string]bool)     // pod IDs reachable via can_portforward

	srcSet := make(map[string]bool, len(sourceIDs))
	for _, s := range sourceIDs {
		srcSet[s] = true
	}

	for i := range g.Edges {
		e := &g.Edges[i]
		if !srcSet[e.From] {
			continue
		}
		switch e.Kind {
		case EdgeCanExec:
			execTargets[e.To] = true
		case EdgeCanPortForward:
			pfTargets[e.To] = true
		}
	}

	if len(execTargets) == 0 && len(pfTargets) == 0 {
		return nil
	}

	var findings []RiskFinding

	makeEvidence := func(targetSet map[string]bool) []string {
		ev := make([]string, 0, len(targetSet))
		for podID := range targetSet {
			n := g.nodeByID(podID)
			if n != nil {
				privileged := ""
				if m := n.Metadata; m != nil {
					if m["privileged_containers"] != "" {
						privileged = " [PRIVILEGED]"
					} else if m["host_pid"] == "true" || m["host_network"] == "true" || m["host_ipc"] == "true" {
						privileged = " [HOST-NS]"
					}
				}
				ev = append(ev, fmt.Sprintf("%s (%s/%s)%s", podID, n.Namespace, n.Name, privileged))
			} else {
				ev = append(ev, podID)
			}
		}
		return ev
	}

	foothold := "current identity"
	if podID := currentPodNodeID(r); podID != "" {
		foothold = podID
	}

	if len(execTargets) > 0 {
		ev := makeEvidence(execTargets)
		findings = append(findings, RiskFinding{
			RuleID:   "LATERAL-EXEC-REACHABILITY",
			Severity: SeverityHigh,
			Score:    8.0,
			Title: fmt.Sprintf("Lateral movement: can exec into %d pod(s) from foothold",
				len(execTargets)),
			Description: fmt.Sprintf(
				"From %s, the current identity has pods/exec create permission in one or more namespaces. "+
					"This enables direct shell access to %d running pod(s) without additional escalation. "+
					"An attacker can use this to pivot across workloads, steal tokens, or read secrets.",
				foothold, len(execTargets)),
			Evidence: append([]string{fmt.Sprintf("Foothold: %s", foothold)}, ev...),
			AffectedNodes: func() []string {
				ids := make([]string, 0, len(execTargets))
				for id := range execTargets { ids = append(ids, id) }
				return ids
			}(),
			MITREIDs:   []string{"T1609"},
			Mitigation: "Restrict pods/exec create permission to specific resourceNames or dedicated debug accounts. " +
				"Use NetworkPolicies and PodSecurityAdmission to limit blast radius. " +
				"Audit all exec events via Kubernetes audit logging.",
		})
		log.Info("lateral exec finding", zap.Int("pods", len(execTargets)), zap.String("foothold", foothold))
	}

	if len(pfTargets) > 0 {
		ev := makeEvidence(pfTargets)
		findings = append(findings, RiskFinding{
			RuleID:   "LATERAL-PORTFORWARD-REACHABILITY",
			Severity: SeverityMedium,
			Score:    6.0,
			Title: fmt.Sprintf("Lateral movement: can portforward to %d pod(s) from foothold",
				len(pfTargets)),
			Description: fmt.Sprintf(
				"From %s, the current identity can portforward to %d pod(s). "+
					"Port-forward allows TCP tunneling to any port of the target pod — "+
					"useful for reaching internal services, databases, and management endpoints.",
				foothold, len(pfTargets)),
			Evidence: append([]string{fmt.Sprintf("Foothold: %s", foothold)}, ev...),
			AffectedNodes: func() []string {
				ids := make([]string, 0, len(pfTargets))
				for id := range pfTargets { ids = append(ids, id) }
				return ids
			}(),
			MITREIDs:   []string{"T1090"},
			Mitigation: "Restrict pods/portforward create permission. " +
				"Use NetworkPolicies to prevent unauthorized pod-to-pod TCP tunneling.",
		})
		log.Info("lateral portforward finding", zap.Int("pods", len(pfTargets)), zap.String("foothold", foothold))
	}

	return findings
}

// inferMultiHopFindings traverses the graph from all realistic foothold nodes toward
// high-value targets and emits one RiskFinding per discovered attack path.
// It must be called after emitInferredEdges so that inferred edges are visible.
//
// Start nodes are ordered concrete-to-abstract (workload/pod → SA → identity) so that
// realistic paths (e.g. Pod → SA → CRB → ClusterRole) are emitted first and the
// per-goal cap is reached before redundant abstract paths.
func inferMultiHopFindings(g *Graph, r *kube.EnumerationResult, existing []RiskFinding, log *zap.Logger) []RiskFinding {
	startIDs := footholdNodesForIdentity(g, r)
	if len(startIDs) == 0 {
		return nil
	}

	goals := HighValueTargets(g, r)
	if len(goals) == 0 {
		return nil
	}

	var findings []RiskFinding
	// Track emitted-path fingerprints globally across all start nodes to avoid
	// duplicating the same node sequence from different abstract start points.
	emittedPaths := make(map[string]bool)

	for _, goal := range goals {
		// Collect candidates from all start nodes (2× budget to survive subset dedup).
		candidateBudget := MaxPathsPerGoal * 2
		var candidates []ScoredPath
		seenFingerprints := make(map[string]bool)

		for _, startID := range startIDs {
			if goal.NodeID == startID {
				continue // start IS the goal
			}
			if len(candidates) >= candidateBudget {
				break
			}

			scored := g.FindWeightedPaths(startID, goal.NodeID, MaxAttackPathDepth, candidateBudget-len(candidates))
			for _, sp := range scored {
				if isDuplicatePath(sp.Path, existing) {
					continue
				}
				fp := pathFingerprint(sp.Path)
				if seenFingerprints[fp] || emittedPaths[fp] {
					continue
				}
				seenFingerprints[fp] = true
				candidates = append(candidates, sp)
			}
		}

		// Sort candidates by path length (shortest first) so that subset detection
		// correctly identifies longer dominated paths.
		for i := 1; i < len(candidates); i++ {
			for j := i; j > 0 && len(candidates[j].Path) < len(candidates[j-1].Path); j-- {
				candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
			}
		}

		// Remove paths whose node sets are strict supersets of a shorter path.
		candidates = deduplicateSubsetPaths(candidates)

		emitted := 0
		for _, sp := range candidates {
			if emitted >= MaxPathsPerGoal {
				break
			}
			fp := pathFingerprint(sp.Path)
			emittedPaths[fp] = true

			numHops := len(sp.Path) - 1
			shape := ClassifyPath(sp.Path)
			score := ScoreByShape(shape, goal.BaseScore, numHops)

			findings = append(findings, RiskFinding{
				RuleID:   "MULTIHOP-ESCALATION",
				Severity: severityFromScore(score),
				Score:    score,
				Title:    BuildPathTitle(sp.Path, goal, shape),
				Description: fmt.Sprintf("%s\n\nTarget: %s — %s",
					formatPathDescription(sp.Path), goal.GoalKind, goal.Description),
				Evidence:      buildPathEvidence(sp.Path),
				AffectedNodes: pathAffectedNodes(sp.Path),
				MITREIDs:      goalKindMITRE(goal.GoalKind),
				AttackPath:    sp.Path,
				PathWeight:    sp.Weight,
				Mitigation: fmt.Sprintf("Break the attack path by removing at least one edge. "+
					"Review permissions and workload configurations along: %s",
					formatPathDescription(sp.Path)),
			})
			emitted++

			log.Info("multi-hop finding",
				zap.String("goal_kind", string(goal.GoalKind)),
				zap.String("goal_node", goal.NodeID),
				zap.Int("hops", numHops),
				zap.Float64("score", score),
				zap.Float64("weight", sp.Weight))
		}
	}

	return findings
}

// pathFingerprint returns a stable string key for an attack path based on its
// ordered node IDs. Used to deduplicate paths discovered from different start nodes.
func pathFingerprint(path AttackPath) string {
	ids := make([]string, len(path))
	for i, step := range path {
		ids[i] = step.Node.ID
	}
	return strings.Join(ids, "→")
}

// isSubsetPath returns true when every node in the shorter path `a` also appears in path `b`.
// Used to filter redundant longer paths: if A→B→D exists, A→B→C→D adds no new reachability.
func isSubsetPath(a, b AttackPath) bool {
	if len(a) >= len(b) {
		return false
	}
	bNodes := make(map[string]bool, len(b))
	for _, step := range b {
		bNodes[step.Node.ID] = true
	}
	for _, step := range a {
		if !bNodes[step.Node.ID] {
			return false
		}
	}
	return true
}

// deduplicateSubsetPaths removes paths whose node sets are strict supersets of a shorter path.
// Input must be sorted by path length (shortest first) for correct subset detection.
func deduplicateSubsetPaths(paths []ScoredPath) []ScoredPath {
	kept := make([]ScoredPath, 0, len(paths))
	for _, candidate := range paths {
		dominated := false
		for _, shorter := range kept {
			if isSubsetPath(shorter.Path, candidate.Path) {
				dominated = true
				break
			}
		}
		if !dominated {
			kept = append(kept, candidate)
		}
	}
	return kept
}

// ── Reviewer multi-hop: workload-centric paths ────────────────────────────────

// maxReviewerPathsPerWorkload caps the number of paths emitted per workload node.
const maxReviewerPathsPerWorkload = 5

// maxReviewerMultiHopTotal caps the total reviewer multi-hop findings across all workloads.
const maxReviewerMultiHopTotal = 300

// inferReviewerMultiHopFindings generates realistic attack chains starting from
// every pod/workload in the cluster, tracing through their ServiceAccount and RBAC
// bindings to reach high-value targets. This produces findings such as:
//
//	Pod X → SA Y → ClusterRoleBinding Z → cluster-admin
//
// Unlike inferMultiHopFindings (which starts from the current identity), this
// function covers the full cluster attack surface regardless of who is running the scan.
// It is intended for reviewer mode only.
func inferReviewerMultiHopFindings(g *Graph, r *kube.EnumerationResult, existing []RiskFinding, log *zap.Logger) []RiskFinding {
	goals := HighValueTargets(g, r)
	if len(goals) == 0 {
		return nil
	}

	var findings []RiskFinding
	emittedPaths := make(map[string]bool)
	total := 0

	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindWorkload && n.Kind != KindPod {
			continue
		}
		if total >= maxReviewerMultiHopTotal {
			log.Info("reviewer multi-hop total cap reached", zap.Int("cap", maxReviewerMultiHopTotal))
			break
		}

		workloadPaths := 0

		for _, goal := range goals {
			if goal.NodeID == n.ID {
				continue // workload is the goal — not a useful attack path
			}
			if workloadPaths >= maxReviewerPathsPerWorkload {
				break
			}

			scored := g.FindWeightedPaths(n.ID, goal.NodeID, MaxAttackPathDepth, maxReviewerPathsPerWorkload-workloadPaths)
			for _, sp := range scored {
				if total >= maxReviewerMultiHopTotal || workloadPaths >= maxReviewerPathsPerWorkload {
					break
				}
				if len(sp.Path) < 3 {
					continue
				}
				if isDuplicatePath(sp.Path, existing) {
					continue
				}
				fp := pathFingerprint(sp.Path)
				if emittedPaths[fp] {
					continue
				}
				emittedPaths[fp] = true

				numHops := len(sp.Path) - 1
				shape := ClassifyPath(sp.Path)
				score := ScoreByShape(shape, goal.BaseScore, numHops)

				findings = append(findings, RiskFinding{
					RuleID:   "MULTIHOP-ESCALATION",
					Severity: severityFromScore(score),
					Score:    score,
					Title:    BuildPathTitle(sp.Path, goal, shape),
					Description: fmt.Sprintf(
						"Foothold: %s (%s/%s)\n\n%s\n\nTarget: %s — %s",
						n.Kind, n.Namespace, n.Name,
						formatPathDescription(sp.Path),
						goal.GoalKind, goal.Description),
					Evidence:      buildPathEvidence(sp.Path),
					AffectedNodes: pathAffectedNodes(sp.Path),
					MITREIDs:      goalKindMITRE(goal.GoalKind),
					AttackPath:    sp.Path,
					PathWeight:    sp.Weight,
					Mitigation: fmt.Sprintf(
						"Break the attack path by removing at least one edge. "+
							"Review permissions and workload configurations along: %s",
						formatPathDescription(sp.Path)),
				})
				workloadPaths++
				total++

				log.Info("reviewer multi-hop finding",
					zap.String("foothold", n.ID),
					zap.String("goal_kind", string(goal.GoalKind)),
					zap.String("goal_node", goal.NodeID),
					zap.Int("hops", numHops),
					zap.Float64("score", score),
					zap.Float64("weight", sp.Weight))
			}
		}
	}

	return findings
}

// ── New improvement-batch rules ───────────────────────────────────────────────

// ruleNonResourceURLPrivesc fires when SSRR returns non-resource URL rules that
// grant exec/portforward access bypassing the resource-based RBAC check.
func ruleNonResourceURLPrivesc() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-NONRESOURCE-URL",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Non-resource URL rule grants exec/portforward — bypasses resource RBAC check",
		MITREIDs: []string{"T1609"},
		Mitigation: `• Non-resource URL rules are rarely needed by workloads. Remove them.
• Audit ClusterRoles with nonResourceURLs containing /exec or /portforward.
• Prefer explicit resource-based RBAC (pods/exec, pods/portforward) which is easier to audit.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			execPatterns := []string{"/exec", "/portforward", "/attach"}
			var evidence []string
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					if len(rule.NonResourceURLs) == 0 {
						continue
					}
					for _, url := range rule.NonResourceURLs {
						for _, pat := range execPatterns {
							if strings.Contains(url, pat) {
								evidence = append(evidence, fmt.Sprintf(
									"SSRR namespace %q: non-resource URL %q verbs=%v (bypasses resource RBAC)",
									ns, url, rule.Verbs))
								break
							}
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("SSRR returned %d non-resource URL rule(s) granting exec/portforward/attach access. "+
				"Non-resource URL grants are checked before resource-level RBAC and can bypass deny policies "+
				"that block pods/exec resource access.", len(evidence)), evidence, nil
		},
	}
}

// ruleCRDPermissions fires when any identity (SSRR/SSAR or reviewer RBAC) has
// create/patch/delete on high-risk operator CRDs present in the cluster.
func ruleCRDPermissions() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-CRD-OPERATOR",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Identity has create/patch/delete on high-risk operator CRDs — workload injection via GitOps/operator",
		MITREIDs: []string{"T1610"},
		Mitigation: `• Treat create/patch on Flux HelmRelease, ArgoCD Application, ExternalSecret, and Crossplane Provider
  as equivalent to patching Deployments — they can inject arbitrary workloads or exfiltrate secrets.
• Restrict these verbs to CI/CD service accounts with audit alerting.
• Use OPA/Gatekeeper to validate CRD resources before admission.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if len(r.ClusterObjects.CRDs) == 0 {
				return "", nil, nil
			}
			// Build a set of high-risk CRD resource names present in this cluster.
			presentCRDs := make(map[string]string, len(r.ClusterObjects.CRDs)) // resource → group/kind
			for _, crd := range r.ClusterObjects.CRDs {
				presentCRDs[crd.Resource] = crd.Group + "/" + crd.Kind
			}
			dangerousVerbs := map[string]bool{"create": true, "patch": true, "update": true, "delete": true, "*": true}
			var evidence []string
			// Check SSRR rules for CRD resource matches.
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					for _, res := range rule.Resources {
						if groupKind, ok := presentCRDs[res]; ok {
							for _, verb := range rule.Verbs {
								if dangerousVerbs[verb] {
									evidence = append(evidence, fmt.Sprintf(
										"SSRR namespace %q: %s %s (%s) — operator resource mutation",
										ns, verb, res, groupKind))
									break
								}
							}
						}
					}
				}
			}
			// Also check SSAR results.
			for _, c := range r.Permissions.SSARChecks {
				if !c.Allowed {
					continue
				}
				if _, ok := presentCRDs[c.Resource]; ok && dangerousVerbs[c.Verb] {
					evidence = append(evidence, fmt.Sprintf(
						"SSAR namespace %q: %s %s (%s) = allowed",
						c.Namespace, c.Verb, c.Resource, presentCRDs[c.Resource]))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("The current identity can mutate %d high-risk operator CRD resource(s). "+
				"Patching Flux/ArgoCD/ExternalSecrets/Crossplane resources is functionally equivalent to "+
				"modifying Deployments or reading Secrets — the operator will execute the requested change.", len(evidence)),
				evidence, nil
		},
	}
}

// ruleOrphanedSATokens detects kubernetes.io/service-account-token secrets whose
// owning ServiceAccount no longer exists. These tokens remain valid and represent
// a persistent access vector if an attacker knows the token value.
func ruleOrphanedSATokens() inferenceRule {
	return inferenceRule{
		RuleID:   "HYGIENE-ORPHANED-SA-TOKEN",
		Severity: SeverityMedium,
		Score:    6.5,
		Title:    "Orphaned ServiceAccount token secrets — valid credentials for deleted SAs",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• Delete orphaned SA token secrets immediately — they remain valid even after the owning SA is deleted.
• Audit: kubectl get secrets --all-namespaces --field-selector=type=kubernetes.io/service-account-token
• Migrate to projected service account tokens (BoundServiceAccountTokenVolume) which expire automatically.
• Enable periodic RBAC cleanup automation to remove orphaned secrets.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			// Build a set of known SA names per namespace.
			saIndex := make(map[string]bool, len(r.ClusterObjects.ServiceAccounts))
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				saIndex[sa.Namespace+"/"+sa.Name] = true
			}
			var evidence []string
			var nodes []string
			for _, sm := range r.ClusterObjects.SecretsMeta {
				if sm.Type != "kubernetes.io/service-account-token" {
					continue
				}
				if sm.SAName == "" {
					continue
				}
				key := sm.Namespace + "/" + sm.SAName
				if !saIndex[key] {
					evidence = append(evidence, fmt.Sprintf(
						"Secret %s/%s (type=SA-token) references deleted SA %q — token is still valid",
						sm.Namespace, sm.Name, sm.SAName))
					nodes = append(nodes, "secret:"+sm.Namespace+":"+sm.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d ServiceAccount token secret(s) reference deleted ServiceAccounts. "+
				"Kubernetes does not automatically revoke legacy SA tokens when an SA is deleted — "+
				"these tokens are active credentials that can be used until manually deleted.", len(evidence)),
				evidence, nodes
		},
	}
}

// ruleDanglingRoleBindings detects RoleBindings/ClusterRoleBindings whose subjects
// reference ServiceAccounts that no longer exist. These represent cleanup debt and
// can be exploited if the SA name is reused (name-reuse attack).
func ruleDanglingRoleBindings() inferenceRule {
	return inferenceRule{
		RuleID:   "HYGIENE-DANGLING-ROLEBINDING",
		Severity: SeverityMedium,
		Score:    5.5,
		Title:    "RoleBindings with dangling subjects — potential name-reuse privilege escalation",
		MITREIDs: []string{"T1078"},
		Mitigation: `• Remove bindings whose subjects no longer exist.
• Implement GitOps-managed RBAC so bindings are automatically cleaned up when SAs are deleted.
• Alert on creation of ServiceAccounts whose names match existing bindings (name-reuse signal).
• Use kubectl auth reconcile to diff RBAC state against a desired-state manifest.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			saIndex := make(map[string]bool, len(r.ClusterObjects.ServiceAccounts))
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				saIndex[sa.Namespace+"/"+sa.Name] = true
			}
			var evidence []string
			var nodes []string
			checkBindings := func(bindings []kube.BindingInfo, kind string) {
				for _, b := range bindings {
					for _, subj := range b.Subjects {
						if subj.Kind != "ServiceAccount" {
							continue
						}
						key := subj.Namespace + "/" + subj.Name
						if !saIndex[key] {
							evidence = append(evidence, fmt.Sprintf(
								"%s %q references deleted SA %s/%s — binding is dormant but grants %s/%s on recreation",
								kind, b.Name, subj.Namespace, subj.Name, b.RoleRef.Kind, b.RoleRef.Name))
							nodes = append(nodes, "binding:"+b.Namespace+":"+b.Name)
						}
					}
				}
			}
			checkBindings(r.ClusterObjects.RoleBindings, "RoleBinding")
			checkBindings(r.ClusterObjects.ClusterRoleBindings, "ClusterRoleBinding")
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d binding(s) reference non-existent ServiceAccount subjects. "+
				"If a new SA is created with the same name, it immediately inherits all bound permissions — "+
				"this is exploitable in namespaces where SA creation is allowed.", len(evidence)), evidence, nodes
		},
	}
}

// ruleKubeletExposed fires when the kubelet read-only port probe returns accessible nodes.
func ruleKubeletExposed() inferenceRule {
	return inferenceRule{
		RuleID:   "EXPOSURE-KUBELET-READONLY-PORT",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Kubelet read-only port (10255) accessible — unauthenticated pod metadata exposure",
		MITREIDs: []string{"T1613"},
		Mitigation: `• Disable the kubelet read-only port by setting --read-only-port=0 in kubelet configuration.
• This port exposes pod specs, environment variables, and volume metadata without authentication.
• Ensure kubelet uses --anonymous-auth=false and --authorization-mode=Webhook.
• Use NetworkPolicy to block pod-to-node traffic on port 10255 if the port cannot be disabled.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, probe := range r.ClusterObjects.KubeletProbes {
				if probe.ReadOnlyOpen {
					evidence = append(evidence, fmt.Sprintf(
						"Node %s (%s): kubelet port 10255 responded — unauthenticated access confirmed",
						probe.NodeName, probe.IP))
					nodes = append(nodes, "node:"+probe.NodeName)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d node(s) expose the kubelet read-only HTTP port (10255). "+
				"Any pod in the cluster can query /pods to enumerate all pod specs and environment "+
				"variables cluster-wide without API server credentials.", len(evidence)), evidence, nodes
		},
	}
}

// rulePriorityClassAbuse fires when the identity can create pods and any pods in the cluster
// use non-default priority, indicating PriorityClasses are in use and could be weaponised to
// evict critical system pods (kube-dns, CNI, etc.).
func rulePriorityClassAbuse() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-PRIORITY-CLASS-EVICTION",
		Severity: SeverityMedium,
		Score:    6.0,
		Title:    "Pod creation rights + active PriorityClasses — risk of critical system pod eviction",
		MITREIDs: []string{"T1499"},
		Mitigation: `• Restrict access to high-priority PriorityClasses via RBAC (use resourceNames on priorityclasses).
• Apply LimitRange / ResourceQuota to cap the priority of pods created by non-admin service accounts.
• Monitor for creation of high-priority pods outside platform namespaces.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			// Check create pods SSAR permission.
			canCreate := false
			for _, c := range r.Permissions.SSARChecks {
				if c.Allowed && c.Resource == "pods" && c.Verb == "create" {
					canCreate = true
					break
				}
			}
			if !canCreate {
				for _, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "pods", "*") && containsAny(rule.Verbs, "create", "*") {
							canCreate = true
							break
						}
					}
					if canCreate {
						break
					}
				}
			}
			if !canCreate {
				return "", nil, nil
			}
			evidence := []string{
				"SSAR: create pods = allowed",
				"Advisory: if high-priority PriorityClasses exist, an attacker can schedule a resource-exhausting " +
					"pod with elevated priority, forcing the scheduler to evict kube-dns, CNI, or other critical system pods.",
			}
			return "The current identity can create pods. If PriorityClasses above system-cluster-critical exist and " +
				"are not RBAC-restricted, an attacker can use them to schedule pods that evict critical system components, " +
				"causing cluster-wide disruption.", evidence, nil
		},
	}
}

// ── Phase 1: NetworkPolicy + Service rules ───────────────────────────────────

func ruleNoNetworkPolicyDefaultDeny() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-NO-NETPOL-DEFAULT-DENY",
		Severity: SeverityMedium,
		Score:    5.5,
		Title:    "Namespaces without default-deny NetworkPolicy",
		Mitigation: `• Apply a default-deny ingress NetworkPolicy to every namespace.
• Allow only required pod-to-pod and pod-to-service traffic explicitly.
• Use namespace labels to enforce deny-all as a baseline.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			npsByNS := make(map[string][]kube.NetworkPolicyInfo)
			for _, np := range r.ClusterObjects.NetworkPolicies {
				npsByNS[np.Namespace] = append(npsByNS[np.Namespace], np)
			}
			var evidence []string
			var nodes []string
			for _, ns := range r.ClusterObjects.Namespaces {
				if ns.Name == "kube-system" || ns.Name == "kube-public" || ns.Name == "kube-node-lease" {
					continue
				}
				nps := npsByNS[ns.Name]
				hasDenyAll := false
				for _, np := range nps {
					hasIngress := false
					for _, pt := range np.PolicyTypes {
						if pt == "Ingress" {
							hasIngress = true
						}
					}
					if hasIngress && len(np.IngressRules) == 0 && len(np.PodSelector) == 0 {
						hasDenyAll = true
						break
					}
				}
				if !hasDenyAll {
					evidence = append(evidence, fmt.Sprintf("Namespace %q has no default-deny ingress NetworkPolicy", ns.Name))
					nodes = append(nodes, "ns:"+ns.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d namespace(s) lack a default-deny ingress NetworkPolicy. "+
				"Any pod can receive traffic from any other pod in the cluster, enabling unrestricted lateral movement.",
				len(evidence)), evidence, nodes
		},
	}
}

func ruleNetworkPolicyBypass() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-DELETE-NETPOL",
		Severity: SeverityHigh,
		Score:    7.5,
		Title:    "Identity can delete NetworkPolicies — network isolation bypass",
		MITREIDs: []string{"T1562.001"},
		Mitigation: `• Restrict delete permissions on networkpolicies to infrastructure admin accounts only.
• Use OPA/Gatekeeper to prevent deletion of critical NetworkPolicy objects.
• Monitor audit logs for NetworkPolicy deletion events.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "networkpolicies" && (c.Verb == "delete" || c.Verb == "deletecollection") && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s networkpolicies in %q = allowed", c.Verb, c.Namespace))
				}
			}
			if len(evidence) == 0 {
				for _, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "networkpolicies", "*") &&
							containsAny(rule.Verbs, "delete", "deletecollection", "*") {
							evidence = append(evidence, "SSRR: delete networkpolicies = allowed")
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can delete NetworkPolicies. An attacker can remove network isolation " +
				"controls, exposing internal services and enabling unrestricted lateral movement between pods.", evidence, nil
		},
	}
}

func ruleServiceExposure() inferenceRule {
	return inferenceRule{
		RuleID:   "EXPOSURE-EXTERNAL-SERVICE",
		Severity: SeverityInfo,
		Score:    3.0,
		Title:    "Externally-exposed Services (NodePort/LoadBalancer)",
		Mitigation: `• Review whether NodePort and LoadBalancer services need external exposure.
• Use Ingress controllers with TLS termination instead of direct NodePort exposure.
• Apply NetworkPolicies to restrict inbound traffic to exposed services.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, svc := range r.ClusterObjects.Services {
				if svc.Type == "NodePort" || svc.Type == "LoadBalancer" {
					evidence = append(evidence, fmt.Sprintf("Service %s/%s: type=%s",
						svc.Namespace, svc.Name, svc.Type))
					nodes = append(nodes, "service:"+svc.Namespace+":"+svc.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d externally-exposed service(s) found. "+
				"NodePort and LoadBalancer services are reachable from outside the cluster.",
				len(evidence)), evidence, nodes
		},
	}
}

// ── Phase 2: Cloud metadata endpoint rules ───────────────────────────────────

func ruleAWSIMDSv1Accessible() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-IMDS-V1-ACCESSIBLE",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "AWS IMDSv1 reachable — credential theft without token hop",
		MITREIDs: []string{"T1552.005", "T1078.004"},
		Mitigation: `• Enforce IMDSv2-only on all EC2 instances: aws ec2 modify-instance-metadata-options --http-tokens required.
• Use EKS Pod Identity or IRSA with projected tokens instead of instance metadata credentials.
• Apply egress NetworkPolicy blocking 169.254.169.254 from non-system pods.
• Consider EKS Node Restriction admission controller to block metadata access from pods.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			for _, mp := range r.ClusterObjects.MetadataProbes {
				if mp.MetadataV1 {
					return "AWS IMDSv1 is reachable from within the cluster. Any pod can retrieve temporary IAM credentials " +
						"for the node's instance role by sending a simple GET request to 169.254.169.254. " +
						"This is the most dangerous metadata endpoint configuration — no token hop is required.",
						[]string{"IMDSv1 GET http://169.254.169.254/latest/meta-data/ returned HTTP 2xx"},
						[]string{"metadata:aws"}
				}
			}
			return "", nil, nil
		},
	}
}

func ruleAWSIMDSv2Only() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-IMDS-V2-ONLY",
		Severity: SeverityMedium,
		Score:    5.5,
		Title:    "AWS IMDSv2 reachable — credential theft requires PUT token",
		MITREIDs: []string{"T1552.005"},
		Mitigation: `• IMDSv2 requires a PUT request to obtain a session token before metadata access.
• This mitigates SSRF-based attacks but not direct pod access.
• Consider EKS Pod Identity or IRSA to avoid relying on instance metadata entirely.
• Apply egress NetworkPolicy blocking 169.254.169.254.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			for _, mp := range r.ClusterObjects.MetadataProbes {
				if mp.MetadataV2 && !mp.MetadataV1 {
					return "AWS IMDSv2 is reachable. While IMDSv2 requires a PUT request to obtain a session token " +
						"(mitigating SSRF-based credential theft), a compromised pod with direct network access " +
						"can still retrieve IAM credentials via the token-based flow.",
						[]string{"IMDSv2 PUT http://169.254.169.254/latest/api/token returned HTTP 2xx"},
						[]string{"metadata:aws"}
				}
			}
			return "", nil, nil
		},
	}
}

func ruleGKEMetadataReachable() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-GKE-METADATA-REACHABLE",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "GKE metadata server reachable — SA token theft possible",
		MITREIDs: []string{"T1552.005", "T1078.004"},
		Mitigation: `• Enable GKE Workload Identity on all node pools to replace metadata-based credential access.
• Use GKE Metadata Server with Workload Identity Federation for fine-grained cloud IAM.
• Block metadata access from pods not using Workload Identity.
• Apply egress NetworkPolicy blocking metadata.google.internal.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			for _, mp := range r.ClusterObjects.MetadataProbes {
				if mp.GKEMetadata {
					return "GKE metadata server (metadata.google.internal) is reachable from within the cluster. " +
						"Pods without Workload Identity can access the node's default service account credentials, " +
						"enabling cloud IAM privilege escalation.",
						[]string{"GET http://metadata.google.internal/computeMetadata/v1/ returned HTTP 2xx"},
						[]string{"metadata:gcp"}
				}
			}
			return "", nil, nil
		},
	}
}

func ruleAzureIMDSReachable() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-AZURE-IMDS-REACHABLE",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Azure IMDS reachable — managed identity token theft possible",
		MITREIDs: []string{"T1552.005", "T1078.004"},
		Mitigation: `• Use AKS Workload Identity (federated credentials) instead of pod-managed identities.
• Apply egress NetworkPolicy blocking 169.254.169.254 from application pods.
• Avoid assigning managed identities to node pools when using Workload Identity.
• Monitor Azure Activity Log for unexpected token acquisitions.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			for _, mp := range r.ClusterObjects.MetadataProbes {
				if mp.AzureIMDS {
					return "Azure Instance Metadata Service (IMDS) is reachable from within the cluster. " +
						"Any pod can request managed identity tokens from 169.254.169.254, enabling Azure " +
						"resource access with the node's managed identity permissions.",
						[]string{"GET http://169.254.169.254/metadata/instance returned HTTP 2xx"},
						[]string{"metadata:azure"}
				}
			}
			return "", nil, nil
		},
	}
}

func ruleCloudRoleOverlyPermissive() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-ROLE-OVERLY-PERMISSIVE",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Cloud IAM role with overly permissive name pattern",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Apply least-privilege to cloud IAM roles bound to Kubernetes ServiceAccounts.
• Use IAM conditions (AWS: aws:RequestedRegion, GCP: resource.name) to scope permissions.
• Regularly audit cloud IAM roles for overly broad permissions.
• Use cloud security posture management (CSPM) tools to detect overly permissive roles.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			dangerousPatterns := []string{"admin", "full-access", "power-user", "AdministratorAccess", "Owner", "Contributor"}
			var evidence []string
			var nodes []string
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				role := sa.IRSARole
				provider := "aws"
				if role == "" {
					role = sa.GCPServiceAccount
					provider = "gcp"
				}
				if role == "" {
					role = sa.AzureIdentity
					provider = "azure"
				}
				if role == "" {
					continue
				}
				for _, pat := range dangerousPatterns {
					if strings.Contains(strings.ToLower(role), strings.ToLower(pat)) {
						evidence = append(evidence, fmt.Sprintf("SA %s/%s → %s role %q matches pattern %q",
							sa.Namespace, sa.Name, provider, role, pat))
						nodes = append(nodes, saNodeID(sa.Namespace, sa.Name))
						break
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d ServiceAccount(s) bound to cloud IAM roles with overly permissive name patterns. "+
				"These roles likely grant broad cloud-plane access.", len(evidence)), evidence, nodes
		},
	}
}

// ── Phase 3: PV + ImagePullSecret rules ──────────────────────────────────────

func ruleSharedPVCrossAccess() inferenceRule {
	return inferenceRule{
		RuleID:   "CONFIG-SHARED-PV-CROSS-ACCESS",
		Severity: SeverityMedium,
		Score:    5.5,
		Title:    "ReadWriteMany PVC shared across multiple pods — cross-pod data access",
		Mitigation: `• Avoid ReadWriteMany PVCs unless required for multi-writer workloads.
• Use ReadWriteOnce or ReadOnlyMany access modes when shared writes are not needed.
• Ensure pods sharing a PVC are in the same trust domain.
• Monitor PV data integrity with file integrity monitoring (FIM).`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			pvcPods := make(map[string][]string)
			for _, pod := range r.ClusterObjects.Pods {
				for _, vol := range pod.Volumes {
					if vol.SourceKind == "PersistentVolumeClaim" && vol.SourceName != "" {
						key := pod.Namespace + "/" + vol.SourceName
						pvcPods[key] = append(pvcPods[key], pod.Namespace+"/"+pod.Name)
					}
				}
			}
			// Find PVCs with RWX that are shared.
			rwxPVCs := make(map[string]bool)
			for _, pvc := range r.ClusterObjects.PersistentVolumeClaims {
				for _, am := range pvc.AccessModes {
					if am == "ReadWriteMany" {
						rwxPVCs[pvc.Namespace+"/"+pvc.Name] = true
					}
				}
			}
			var evidence []string
			var nodes []string
			for pvcKey, pods := range pvcPods {
				if len(pods) < 2 || !rwxPVCs[pvcKey] {
					continue
				}
				evidence = append(evidence, fmt.Sprintf("PVC %s shared by %d pods: %v", pvcKey, len(pods), pods))
				nodes = append(nodes, "pvc:"+strings.Replace(pvcKey, "/", ":", 1))
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d ReadWriteMany PVC(s) are shared across multiple pods. "+
				"A compromised pod can read and modify data accessible to all pods sharing the volume.",
				len(evidence)), evidence, nodes
		},
	}
}

func ruleImagePullSecretExposure() inferenceRule {
	return inferenceRule{
		RuleID:   "CRED-IMAGEPULLSECRET-EXPOSURE",
		Severity: SeverityHigh,
		Score:    7.5,
		Title:    "ImagePullSecret credentials accessible — container registry credential theft",
		MITREIDs: []string{"T1552.007"},
		Mitigation: `• Use short-lived credentials for container registry access (IAM-based pull, OIDC tokens).
• Restrict RBAC: remove get/list secrets from ServiceAccounts that don't need registry access.
• Rotate registry credentials regularly and monitor for unauthorized image pulls.
• Consider using node-level registry authentication instead of imagePullSecrets.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			canGetSecrets := make(map[string]bool)
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "secrets" && (c.Verb == "get" || c.Verb == "list") && c.Allowed {
					canGetSecrets[c.Namespace] = true
				}
			}
			var evidence []string
			var nodes []string
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				if len(sa.ImagePullSecrets) == 0 {
					continue
				}
				if !canGetSecrets[sa.Namespace] {
					continue
				}
				for _, ips := range sa.ImagePullSecrets {
					evidence = append(evidence, fmt.Sprintf("SA %s/%s uses imagePullSecret %q — readable via SSAR",
						sa.Namespace, sa.Name, ips))
					nodes = append(nodes, "secret:"+sa.Namespace+":"+ips)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d imagePullSecret(s) are accessible to the current identity. "+
				"These contain container registry credentials that can be used to pull private images or push "+
				"malicious images if the registry allows push access.", len(evidence)), evidence, nodes
		},
	}
}

// ── Phase 5: Admission controller abuse rules ────────────────────────────────

func ruleWebhookBackendCompromise() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-WEBHOOK-BACKEND-COMPROMISE",
		Severity: SeverityCritical,
		Score:    9.5,
		Title:    "Identity can patch Deployment backing a mutating webhook — controls all pod admissions",
		MITREIDs: []string{"T1078.001", "T1525"},
		Mitigation: `• Restrict patch/update on webhook backend Deployments to CI/CD accounts only.
• Run webhook backends in dedicated namespaces with strict RBAC.
• Use Pod Security Admission to prevent webhook backends from being modified.
• Monitor webhook backend Deployment changes via audit logging.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			patchableNS := make(map[string]bool)
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "deployments" && (c.Verb == "patch" || c.Verb == "update") && c.Allowed {
					patchableNS[c.Namespace] = true
				}
			}
			if len(patchableNS) == 0 {
				return "", nil, nil
			}
			var evidence []string
			var nodes []string
			for _, wh := range r.ClusterObjects.Webhooks {
				if wh.Kind != "Mutating" || wh.ServiceNS == "" {
					continue
				}
				if patchableNS[wh.ServiceNS] {
					evidence = append(evidence, fmt.Sprintf(
						"Mutating webhook %q backed by service %s/%s — identity can patch deployments in %q",
						wh.Name, wh.ServiceNS, wh.ServiceName, wh.ServiceNS))
					nodes = append(nodes, "webhook:"+wh.Name)
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can patch the Deployment backing a mutating admission webhook. " +
				"By modifying the webhook backend, an attacker can inject sidecars, modify images, or steal " +
				"tokens for all future pods created in the webhook's scope.", evidence, nodes
		},
	}
}

func ruleWebhookPersistence() inferenceRule {
	return inferenceRule{
		RuleID:   "PERSIST-WEBHOOK-INJECTION",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "Identity can create mutating webhooks — persistent backdoor injection path",
		MITREIDs: []string{"T1525", "T1546"},
		Mitigation: `• Restrict create/patch on mutatingwebhookconfigurations to infrastructure admin accounts.
• Use ValidatingAdmissionPolicy to prevent creation of overly broad webhooks.
• Monitor audit logs for webhook configuration changes.
• Use webhook allow-listing in the API server configuration.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "mutatingwebhookconfigurations" &&
					(c.Verb == "create" || c.Verb == "patch") && c.Allowed {
					evidence = append(evidence, fmt.Sprintf("SSAR: %s mutatingwebhookconfigurations = allowed", c.Verb))
				}
			}
			if len(evidence) == 0 {
				for _, rules := range r.Permissions.SSRRByNamespace {
					for _, rule := range rules {
						if containsAny(rule.Resources, "mutatingwebhookconfigurations", "*") &&
							containsAny(rule.Verbs, "create", "patch", "*") {
							evidence = append(evidence, "SSRR: create/patch mutatingwebhookconfigurations = allowed")
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return "The current identity can create or patch MutatingWebhookConfigurations. " +
				"An attacker can register a webhook that injects malicious containers, modifies environment " +
				"variables, or steals service account tokens from all future pods — creating a persistent backdoor " +
				"that survives pod restarts and workload redeployments.", evidence, nil
		},
	}
}

func ruleValidatingWebhookBypass() inferenceRule {
	return inferenceRule{
		RuleID:   "PRIVESC-DELETE-VALIDATING-WEBHOOK",
		Severity: SeverityMedium,
		Score:    6.5,
		Title:    "Identity can delete validating webhooks — security control bypass",
		MITREIDs: []string{"T1562.001"},
		Mitigation: `• Restrict delete permissions on validatingwebhookconfigurations to infrastructure admins.
• Use OPA/Gatekeeper self-protection policies to prevent webhook deletion.
• Monitor audit logs for webhook deletion events and alert immediately.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			for _, c := range r.Permissions.SSARChecks {
				if c.Resource == "validatingwebhookconfigurations" && c.Verb == "delete" && c.Allowed {
					evidence = append(evidence, "SSAR: delete validatingwebhookconfigurations = allowed")
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			var nodes []string
			for _, wh := range r.ClusterObjects.Webhooks {
				if wh.Kind == "Validating" {
					nodes = append(nodes, "webhook:"+wh.Name)
				}
			}
			return "The current identity can delete ValidatingWebhookConfigurations. " +
				"An attacker can remove security controls enforced by admission webhooks (OPA, Kyverno, " +
				"Pod Security), then deploy workloads that would normally be blocked.", evidence, nodes
		},
	}
}

// ── Cloud coverage improvement rules ─────────────────────────────────────────

func ruleAWSAuthSystemMasters() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-AWS-AUTH-SYSTEM-MASTERS",
		Severity: SeverityCritical,
		Score:    10.0,
		Title:    "aws-auth ConfigMap grants system:masters — cluster-admin via IAM",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Remove system:masters group mapping from aws-auth ConfigMap immediately.
• Use EKS Access Entries with scoped access policies instead of aws-auth.
• Map IAM roles to the minimum required Kubernetes groups.
• Enable CloudTrail logging for aws-auth ConfigMap changes.
• Consider using EKS Pod Identity instead of IRSA for workload identity.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if r.ClusterObjects.AWSAuth == nil {
				return "", nil, nil
			}
			var evidence []string
			allEntries := append(r.ClusterObjects.AWSAuth.MapRoles, r.ClusterObjects.AWSAuth.MapUsers...)
			for _, entry := range allEntries {
				for _, group := range entry.Groups {
					if group == "system:masters" {
						evidence = append(evidence, fmt.Sprintf(
							"%s %q → username=%q, groups=[system:masters] — FULL CLUSTER ADMIN",
							entry.Type, entry.ARN, entry.Username))
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d IAM principal(s) mapped to system:masters in aws-auth ConfigMap. "+
				"Any entity that can assume these IAM roles has unrestricted cluster-admin access. "+
				"Compromising the IAM role grants immediate full Kubernetes control.",
				len(evidence)), evidence, nil
		},
	}
}

func ruleAWSAuthWildcard() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-AWS-AUTH-WILDCARD",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "aws-auth ConfigMap contains wildcard or overly broad IAM mapping",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Avoid mapping entire AWS account or wildcard principals in aws-auth.
• Use specific IAM role ARNs, not account-level wildcards.
• Regularly audit aws-auth mappings against actual access requirements.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if r.ClusterObjects.AWSAuth == nil {
				return "", nil, nil
			}
			var evidence []string
			allEntries := append(r.ClusterObjects.AWSAuth.MapRoles, r.ClusterObjects.AWSAuth.MapUsers...)
			for _, entry := range allEntries {
				if strings.Contains(entry.ARN, "*") || strings.Contains(entry.Username, "{{") {
					evidence = append(evidence, fmt.Sprintf(
						"%s %q → username=%q (contains wildcard/template)",
						entry.Type, entry.ARN, entry.Username))
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d overly broad IAM mapping(s) in aws-auth ConfigMap. "+
				"Wildcard or template-based mappings may grant access to unintended IAM principals.",
				len(evidence)), evidence, nil
		},
	}
}

func ruleIRSACrossAccount() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-IRSA-CROSS-ACCOUNT",
		Severity: SeverityHigh,
		Score:    8.5,
		Title:    "IRSA role assumption crosses AWS account boundary",
		MITREIDs: []string{"T1078.004", "T1550"},
		Mitigation: `• Verify cross-account IRSA roles have strict condition keys limiting access.
• Use aws:SourceAccount and sts:ExternalId conditions in trust policies.
• Audit cross-account IAM roles for least-privilege permissions.
• Consider using separate IRSA roles per workload instead of shared cross-account roles.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			accountIDs := make(map[string]bool)
			var evidence []string
			var nodes []string
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				if sa.IRSARole == "" {
					continue
				}
				acctID, roleName, _, _ := kube.ParseIRSARoleARN(sa.IRSARole)
				if acctID != "" {
					accountIDs[acctID] = true
					_ = roleName
				}
			}
			if len(accountIDs) <= 1 {
				return "", nil, nil
			}
			// Multiple AWS accounts referenced — flag cross-account.
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				if sa.IRSARole == "" {
					continue
				}
				acctID, _, _, _ := kube.ParseIRSARoleARN(sa.IRSARole)
				evidence = append(evidence, fmt.Sprintf(
					"SA %s/%s → IRSA role %q (account: %s)",
					sa.Namespace, sa.Name, sa.IRSARole, acctID))
				nodes = append(nodes, saNodeID(sa.Namespace, sa.Name))
			}
			accts := make([]string, 0, len(accountIDs))
			for id := range accountIDs {
				accts = append(accts, id)
			}
			return fmt.Sprintf("IRSA roles span %d AWS accounts (%s). Cross-account role assumptions "+
				"expand the blast radius — compromising one workload's SA may grant access to resources "+
				"in a different AWS account.", len(accountIDs), strings.Join(accts, ", ")), evidence, nodes
		},
	}
}

func ruleEKSPodIdentityDetected() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-EKS-POD-IDENTITY",
		Severity: SeverityInfo,
		Score:    3.0,
		Title:    "EKS Pod Identity agent detected — credential injection via webhook",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• EKS Pod Identity automatically injects AWS credentials into pods via a webhook.
• Verify that Pod Identity associations follow least-privilege for each workload.
• Audit Pod Identity associations via: aws eks list-pod-identity-associations.
• Consider network-level restrictions to the Pod Identity agent endpoint.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			pi := r.ClusterObjects.EKSPodIdentity
			if pi == nil || !pi.Enabled {
				return "", nil, nil
			}
			var evidence []string
			if pi.AgentDaemonSet != "" {
				evidence = append(evidence, "EKS Pod Identity agent DaemonSet: "+pi.AgentDaemonSet)
			}
			if pi.WebhookName != "" {
				evidence = append(evidence, "EKS Pod Identity webhook: "+pi.WebhookName)
			}
			return "EKS Pod Identity is enabled. AWS credentials are automatically injected into pods " +
				"via a mutating webhook. Pods receive temporary credentials without needing IRSA annotations " +
				"or projected SA tokens. Verify that pod identity associations are properly scoped.", evidence, nil
		},
	}
}

func ruleAADPodIdentityLegacy() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-AAD-POD-IDENTITY-LEGACY",
		Severity: SeverityHigh,
		Score:    7.5,
		Title:    "AAD Pod Identity (legacy) detected — migrate to Workload Identity",
		MITREIDs: []string{"T1078.004", "T1550"},
		Mitigation: `• AAD Pod Identity is deprecated. Migrate to Azure Workload Identity Federation.
• AAD Pod Identity uses NMI (Node Managed Identity) which intercepts IMDS requests.
• The NMI DaemonSet runs as privileged and can access all pod network traffic.
• Known vulnerability: pod can impersonate another pod's managed identity via race condition.
• Migration guide: https://learn.microsoft.com/en-us/azure/aks/workload-identity-migrate-from-pod-identity`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			aadpi := r.ClusterObjects.AADPodIdentity
			if aadpi == nil || !aadpi.Enabled {
				return "", nil, nil
			}
			var evidence []string
			if aadpi.NMIDaemonSet != "" {
				evidence = append(evidence, "NMI DaemonSet: "+aadpi.NMIDaemonSet+" (intercepts IMDS requests)")
			}
			if aadpi.MICDeployment != "" {
				evidence = append(evidence, "MIC Deployment: "+aadpi.MICDeployment+" (manages Azure identity assignments)")
			}
			if aadpi.CRDsPresent {
				evidence = append(evidence, "AzureIdentity CRDs present (aadpodidentity.k8s.io)")
			}
			return "AAD Pod Identity (legacy) is active in this cluster. This deprecated system has known " +
				"security issues including identity spoofing via NMI race conditions. The NMI DaemonSet runs " +
				"privileged and intercepts all pod IMDS traffic. Migrate to Azure Workload Identity Federation.", evidence, nil
		},
	}
}

func ruleAzureKeyVaultCSI() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-AZURE-KEYVAULT-CSI",
		Severity: SeverityInfo,
		Score:    3.0,
		Title:    "Azure Key Vault CSI driver detected — secrets injected from Key Vault",
		Mitigation: `• Azure Key Vault CSI driver mounts secrets from Key Vault into pods as volumes.
• Verify that SecretProviderClass resources follow least-privilege Key Vault access.
• Monitor Key Vault audit logs for unexpected secret access patterns.
• Ensure pods using Key Vault secrets have appropriate RBAC to prevent lateral movement.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if !r.ClusterObjects.AzureKeyVaultCSI {
				return "", nil, nil
			}
			return "Azure Key Vault CSI driver is installed. Secrets from Azure Key Vault are mounted " +
				"into pods as files via SecretProviderClass resources. This is a secure pattern but " +
				"ensure Key Vault access policies follow least-privilege.",
				[]string{"secrets-store-csi-driver detected in kube-system"}, nil
		},
	}
}

func ruleAzureTenantMismatch() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-AZURE-TENANT-CROSS",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "Azure Workload Identity spans multiple tenants — cross-tenant escalation risk",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Verify that cross-tenant workload identity is intentional.
• Use federated credential subject validation to restrict cross-tenant access.
• Monitor Azure AD sign-in logs for cross-tenant token acquisitions.
• Consider separate managed identities per tenant.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			tenants := make(map[string]bool)
			var evidence []string
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				if sa.AzureTenantID != "" {
					tenants[sa.AzureTenantID] = true
				}
			}
			if len(tenants) <= 1 {
				return "", nil, nil
			}
			for _, sa := range r.ClusterObjects.ServiceAccounts {
				if sa.AzureTenantID != "" {
					evidence = append(evidence, fmt.Sprintf(
						"SA %s/%s → Azure client-id=%s, tenant=%s",
						sa.Namespace, sa.Name, sa.AzureIdentity, sa.AzureTenantID))
				}
			}
			tIDs := make([]string, 0, len(tenants))
			for t := range tenants {
				tIDs = append(tIDs, t)
			}
			return fmt.Sprintf("Workload Identity annotations reference %d Azure AD tenants (%s). "+
				"Cross-tenant workload identity creates a lateral movement path between Azure tenants.",
				len(tenants), strings.Join(tIDs, ", ")), evidence, nil
		},
	}
}

func ruleGKEAutopilotHardening() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-GKE-AUTOPILOT-HARDENING",
		Severity: SeverityInfo,
		Score:    1.0,
		Title:    "GKE Autopilot cluster detected — enhanced security defaults enforced",
		Mitigation: `• GKE Autopilot enforces Workload Identity, disables metadata access, and applies Pod Security Standards.
• Autopilot clusters have a reduced attack surface compared to standard GKE.
• Ensure applications are compatible with Autopilot restrictions (no privileged containers, no hostPath).`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if r.ClusterObjects.GKEInfo == nil || !r.ClusterObjects.GKEInfo.IsAutopilot {
				return "", nil, nil
			}
			return "This is a GKE Autopilot cluster with enhanced security defaults. Autopilot enforces " +
				"Workload Identity (disabling metadata server access), applies Pod Security Standards " +
				"(no privileged containers), and restricts hostPath mounts. Many container escape techniques " +
				"are mitigated by default.",
				[]string{"GKE Autopilot detected via node labels"}, nil
		},
	}
}

func ruleGKEConfigConnector() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-GKE-CONFIG-CONNECTOR",
		Severity: SeverityHigh,
		Score:    8.0,
		Title:    "GKE Config Connector detected — Kubernetes-to-GCP IAM bridge",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Config Connector creates GCP resources directly from Kubernetes manifests.
• A compromised SA with Config Connector CRD permissions can create/modify cloud IAM resources.
• Restrict RBAC for cnrm.cloud.google.com CRDs to dedicated admin accounts.
• Monitor GCP Audit Logs for Config Connector-initiated resource changes.
• Consider namespace-level Config Connector mode instead of cluster-level.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if r.ClusterObjects.GKEInfo == nil || !r.ClusterObjects.GKEInfo.ConfigConnectorEnabled {
				return "", nil, nil
			}
			var evidence []string
			evidence = append(evidence, fmt.Sprintf("Config Connector CRDs detected: %s",
				strings.Join(r.ClusterObjects.GKEInfo.ConfigConnectorCRDs, ", ")))
			// Check if current identity can create Config Connector resources.
			for ns, rules := range r.Permissions.SSRRByNamespace {
				for _, rule := range rules {
					for _, apiGroup := range rule.APIGroups {
						if strings.Contains(apiGroup, "cnrm.cloud.google.com") {
							evidence = append(evidence, fmt.Sprintf(
								"SSRR: identity has %v on cnrm resources in %q",
								rule.Verbs, ns))
						}
					}
				}
			}
			return "GKE Config Connector is installed, creating a direct bridge from Kubernetes to GCP IAM. " +
				"Any identity with create/update permissions on cnrm.cloud.google.com CRDs can provision or modify " +
				"GCP resources including IAM bindings, service accounts, and compute instances.", evidence, nil
		},
	}
}

func ruleGKEMetadataConcealment() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-GKE-METADATA-CONCEALMENT",
		Severity: SeverityInfo,
		Score:    1.0,
		Title:    "GKE metadata concealment is active — reduced cloud credential exposure",
		Mitigation: `• Metadata concealment blocks pods from accessing the GCE metadata server directly.
• This is a strong control that prevents node credential theft via metadata.
• Verify that Workload Identity is enabled for all workloads that need GCP access.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if r.ClusterObjects.GKEInfo == nil || !r.ClusterObjects.GKEInfo.MetadataConcealment {
				return "", nil, nil
			}
			return "GKE metadata concealment is active on this cluster's nodes. The GCE metadata server " +
				"is blocked or proxied, preventing pods from accessing node-level credentials. This " +
				"significantly reduces the cloud credential theft attack surface.",
				[]string{"Metadata proxy detected via node label cloud.google.com/metadata-proxy-ready=true"}, nil
		},
	}
}

func ruleGCPSAKeysInSecrets() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-GCP-SA-KEY-IN-SECRET",
		Severity: SeverityCritical,
		Score:    9.0,
		Title:    "GCP service account JSON key detected in Kubernetes Secret",
		MITREIDs: []string{"T1552.001", "T1078.004"},
		Mitigation: `• Remove GCP service account JSON keys from Kubernetes Secrets immediately.
• Use GKE Workload Identity instead of long-lived service account keys.
• If keys are required, use External Secrets Operator to rotate them automatically.
• Delete the GCP service account key from the GCP console and regenerate if compromised.
• Enable GCP Organization Policy constraints to prevent key creation.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			if len(r.ClusterObjects.GCPSAKeysInSecrets) == 0 {
				return "", nil, nil
			}
			evidence := make([]string, len(r.ClusterObjects.GCPSAKeysInSecrets))
			copy(evidence, r.ClusterObjects.GCPSAKeysInSecrets)
			return fmt.Sprintf("%d Kubernetes Secret(s) contain GCP service account JSON key files. "+
				"These are long-lived credentials that grant persistent access to GCP resources. "+
				"Unlike Workload Identity tokens, SA keys do not expire and cannot be scoped per-workload.",
				len(evidence)), evidence, nil
		},
	}
}

func ruleIRSATokenExpiration() inferenceRule {
	return inferenceRule{
		RuleID:   "CLOUD-IRSA-TOKEN-NO-EXPIRY",
		Severity: SeverityMedium,
		Score:    5.5,
		Title:    "IRSA projected token with default or long expiration",
		MITREIDs: []string{"T1078.004"},
		Mitigation: `• Set expirationSeconds on projected service account tokens to 3600 (1 hour) or less.
• IRSA tokens with default expiration (24h or more) extend the window for credential theft.
• Configure the minimum audience for STS (sts.amazonaws.com) in projected volumes.
• Monitor CloudTrail for AssumeRoleWithWebIdentity calls with unexpected tokens.`,
		check: func(g *Graph, r *kube.EnumerationResult) (string, []string, []string) {
			var evidence []string
			var nodes []string
			for _, wl := range r.ClusterObjects.Workloads {
				if wl.ServiceAccount == "" {
					continue
				}
				// Check if this SA has IRSA annotation.
				hasIRSA := false
				for _, sa := range r.ClusterObjects.ServiceAccounts {
					if sa.Name == wl.ServiceAccount && sa.Namespace == wl.Namespace && sa.IRSARole != "" {
						hasIRSA = true
						break
					}
				}
				if !hasIRSA {
					continue
				}
				// Check projected token volumes for audience + expiration.
				for _, vol := range wl.Volumes {
					if vol.SourceKind == "Projected" && vol.Audience != "" {
						if strings.Contains(strings.ToLower(vol.Audience), "sts") {
							evidence = append(evidence, fmt.Sprintf(
								"Workload %s/%s has IRSA projected token with audience=%q (check expirationSeconds)",
								wl.Namespace, wl.Name, vol.Audience))
							nodes = append(nodes, "workload:"+wl.Namespace+":"+wl.Name)
						}
					}
				}
			}
			if len(evidence) == 0 {
				return "", nil, nil
			}
			return fmt.Sprintf("%d workload(s) use IRSA with projected tokens. Verify that expirationSeconds "+
				"is set to 3600 or less. Default token expiration (86400s/24h) extends the credential theft window.",
				len(evidence)), evidence, nodes
		},
	}
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
