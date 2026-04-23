package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

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
