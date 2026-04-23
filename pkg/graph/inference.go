// Package graph: inference orchestrators.
//
// This file wires together the rule registry and the reviewer-mode analysis.
// Individual rule implementations live in:
//   - inference_rules_rbac.go      (RBAC/escalation/takeover rules)
//   - inference_rules_security.go  (pod/workload security-config rules)
//   - inference_rules_advanced.go  (cloud, operator, webhook rules)
// Shared helpers live in inference_helpers.go.
// Shared types live in inference_types.go.
package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)

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
		ruleWebhookBackendTakeover(),
	}
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
