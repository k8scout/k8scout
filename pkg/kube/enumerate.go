package kube

import (
	"context"
	"strings"

	"go.uber.org/zap"
)

// Enumerate orchestrates all collectors and returns a combined EnumerationResult.
// Errors from individual collectors are logged and do not abort the run.
func Enumerate(ctx context.Context, c *Client, opts EnumerateOptions) (*EnumerationResult, error) {
	log := opts.Log

	result := &EnumerationResult{
		Permissions: PermissionsInfo{
			SSRRByNamespace: make(map[string][]PolicyRule),
		},
	}

	// ── Identity ─────────────────────────────────────────────────────────────
	log.Info("collecting identity")
	id, err := collectIdentity(ctx, c, log)
	if err != nil {
		log.Warn("identity collection partial", zap.Error(err))
	}
	result.Identity = id

	// ── Namespaces ────────────────────────────────────────────────────────────
	log.Info("collecting namespaces")
	nsList, err := collectNamespaces(ctx, c, log)
	if err != nil {
		log.Warn("namespace collection failed", zap.Error(err))
	}
	result.ClusterObjects.Namespaces = nsList

	// ── Permissions: SSRR per namespace ──────────────────────────────────────
	if opts.Stealth {
		log.Info("stealth mode: skipping SelfSubjectRulesReview")
		result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
			Action:     "SelfSubjectRulesReview (per namespace)",
			Count:      len(opts.Namespaces),
			Skipped:    true,
			NoiseLevel: "high",
		})
	} else {
		log.Info("running SelfSubjectRulesReview", zap.Strings("namespaces", opts.Namespaces))
		for _, ns := range opts.Namespaces {
			rules, err := collectSSRR(ctx, c, ns, log)
			if err != nil {
				log.Warn("SSRR failed", zap.String("namespace", ns), zap.Error(err))
				continue
			}
			result.Permissions.SSRRByNamespace[ns] = rules
		}
		result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
			Action:     "SelfSubjectRulesReview (per namespace)",
			Count:      len(opts.Namespaces),
			Skipped:    false,
			NoiseLevel: "high",
		})
	}

	// ── Permissions: SSAR spot checks ─────────────────────────────────────────
	skipSSAR := opts.SkipSSAR || opts.Stealth
	if skipSSAR {
		if opts.Stealth {
			log.Info("stealth mode: skipping SSAR spot checks")
		}
		result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
			Action:     "SelfSubjectAccessReview spot checks",
			Count:      0,
			Skipped:    true,
			NoiseLevel: "high",
		})
	} else {
		log.Info("running SSAR spot checks")
		checks := collectSSAR(ctx, c, opts.Namespaces, log)
		result.Permissions.SSARChecks = checks
		result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
			Action:     "SelfSubjectAccessReview spot checks",
			Count:      len(checks),
			Skipped:    false,
			NoiseLevel: "high",
		})
	}

	// ── RBAC ──────────────────────────────────────────────────────────────────
	log.Info("collecting RBAC objects")
	rbac, err := collectRBAC(ctx, c, opts.Namespaces, log)
	if err != nil {
		log.Warn("RBAC collection partial", zap.Error(err))
	}
	result.ClusterObjects.ClusterRoles = rbac.ClusterRoles
	result.ClusterObjects.ClusterRoleBindings = rbac.ClusterRoleBindings
	result.ClusterObjects.Roles = rbac.Roles
	result.ClusterObjects.RoleBindings = rbac.RoleBindings
	result.ClusterObjects.ServiceAccounts = rbac.ServiceAccounts

	// ── Workloads & Pods ──────────────────────────────────────────────────────
	log.Info("collecting workloads and pods")
	for _, ns := range opts.Namespaces {
		wl, err := collectWorkloads(ctx, c, ns, log)
		if err != nil {
			log.Warn("workload collection failed", zap.String("namespace", ns), zap.Error(err))
			continue
		}
		result.ClusterObjects.Workloads = append(result.ClusterObjects.Workloads, wl...)

		pods, err := collectPods(ctx, c, ns, log)
		if err != nil {
			log.Warn("pod collection failed", zap.String("namespace", ns), zap.Error(err))
			continue
		}
		result.ClusterObjects.Pods = append(result.ClusterObjects.Pods, pods...)
	}

	// ── Secrets metadata (+ values when GET permission confirmed) ─────────────
	log.Info("collecting secrets (values captured when GET permission confirmed)")
	for _, ns := range opts.Namespaces {
		canGetSecrets := ssarNsAllows(result.Permissions.SSARChecks, "get", "secrets", ns)
		if canGetSecrets {
			log.Info("GET secrets allowed — capturing values", zap.String("namespace", ns))
		}
		sm, err := collectSecretsMeta(ctx, c, ns, canGetSecrets, log)
		if err != nil {
			log.Warn("secret collection failed", zap.String("namespace", ns), zap.Error(err))
			continue
		}
		result.ClusterObjects.SecretsMeta = append(result.ClusterObjects.SecretsMeta, sm...)

		canGetCMs := ssarNsAllows(result.Permissions.SSARChecks, "get", "configmaps", ns)
		if canGetCMs {
			log.Info("GET configmaps allowed — capturing data", zap.String("namespace", ns))
		}
		cm, err := collectConfigMapsMeta(ctx, c, ns, canGetCMs, log)
		if err != nil {
			log.Warn("configmap collection failed", zap.String("namespace", ns), zap.Error(err))
			continue
		}
		result.ClusterObjects.ConfigMapsMeta = append(result.ClusterObjects.ConfigMapsMeta, cm...)
	}

	// ── Nodes ─────────────────────────────────────────────────────────────────
	log.Info("collecting node metadata")
	nodes, err := collectNodes(ctx, c, log)
	if err != nil {
		log.Warn("node collection failed (permission likely missing)", zap.Error(err))
	}
	result.ClusterObjects.Nodes = nodes

	// ── Admission Webhooks ────────────────────────────────────────────────────
	log.Info("collecting admission webhook configurations")
	webhooks, err := collectWebhooks(ctx, c, log)
	if err != nil {
		log.Warn("webhook collection failed (permission likely missing)", zap.Error(err))
	}
	result.ClusterObjects.Webhooks = webhooks
	result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
		Action:     "List MutatingWebhookConfigurations + ValidatingWebhookConfigurations",
		Count:      len(webhooks),
		Skipped:    false,
		NoiseLevel: "low",
	})

	// ── Operator CRDs ─────────────────────────────────────────────────────────
	log.Info("discovering operator CRDs via Discovery API")
	crds, err := collectCRDs(ctx, c, log)
	if err != nil {
		log.Warn("CRD collection failed", zap.Error(err))
	}
	result.ClusterObjects.CRDs = crds
	result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
		Action:     "Discovery API ServerGroups + ServerResourcesForGroupVersion",
		Count:      len(crds),
		Skipped:    false,
		NoiseLevel: "low",
	})

	// ── Active enrichment: derived identity permissions ──────────────────────
	// When the current identity can impersonate other SAs, run SSRR as each
	// reachable SA to discover their permissions. This enables multi-level
	// attack path construction: pod → SA₁ → workload → SA₂ → SA₂'s targets.
	if !opts.Stealth {
		log.Info("running active enrichment for derived identities")
		derived := EnrichDerivedIdentities(ctx, c, result, log)
		result.DerivedIdentities = derived
		enrichCount := 0
		if derived != nil {
			enrichCount = len(derived)
		}
		result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
			Action:     "SSRR via impersonation (derived identities)",
			Count:      enrichCount,
			Skipped:    false,
			NoiseLevel: "high",
		})
	} else {
		log.Info("stealth mode: skipping active enrichment")
		result.AuditFootprint = append(result.AuditFootprint, AuditEntry{
			Action:     "SSRR via impersonation (derived identities)",
			Count:      0,
			Skipped:    true,
			NoiseLevel: "high",
		})
	}

	return result, nil
}

// ssarNsAllows returns true if the SSAR result set contains an allowed check for verb+resource in namespace.
func ssarNsAllows(checks []SSARCheck, verb, resource, ns string) bool {
	for _, c := range checks {
		if c.Allowed && c.Verb == verb && c.Resource == resource && c.Namespace == ns {
			return true
		}
	}
	return false
}

// nodeRoles extracts the Kubernetes role labels into role names (master, worker, etc.).
func nodeRoles(labels map[string]string) []string {
	var roles []string
	for k := range labels {
		if strings.HasPrefix(k, "node-role.kubernetes.io/") {
			roles = append(roles, strings.TrimPrefix(k, "node-role.kubernetes.io/"))
		}
	}
	return roles
}
