package kube

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// DerivedIdentity represents a ServiceAccount whose permissions were discovered
// via impersonation during the active enrichment phase.
type DerivedIdentity struct {
	// SAName is the ServiceAccount name (e.g. "coredns").
	SAName string `json:"sa_name"`
	// Namespace is the SA's namespace.
	Namespace string `json:"namespace"`
	// Username is the full Kubernetes username (system:serviceaccount:<ns>:<name>).
	Username string `json:"username"`
	// How is a description of how this identity was discovered as reachable.
	How string `json:"how"`
	// SSRRRules contains the SA's permissions discovered via impersonated SSRR.
	SSRRRules map[string][]PolicyRule `json:"ssrr_rules,omitempty"`
}

// maxDerivedIdentities caps the number of SAs we try to enrich to prevent
// excessive API calls on large clusters.
const maxDerivedIdentities = 20

// EnrichDerivedIdentities discovers ServiceAccounts reachable from the current
// identity through workload takeover (patch), exec, impersonation, or token
// creation, and runs SSRR as each one via impersonation to discover their
// permissions.
//
// This is the "enumeration after progression" step: after the base graph is
// built, we know which SAs we can "become." For each one, we ask the API
// server what THAT SA can do, creating the data needed for multi-level attack
// path construction.
//
// Prerequisites:
//   - The current identity must have "impersonate" permission on serviceaccounts
//     (confirmed by SSAR spot checks)
//   - Only runs when impersonation is available; silently returns nil otherwise
//
// The function performs iterative deepening: SAs discovered at depth N whose
// permissions reveal access to further SAs are enriched at depth N+1.
func EnrichDerivedIdentities(
	ctx context.Context,
	c *Client,
	result *EnumerationResult,
	log *zap.Logger,
) []DerivedIdentity {
	// Check if we can impersonate serviceaccounts.
	canImpersonate := false
	canCreateTokens := false
	for _, check := range result.Permissions.SSARChecks {
		if !check.Allowed {
			continue
		}
		if check.Resource == "serviceaccounts" && check.Verb == "impersonate" {
			canImpersonate = true
		}
		if check.Resource == "serviceaccounts" && check.Subresource == "token" && check.Verb == "create" {
			canCreateTokens = true
		}
	}

	// Also check SSRR for impersonation permissions.
	if !canImpersonate {
		for _, rules := range result.Permissions.SSRRByNamespace {
			for _, rule := range rules {
				if containsAny(rule.Verbs, "impersonate", "*") &&
					containsAny(rule.Resources, "serviceaccounts", "users", "*") {
					canImpersonate = true
					break
				}
			}
			if canImpersonate {
				break
			}
		}
	}

	// Gather any captured SA-token secrets for token-based enrichment, which
	// works without impersonation permission.
	capturedTokens := collectCapturedSATokens(result)

	if !canImpersonate {
		if canCreateTokens {
			log.Info("active enrichment: can create SA tokens but not impersonate — " +
				"impersonation required for SSRR enrichment")
		}
		if len(capturedTokens) > 0 {
			log.Info("active enrichment: no impersonation but captured SA tokens available — using token-based enrichment",
				zap.Int("tokens", len(capturedTokens)))
			return enrichViaCapturedTokens(ctx, c, result, capturedTokens, log)
		}
		return nil
	}

	log.Info("active enrichment: impersonation available, discovering derived identities")

	// Collect all SAs reachable through the current identity's permissions.
	// These are SAs we can "become" via workload takeover, exec, or direct impersonation.
	type derivedSA struct {
		ns, name, how string
	}

	discovered := make(map[string]derivedSA) // key: "ns/name"

	// 1. SAs from workloads we can patch (takeover → inject code as that SA).
	patchableNS := make(map[string]bool)
	for _, check := range result.Permissions.SSARChecks {
		if !check.Allowed {
			continue
		}
		if check.Verb == "patch" && (check.Resource == "deployments" ||
			check.Resource == "daemonsets" || check.Resource == "statefulsets") {
			patchableNS[check.Namespace] = true
		}
	}
	for _, wl := range result.ClusterObjects.Workloads {
		if patchableNS[wl.Namespace] && wl.ServiceAccount != "" {
			key := wl.Namespace + "/" + wl.ServiceAccount
			if _, ok := discovered[key]; !ok {
				discovered[key] = derivedSA{
					ns:   wl.Namespace,
					name: wl.ServiceAccount,
					how:  fmt.Sprintf("patch %s/%s (%s)", wl.Namespace, wl.Name, wl.Kind),
				}
			}
		}
	}

	// 2. SAs from pods we can exec into.
	execNS := make(map[string]bool)
	for _, check := range result.Permissions.SSARChecks {
		if check.Allowed && check.Resource == "pods" &&
			check.Subresource == "exec" && check.Verb == "create" {
			execNS[check.Namespace] = true
		}
	}
	for _, pod := range result.ClusterObjects.Pods {
		if execNS[pod.Namespace] && pod.ServiceAccount != "" {
			key := pod.Namespace + "/" + pod.ServiceAccount
			if _, ok := discovered[key]; !ok {
				discovered[key] = derivedSA{
					ns:   pod.Namespace,
					name: pod.ServiceAccount,
					how:  fmt.Sprintf("exec into pod %s/%s", pod.Namespace, pod.Name),
				}
			}
		}
	}

	// 3. All enumerated SAs (since we can impersonate any SA).
	for _, sa := range result.ClusterObjects.ServiceAccounts {
		key := sa.Namespace + "/" + sa.Name
		if _, ok := discovered[key]; !ok {
			discovered[key] = derivedSA{
				ns:   sa.Namespace,
				name: sa.Name,
				how:  "direct impersonation",
			}
		}
	}

	// Skip the current SA (we already have its permissions).
	currentSAKey := result.Identity.Namespace + "/" + result.Identity.SAName
	delete(discovered, currentSAKey)

	if len(discovered) == 0 {
		log.Info("active enrichment: no derived SAs discovered")
		return nil
	}

	// Cap to prevent excessive API calls.
	toEnrich := make([]derivedSA, 0, len(discovered))
	for _, sa := range discovered {
		toEnrich = append(toEnrich, sa)
		if len(toEnrich) >= maxDerivedIdentities {
			break
		}
	}

	log.Info("active enrichment: running SSRR for derived identities",
		zap.Int("count", len(toEnrich)),
		zap.Int("total_discovered", len(discovered)))

	// Determine namespaces to run SSRR against.
	// Use the same namespaces the main enumeration used.
	var nsToCheck []string
	for _, ns := range result.ClusterObjects.Namespaces {
		nsToCheck = append(nsToCheck, ns.Name)
	}
	if len(nsToCheck) == 0 {
		nsToCheck = []string{result.Identity.Namespace}
	}

	var enriched []DerivedIdentity

	for _, sa := range toEnrich {
		username := fmt.Sprintf("system:serviceaccount:%s:%s", sa.ns, sa.name)

		di := DerivedIdentity{
			SAName:    sa.name,
			Namespace: sa.ns,
			Username:  username,
			How:       sa.how,
			SSRRRules: make(map[string][]PolicyRule),
		}

		hasRules := false

		for _, ns := range nsToCheck {
			callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
			review, err := c.SSRRAs(callCtx, username, ns)
			callCancel()

			if err != nil {
				// Impersonation might be denied for this specific SA.
				// Log once and skip remaining namespaces for this SA.
				log.Debug("SSRR-as failed for derived identity",
					zap.String("sa", username),
					zap.String("namespace", ns),
					zap.Error(err))
				break
			}

			rules := make([]PolicyRule, 0, len(review.Status.ResourceRules))
			for _, r := range review.Status.ResourceRules {
				pr := PolicyRule{
					Verbs:         nonEmpty(r.Verbs),
					APIGroups:     nonEmpty(r.APIGroups),
					Resources:     nonEmpty(r.Resources),
					ResourceNames: nonEmpty(r.ResourceNames),
				}
				rules = append(rules, pr)
			}

			if len(rules) > 0 {
				di.SSRRRules[ns] = rules
				hasRules = true
			}
		}

		if hasRules {
			enriched = append(enriched, di)
			log.Info("enriched derived identity",
				zap.String("sa", username),
				zap.String("via", sa.how),
				zap.Int("namespaces_with_rules", len(di.SSRRRules)))
		}
	}

	log.Info("active enrichment complete",
		zap.Int("enriched", len(enriched)),
		zap.Int("attempted", len(toEnrich)))

	return enriched
}

// capturedToken pairs an SA-token's raw bearer value with its owning SA.
type capturedToken struct {
	saName, namespace, token, secretName string
}

// collectCapturedSATokens walks captured secret values and returns any
// kubernetes.io/service-account-token secrets whose "token" key has been
// captured. Returned tokens can be replayed to authenticate as the owning SA.
func collectCapturedSATokens(result *EnumerationResult) []capturedToken {
	var out []capturedToken
	for _, sm := range result.ClusterObjects.SecretsMeta {
		if sm.Type != "kubernetes.io/service-account-token" {
			continue
		}
		if sm.SAName == "" {
			continue
		}
		tok, ok := sm.Values["token"]
		if !ok || tok == "" {
			continue
		}
		out = append(out, capturedToken{
			saName:     sm.SAName,
			namespace:  sm.Namespace,
			token:      tok,
			secretName: sm.Name,
		})
	}
	return out
}

// enrichViaCapturedTokens runs SSRR as each captured SA token, discovering
// that SA's permissions without needing impersonation rights.
func enrichViaCapturedTokens(
	ctx context.Context,
	c *Client,
	result *EnumerationResult,
	tokens []capturedToken,
	log *zap.Logger,
) []DerivedIdentity {
	// Determine namespaces to probe.
	var nsToCheck []string
	for _, ns := range result.ClusterObjects.Namespaces {
		nsToCheck = append(nsToCheck, ns.Name)
	}
	if len(nsToCheck) == 0 {
		nsToCheck = []string{result.Identity.Namespace}
	}

	// Cap to prevent excessive API calls on large clusters.
	if len(tokens) > maxDerivedIdentities {
		tokens = tokens[:maxDerivedIdentities]
	}

	var enriched []DerivedIdentity
	currentSAKey := result.Identity.Namespace + "/" + result.Identity.SAName

	for _, t := range tokens {
		// Skip the current SA — its permissions are already known.
		if t.namespace+"/"+t.saName == currentSAKey {
			continue
		}

		username := fmt.Sprintf("system:serviceaccount:%s:%s", t.namespace, t.saName)
		di := DerivedIdentity{
			SAName:    t.saName,
			Namespace: t.namespace,
			Username:  username,
			How:       fmt.Sprintf("captured SA-token secret %s/%s", t.namespace, t.secretName),
			SSRRRules: make(map[string][]PolicyRule),
		}

		hasRules := false
		for _, ns := range nsToCheck {
			callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
			review, err := c.SSRRWithToken(callCtx, t.token, ns)
			callCancel()

			if err != nil {
				log.Debug("token-based SSRR failed",
					zap.String("sa", username),
					zap.String("namespace", ns),
					zap.Error(err))
				break
			}

			rules := make([]PolicyRule, 0, len(review.Status.ResourceRules))
			for _, r := range review.Status.ResourceRules {
				rules = append(rules, PolicyRule{
					Verbs:         nonEmpty(r.Verbs),
					APIGroups:     nonEmpty(r.APIGroups),
					Resources:     nonEmpty(r.Resources),
					ResourceNames: nonEmpty(r.ResourceNames),
				})
			}

			if len(rules) > 0 {
				di.SSRRRules[ns] = rules
				hasRules = true
			}
		}

		if hasRules {
			enriched = append(enriched, di)
			log.Info("enriched derived identity via captured token",
				zap.String("sa", username),
				zap.Int("namespaces_with_rules", len(di.SSRRRules)))
		}
	}

	log.Info("token-based enrichment complete",
		zap.Int("enriched", len(enriched)),
		zap.Int("tokens", len(tokens)))

	return enriched
}

// containsAny returns true if any value in vals appears in slice s.
func containsAny(s []string, vals ...string) bool {
	for _, item := range s {
		for _, v := range vals {
			if item == v {
				return true
			}
		}
	}
	return false
}
