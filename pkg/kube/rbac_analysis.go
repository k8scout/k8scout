package kube

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ComputeAllEffectivePermissions derives effective RBAC rules for every non-system subject
// found across all ClusterRoleBindings and RoleBindings.
//
// This is the reviewer-mode equivalent of per-identity SSRR: instead of asking "what can I do?",
// it computes "what can every SA/user do?" purely from RBAC definitions — no SSRR API calls needed.
//
// Minimum required cluster permissions:
//
//	get,list on: ClusterRoles, ClusterRoleBindings, Roles, RoleBindings
func ComputeAllEffectivePermissions(
	clusterRoles []RoleInfo,
	clusterRoleBindings []BindingInfo,
	roles []RoleInfo,
	roleBindings []BindingInfo,
	log *zap.Logger,
) []IdentityPermissions {
	// Build lookup maps for fast role resolution.
	crRules := make(map[string][]PolicyRule, len(clusterRoles))
	for _, cr := range clusterRoles {
		crRules[cr.Name] = cr.Rules
	}
	rRules := make(map[string][]PolicyRule, len(roles))
	for _, r := range roles {
		rRules[r.Namespace+"/"+r.Name] = r.Rules
	}

	// Collect unique subjects and all their bindings.
	type subjKey struct{ kind, ns, name string }
	type bnd struct {
		ref         RoleRef
		bindingNS   string // empty = cluster-scoped CRB
		bindingName string
	}
	sbMap := make(map[subjKey][]bnd)

	for _, crb := range clusterRoleBindings {
		for _, s := range crb.Subjects {
			if skipReviewSubject(s) {
				continue
			}
			sk := subjKey{s.Kind, s.Namespace, s.Name}
			sbMap[sk] = append(sbMap[sk], bnd{crb.RoleRef, "", crb.Name})
		}
	}
	for _, rb := range roleBindings {
		for _, s := range rb.Subjects {
			if skipReviewSubject(s) {
				continue
			}
			sk := subjKey{s.Kind, s.Namespace, s.Name}
			sbMap[sk] = append(sbMap[sk], bnd{rb.RoleRef, rb.Namespace, rb.Name})
		}
	}

	result := make([]IdentityPermissions, 0, len(sbMap))
	for sk, bindings := range sbMap {
		var rules []PolicyRule
		var boundRoles []string

		for _, b := range bindings {
			if b.ref.Kind == "ClusterRole" {
				rules = append(rules, crRules[b.ref.Name]...)
				boundRoles = append(boundRoles, fmt.Sprintf("ClusterRole/%s (via %s)", b.ref.Name, b.bindingName))
			} else {
				key := b.bindingNS + "/" + b.ref.Name
				rules = append(rules, rRules[key]...)
				boundRoles = append(boundRoles,
					fmt.Sprintf("Role/%s/%s (via %s)", b.bindingNS, b.ref.Name, b.bindingName))
			}
		}

		ip := IdentityPermissions{
			SubjectKind: sk.kind,
			Namespace:   sk.ns,
			Name:        sk.name,
			BoundRoles:  dedupStrings(boundRoles),
			Rules:       rules,
		}
		switch sk.kind {
		case "ServiceAccount":
			ip.Subject = fmt.Sprintf("system:serviceaccount:%s:%s", sk.ns, sk.name)
		case "User":
			ip.Subject = "user:" + sk.name
		case "Group":
			ip.Subject = "group:" + sk.name
		default:
			ip.Subject = sk.name
		}
		result = append(result, ip)
	}

	log.Info("computed effective RBAC permissions", zap.Int("subjects", len(result)))
	return result
}

// skipReviewSubject returns true for built-in system users/groups we don't enumerate individually.
// ServiceAccounts are always analyzed (even in kube-system) since a misconfigured SA is still a risk.
func skipReviewSubject(s Subject) bool {
	if s.Kind == "ServiceAccount" {
		return false
	}
	// Skip system: users/groups — these are kubelets, controllers, system:masters, etc.
	return strings.HasPrefix(s.Name, "system:")
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
