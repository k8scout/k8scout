package graph

import (
	"strings"
	"testing"

	"github.com/hac01/k8scout/pkg/kube"
)

// newEnumeration returns a zero-value EnumerationResult with initialized maps,
// ready for test cases to populate specific fields.
func newEnumeration() *kube.EnumerationResult {
	return &kube.EnumerationResult{
		Permissions: kube.PermissionsInfo{
			SSRRByNamespace: map[string][]kube.PolicyRule{},
		},
	}
}

// allowSSAR constructs a "verb on resource in namespace = allowed" SSAR check.
// Subresource is empty; use allowSSARSub for subresource-scoped checks.
func allowSSAR(verb, resource, ns string) kube.SSARCheck {
	return kube.SSARCheck{
		Verb:      verb,
		Resource:  resource,
		Namespace: ns,
		Allowed:   true,
	}
}

// allowSSARSub is allowSSAR with a subresource (e.g. pods/exec, serviceaccounts/token).
func allowSSARSub(verb, resource, subresource, ns string) kube.SSARCheck {
	return kube.SSARCheck{
		Verb:        verb,
		Resource:    resource,
		Subresource: subresource,
		Namespace:   ns,
		Allowed:     true,
	}
}

// denySSAR is the rejected counterpart — same fields but Allowed=false.
func denySSAR(verb, resource, ns string) kube.SSARCheck {
	c := allowSSAR(verb, resource, ns)
	c.Allowed = false
	return c
}

// assertRuleFires validates that the rule returned a non-empty description and
// pins the rule's identity metadata (ID, severity, score). Returns evidence and
// affected nodes for further assertions.
func assertRuleFires(t *testing.T, rule inferenceRule, r *kube.EnumerationResult,
	wantID string, wantSev Severity, wantScore float64,
) (desc string, evidence, nodes []string) {
	t.Helper()
	desc, evidence, nodes = rule.check(&Graph{}, r)
	if desc == "" {
		t.Fatalf("rule %s: expected to fire, got empty desc", wantID)
	}
	if rule.RuleID != wantID {
		t.Errorf("rule ID: got %q, want %q", rule.RuleID, wantID)
	}
	if rule.Severity != wantSev {
		t.Errorf("rule %s severity: got %s, want %s", wantID, rule.Severity, wantSev)
	}
	if rule.Score != wantScore {
		t.Errorf("rule %s score: got %v, want %v", wantID, rule.Score, wantScore)
	}
	return desc, evidence, nodes
}

// assertRuleSilent validates the rule does not fire (returns empty desc).
func assertRuleSilent(t *testing.T, rule inferenceRule, r *kube.EnumerationResult) {
	t.Helper()
	desc, evidence, nodes := rule.check(&Graph{}, r)
	if desc != "" {
		t.Fatalf("rule %s: expected silent, got desc=%q evidence=%v nodes=%v",
			rule.RuleID, desc, evidence, nodes)
	}
}

// assertAnyEvidenceContains confirms at least one evidence line contains the substring.
func assertAnyEvidenceContains(t *testing.T, evidence []string, substr string) {
	t.Helper()
	for _, e := range evidence {
		if strings.Contains(e, substr) {
			return
		}
	}
	t.Errorf("no evidence line contains %q; got: %v", substr, evidence)
}
