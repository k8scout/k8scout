package kube

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectIdentity gathers the current identity via TokenReview + in-cluster file.
// When running inside a Kubernetes pod, it also detects the pod name and node name
// to enable foothold-anchored attack path generation.
func collectIdentity(ctx context.Context, c *Client, log *zap.Logger) (IdentityInfo, error) {
	id := IdentityInfo{
		Namespace: c.CurrentNamespace(),
	}

	// Detect in-cluster context: the SA namespace file is only present inside pods.
	nsBytes, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if len(nsBytes) > 0 {
		id.Namespace = strings.TrimSpace(string(nsBytes))
		id.InCluster = true

		// Kubernetes sets HOSTNAME to the pod name for every pod (unless overridden).
		// This is the most reliable way to detect the current pod without extra RBAC.
		if hostname := os.Getenv("HOSTNAME"); hostname != "" {
			id.PodName = hostname
			log.Info("in-cluster: detected pod foothold", zap.String("pod", hostname))
		}

		// MY_NODE_NAME is only set when the pod spec includes the downward API field.
		// Read it opportunistically; absence is not an error.
		if nodeName := os.Getenv("MY_NODE_NAME"); nodeName != "" {
			id.NodeName = nodeName
		}
	}

	username, uid, groups, extra, err := c.WhoAmI(ctx)
	if err != nil {
		log.Warn("WhoAmI/TokenReview denied; deriving identity from SSRR", zap.Error(err))
		// Fall back: run a minimal SSRR and note the username from API server response headers.
		// The username will be populated after SSRR runs if the API server echoes it.
		return id, nil
	}

	id.Username = username
	id.UID = uid
	id.Groups = groups
	id.Extra = extra

	// Parse SA name from "system:serviceaccount:<ns>:<name>" username pattern.
	if parts := strings.Split(username, ":"); len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
		id.Namespace = parts[2]
		id.SAName = parts[3]
	}

	// If we know the pod name, try to resolve the node name and owner workload via API (non-fatal).
	// The SA may lack get-pod permission, which is fine — we just log and continue.
	if id.InCluster && id.PodName != "" {
		if pod, err := c.Clientset().CoreV1().Pods(id.Namespace).Get(ctx, id.PodName, metav1.GetOptions{}); err == nil {
			if id.NodeName == "" {
				id.NodeName = pod.Spec.NodeName
				if id.NodeName != "" {
					log.Info("in-cluster: resolved node for pod", zap.String("node", id.NodeName))
				}
			}
			// Resolve owner workload from owner references.
			for _, ref := range pod.OwnerReferences {
				if ref.Controller != nil && !*ref.Controller {
					continue
				}
				kind, name := ref.Kind, ref.Name
				if kind == "ReplicaSet" {
					kind = "Deployment"
					if idx := lastNthIndex(name, '-', 2); idx > 0 {
						name = name[:idx]
					}
				}
				id.OwnerWorkload = name
				id.OwnerWorkloadKind = kind
				log.Info("in-cluster: resolved owner workload",
					zap.String("kind", kind), zap.String("name", name))
				break
			}
		} else {
			log.Debug("could not resolve pod info (get pod permission may be missing)", zap.Error(err))
		}
	}

	return id, nil
}

// collectSSRR runs a SelfSubjectRulesReview for a given namespace and returns policy rules.
func collectSSRR(ctx context.Context, c *Client, namespace string, log *zap.Logger) ([]PolicyRule, error) {
	callCtx, callCancel := context.WithTimeout(ctx, 10*time.Second)
	defer callCancel()
	review, err := c.SSRR(callCtx, namespace)
	if err != nil {
		return nil, fmt.Errorf("SSRR for namespace %q: %w", namespace, err)
	}

	if review.Status.Incomplete {
		log.Warn("SSRR result marked incomplete (superuser or too many rules)",
			zap.String("namespace", namespace),
			zap.String("reason", review.Status.EvaluationError))
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

	for _, r := range review.Status.NonResourceRules {
		pr := PolicyRule{
			Verbs:           nonEmpty(r.Verbs),
			NonResourceURLs: nonEmpty(r.NonResourceURLs),
		}
		rules = append(rules, pr)
	}

	log.Debug("SSRR complete", zap.String("namespace", namespace), zap.Int("rules", len(rules)))
	return rules, nil
}

// ssarSpotChecks defines the high-risk permission checks to validate.
var ssarSpotChecks = []struct {
	Verb        string
	Resource    string
	Subresource string
}{
	{"list",        "secrets",             ""},
	{"get",         "secrets",             ""},
	{"create",      "pods",                ""},
	{"delete",      "pods",                ""},
	{"get",         "pods",                "log"},
	{"create",      "pods",                "exec"},
	{"create",      "pods",                "portforward"},
	{"impersonate", "users",               ""},
	{"impersonate", "serviceaccounts",     ""},
	{"create",      "rolebindings",        ""},
	{"create",      "clusterrolebindings", ""},
	{"patch",       "deployments",         ""},
	{"patch",       "daemonsets",          ""},
	{"patch",       "statefulsets",        ""},
	{"patch",       "pods",                ""},
	{"create",      "serviceaccounts",     "token"},
	{"list",        "nodes",               ""},
	{"get",         "nodes",               ""},
	{"create",      "namespaces",          ""},
	{"delete",      "namespaces",          ""},
	{"patch",       "clusterroles",        ""},
	{"patch",       "clusterrolebindings", ""},
	// Escalation control verbs — allow creating bindings/roles beyond current permissions.
	{"escalate",    "clusterroles",        ""},
	{"bind",        "clusterroles",        ""},
	{"bind",        "clusterrolebindings", ""},
	// ConfigMap read — may contain leaked kubeconfig or credentials.
	{"get",         "configmaps",          ""},
	// Pod attach — similar to exec, attaches to a running container.
	{"create",      "pods",                "attach"},
	// Webhook mutation — can inject into all future workloads.
	{"patch",       "mutatingwebhookconfigurations", ""},
	{"create",      "mutatingwebhookconfigurations", ""},
}

// collectSSAR runs all spot-check SSARs across all provided namespaces.
// For cluster-scoped resources it uses namespace="" once.
func collectSSAR(ctx context.Context, c *Client, namespaces []string, log *zap.Logger) []SSARCheck {
	clusterScopedResources := map[string]bool{
		"nodes": true, "namespaces": true,
		"clusterroles": true, "clusterrolebindings": true,
		"users": true,
		"mutatingwebhookconfigurations": true,
	}

	// Build the list of checks to run, deduplicating cluster-scoped entries.
	type ssarJob struct {
		Verb, Resource, Subresource, Namespace string
	}
	var jobs []ssarJob
	seen := map[string]bool{}

	for _, ns := range namespaces {
		for _, sc := range ssarSpotChecks {
			if clusterScopedResources[sc.Resource] {
				key := fmt.Sprintf("%s/%s/%s", sc.Verb, sc.Resource, sc.Subresource)
				if seen[key] {
					continue
				}
				seen[key] = true
				jobs = append(jobs, ssarJob{sc.Verb, sc.Resource, sc.Subresource, ""})
			} else {
				jobs = append(jobs, ssarJob{sc.Verb, sc.Resource, sc.Subresource, ns})
			}
		}
	}

	// Run all SSAR checks concurrently with a per-call timeout.
	type ssarResult struct {
		check SSARCheck
		err   error
	}
	results := make(chan ssarResult, len(jobs))

	for _, j := range jobs {
		go func(j ssarJob) {
			callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
			defer callCancel()

			allowed, reason, err := c.SSAR(callCtx, j.Verb, j.Resource, j.Subresource, j.Namespace)
			if err != nil {
				results <- ssarResult{err: err}
				return
			}
			results <- ssarResult{check: SSARCheck{
				Verb: j.Verb, Resource: j.Resource, Subresource: j.Subresource,
				Namespace: j.Namespace, Allowed: allowed, Reason: reason,
			}}
		}(j)
	}

	var checks []SSARCheck
	for range jobs {
		r := <-results
		if r.err != nil {
			log.Debug("SSAR check failed", zap.Error(r.err))
			continue
		}
		checks = append(checks, r.check)
	}

	log.Info("SSAR spot checks complete", zap.Int("total", len(jobs)), zap.Int("succeeded", len(checks)))
	return checks
}

// nonEmpty returns the slice if non-nil, else nil (avoids empty JSON arrays).
func nonEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	// Replace wildcard marker for clarity in output.
	out := make([]string, len(s))
	copy(out, s)
	return out
}

