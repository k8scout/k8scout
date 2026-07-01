package kube

import (
	"bufio"
	"context"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ReconResult is the lightweight "recon" output: who you are, what permissions you
// hold, which resources you can touch, and (optionally) namespaces discovered by
// bruteforce. It deliberately skips graph building, inference, and AI narrative.
type ReconResult struct {
	Identity        IdentityInfo            `json:"identity"`
	Namespaces      []string                `json:"namespaces"`
	SSRRByNamespace map[string][]PolicyRule `json:"ssrr_by_namespace,omitempty"`
	Capabilities    []ResourceAccess        `json:"capabilities,omitempty"`
	NamespaceProbes []NamespaceProbe        `json:"namespace_probes,omitempty"`
}

// ResourceAccess records which verbs the current identity may perform on a resource type.
// Only resources with at least one allowed verb are recorded.
type ResourceAccess struct {
	Resource     string   `json:"resource"`
	Namespace    string   `json:"namespace,omitempty"` // empty for cluster-scoped
	ClusterScope bool     `json:"cluster_scope,omitempty"`
	AllowedVerbs []string `json:"allowed_verbs,omitempty"`
}

// NamespaceProbe records the result of probing a candidate namespace during bruteforce.
type NamespaceProbe struct {
	Namespace string `json:"namespace"`
	// Status is one of:
	//   "confirmed" — a well-known object was read; the namespace exists and is (partly) readable.
	//   "forbidden" — a probe returned 403; the namespace may exist but access is denied.
	//   "not_found" — every probe returned 404; the namespace likely does not exist.
	Status   string `json:"status"`
	Method   string `json:"method,omitempty"`   // which probe confirmed existence
	Readable bool   `json:"readable,omitempty"` // true if a well-known object was successfully read
}

// ReconOptions configures a Recon run.
type ReconOptions struct {
	Namespaces        []string
	BruteforceNS      bool
	NamespaceWordlist []string
	SkipSSRR          bool
	SkipCapabilities  bool
	Log               *zap.Logger
}

// DefaultNamespaceWordlist is the built-in candidate list used when bruteforcing
// namespaces without a user-supplied wordlist. It covers Kubernetes system
// namespaces plus common operator, CI/CD, monitoring, and platform namespaces.
var DefaultNamespaceWordlist = []string{
	"default", "kube-system", "kube-public", "kube-node-lease",
	"kubernetes-dashboard", "local-path-storage",
	// Platform / service mesh
	"istio-system", "istio-ingress", "linkerd", "consul", "cilium", "calico-system",
	"tigera-operator", "kube-flannel", "metallb-system",
	// Ingress / cert
	"ingress-nginx", "nginx-ingress", "traefik", "cert-manager", "external-dns",
	// GitOps / CI-CD
	"argocd", "argo", "argo-events", "argo-rollouts", "flux-system", "fluxcd",
	"jenkins", "gitlab", "gitlab-runner", "tekton-pipelines", "spinnaker",
	// Observability
	"monitoring", "prometheus", "grafana", "loki", "tempo", "thanos",
	"logging", "elastic-system", "elasticsearch", "kibana", "fluentd",
	"jaeger", "datadog", "newrelic", "sentry",
	// Secrets / identity / policy
	"vault", "external-secrets", "sealed-secrets", "cert-manager",
	"keycloak", "dex", "oauth2-proxy", "gatekeeper-system", "kyverno", "falco",
	// Data / messaging
	"kafka", "rabbitmq", "redis", "postgres", "postgresql", "mysql", "mongodb",
	"cassandra", "elasticsearch", "minio", "rook-ceph",
	// Cloud provider add-ons
	"aws-observability", "amazon-cloudwatch", "karpenter", "kube-system",
	"gke-system", "gmp-system", "config-management-system",
	"azure-system", "gatekeeper-system",
	// App / environment
	"app", "apps", "application", "backend", "frontend", "api", "web",
	"dev", "development", "staging", "stage", "qa", "test", "testing",
	"prod", "production", "sandbox", "demo", "internal", "tools", "ci", "cd",
	"security", "platform", "infra", "infrastructure", "system", "admin",
}

// LoadNamespaceWordlist reads candidate namespace names from a file (one per line,
// blank lines and lines beginning with '#' are ignored).
func LoadNamespaceWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// Recon runs the lightweight recon flow: identity, optional namespace bruteforce,
// effective permissions (SSRR), and a resource-access capability matrix (SSAR).
func Recon(ctx context.Context, c *Client, opts ReconOptions) *ReconResult {
	log := opts.Log
	res := &ReconResult{SSRRByNamespace: make(map[string][]PolicyRule)}

	// ── Identity ──────────────────────────────────────────────────────────────
	log.Info("collecting identity")
	id, err := collectIdentity(ctx, c, log)
	if err != nil {
		log.Warn("identity collection partial", zap.Error(err))
	}
	res.Identity = id

	namespaces := append([]string{}, opts.Namespaces...)

	// ── Namespace bruteforce ──────────────────────────────────────────────────
	if opts.BruteforceNS {
		log.Info("bruteforcing namespaces", zap.Int("candidates", len(opts.NamespaceWordlist)))
		probes := BruteforceNamespaces(ctx, c, opts.NamespaceWordlist, log)
		res.NamespaceProbes = probes
		for _, p := range probes {
			if p.Status == "confirmed" {
				namespaces = appendUniqueStr(namespaces, p.Namespace)
			}
		}
	}

	if len(namespaces) == 0 {
		ns := id.Namespace
		if ns == "" {
			ns = "default"
		}
		namespaces = []string{ns}
	}
	sort.Strings(namespaces)
	res.Namespaces = namespaces

	// ── Effective permissions per namespace (SSRR) ────────────────────────────
	if !opts.SkipSSRR {
		log.Info("collecting effective permissions (SSRR)", zap.Strings("namespaces", namespaces))
		for _, ns := range namespaces {
			rules, err := collectSSRR(ctx, c, ns, log)
			if err != nil {
				log.Warn("SSRR failed", zap.String("namespace", ns), zap.Error(err))
				continue
			}
			res.SSRRByNamespace[ns] = rules
		}
	}

	// ── Resource access matrix (SSAR) ─────────────────────────────────────────
	if !opts.SkipCapabilities {
		log.Info("discovering accessible resources (SSAR)")
		res.Capabilities = DiscoverCapabilities(ctx, c, namespaces, log)
	}

	return res
}

// reconNamespacedResources is the curated resource catalog probed per namespace.
// Subresources use "resource/subresource" form.
var reconNamespacedResources = []string{
	"pods", "pods/log", "pods/exec", "pods/portforward",
	"secrets", "configmaps", "serviceaccounts", "serviceaccounts/token",
	"services", "endpoints", "events", "persistentvolumeclaims",
	"deployments", "daemonsets", "statefulsets", "replicasets",
	"jobs", "cronjobs", "roles", "rolebindings", "networkpolicies", "ingresses",
}

// reconClusterResources is the curated cluster-scoped resource catalog.
var reconClusterResources = []string{
	"namespaces", "nodes", "nodes/proxy", "persistentvolumes", "storageclasses",
	"clusterroles", "clusterrolebindings", "customresourcedefinitions",
	"mutatingwebhookconfigurations", "validatingwebhookconfigurations",
	"certificatesigningrequests", "tokenreviews",
}

var reconVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete"}

// DiscoverCapabilities probes, via SelfSubjectAccessReview, which verbs the current
// identity may perform on a curated catalog of cluster-scoped and per-namespace
// resources. Only resources with at least one allowed verb are returned.
func DiscoverCapabilities(ctx context.Context, c *Client, namespaces []string, log *zap.Logger) []ResourceAccess {
	type target struct {
		display      string
		resource     string
		subresource  string
		namespace    string
		clusterScope bool
	}

	var targets []target
	for _, r := range reconClusterResources {
		res, sub := splitResource(r)
		targets = append(targets, target{r, res, sub, "", true})
	}
	for _, ns := range namespaces {
		for _, r := range reconNamespacedResources {
			res, sub := splitResource(r)
			targets = append(targets, target{r, res, sub, ns, false})
		}
	}

	var (
		mu  sync.Mutex
		out = make([]ResourceAccess, 0, len(targets))
		wg  sync.WaitGroup
		sem = make(chan struct{}, 16) // bound concurrency to avoid hammering the API server
	)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()

			var allowed []string
			for _, v := range reconVerbs {
				callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				ok, _, err := c.SSAR(callCtx, v, t.resource, t.subresource, t.namespace)
				cancel()
				if err != nil {
					continue
				}
				if ok {
					allowed = append(allowed, v)
				}
			}
			if len(allowed) == 0 {
				return
			}
			mu.Lock()
			out = append(out, ResourceAccess{
				Resource:     t.display,
				Namespace:    t.namespace,
				ClusterScope: t.clusterScope,
				AllowedVerbs: allowed,
			})
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool {
		if out[i].ClusterScope != out[j].ClusterScope {
			return out[i].ClusterScope // cluster-scoped first
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Resource < out[j].Resource
	})
	log.Info("capability discovery complete", zap.Int("accessible_resources", len(out)))
	return out
}

// BruteforceNamespaces probes each candidate namespace name to determine whether it
// exists and is (at least partly) readable by the current identity. It is useful when
// the identity cannot list namespaces cluster-wide but may still access specific ones.
func BruteforceNamespaces(ctx context.Context, c *Client, candidates []string, log *zap.Logger) []NamespaceProbe {
	seen := map[string]bool{}
	var probes []NamespaceProbe
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, 16)
	)

	for _, raw := range candidates {
		ns := strings.TrimSpace(raw)
		if ns == "" || seen[ns] {
			continue
		}
		seen[ns] = true

		wg.Add(1)
		sem <- struct{}{}
		go func(ns string) {
			defer wg.Done()
			defer func() { <-sem }()
			p := probeNamespace(ctx, c, ns)
			mu.Lock()
			probes = append(probes, p)
			mu.Unlock()
		}(ns)
	}
	wg.Wait()

	sort.Slice(probes, func(i, j int) bool { return probes[i].Namespace < probes[j].Namespace })

	confirmed := 0
	for _, p := range probes {
		if p.Status == "confirmed" {
			confirmed++
		}
	}
	log.Info("namespace bruteforce complete",
		zap.Int("probed", len(probes)), zap.Int("confirmed", confirmed))
	return probes
}

// probeNamespace attempts to read a series of well-known objects that exist in every
// namespace. A successful read confirms the namespace exists; a 403 on every attempt
// means it may exist but is inaccessible; 404s mean it likely does not exist.
func probeNamespace(ctx context.Context, c *Client, ns string) NamespaceProbe {
	p := NamespaceProbe{Namespace: ns, Status: "not_found"}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cs := c.Clientset()
	forbidden := false

	// Probe 1: GET the namespace object directly (cluster-scoped; may be granted by resourceName).
	if _, err := cs.CoreV1().Namespaces().Get(callCtx, ns, metav1.GetOptions{}); err == nil {
		return NamespaceProbe{Namespace: ns, Status: "confirmed", Method: "get namespace", Readable: true}
	} else if apierrors.IsForbidden(err) {
		forbidden = true
	}

	// Probe 2: GET the "default" ServiceAccount (auto-created in every namespace).
	if _, err := cs.CoreV1().ServiceAccounts(ns).Get(callCtx, "default", metav1.GetOptions{}); err == nil {
		return NamespaceProbe{Namespace: ns, Status: "confirmed", Method: "get serviceaccount/default", Readable: true}
	} else if apierrors.IsForbidden(err) {
		forbidden = true
	}

	// Probe 3: GET the "kube-root-ca.crt" ConfigMap (auto-created in every namespace on k8s >= 1.20).
	if _, err := cs.CoreV1().ConfigMaps(ns).Get(callCtx, "kube-root-ca.crt", metav1.GetOptions{}); err == nil {
		return NamespaceProbe{Namespace: ns, Status: "confirmed", Method: "get configmap/kube-root-ca.crt", Readable: true}
	} else if apierrors.IsForbidden(err) {
		forbidden = true
	}

	if forbidden {
		p.Status = "forbidden"
	}
	return p
}

// splitResource splits "resource/subresource" into its components.
func splitResource(r string) (resource, subresource string) {
	if i := strings.IndexByte(r, '/'); i >= 0 {
		return r[:i], r[i+1:]
	}
	return r, ""
}

// appendUniqueStr appends s to slice only if not already present.
func appendUniqueStr(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
