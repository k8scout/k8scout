// Package kube provides Kubernetes API client construction and low-level helpers.
package kube

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes clientset with project-specific helpers.
type Client struct {
	cs            kubernetes.Interface
	restCfg       *rest.Config
	timeout       time.Duration
	log           *zap.Logger
	serverVersion string
	currentNS     string

	// impersonationCache caches clientsets keyed by impersonated username.
	// Creating a new clientset per SSRR call is expensive (TLS state, HTTP
	// transport) and can trigger GC issues under memory pressure. Cache them.
	impersonationCache map[string]kubernetes.Interface
}

// NewClient constructs a Client from kubeconfig or in-cluster config.
// kubeconfigPath may be empty for auto-detection or in-cluster.
func NewClient(kubeconfigPath string, timeout time.Duration, log *zap.Logger) (*Client, error) {
	cfg, ns, err := buildRestConfig(kubeconfigPath, log)
	if err != nil {
		return nil, fmt.Errorf("building rest config: %w", err)
	}

	// Harden timeouts on the underlying HTTP transport.
	cfg.Timeout = timeout
	if cfg.WrapTransport == nil {
		cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper { return rt }
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating clientset: %w", err)
	}

	c := &Client{
		cs:        cs,
		restCfg:   cfg,
		timeout:   timeout,
		log:       log,
		currentNS: ns,
	}

	// Probe server version (non-fatal).
	if sv, err := cs.Discovery().ServerVersion(); err == nil {
		c.serverVersion = fmt.Sprintf("%s.%s", sv.Major, sv.Minor)
	} else {
		log.Warn("could not retrieve server version", zap.Error(err))
	}

	return c, nil
}

func buildRestConfig(kubeconfigPath string, log *zap.Logger) (*rest.Config, string, error) {
	// 1. Explicit kubeconfig flag.
	if kubeconfigPath != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, "", err
		}
		ns := currentNSFromKubeconfig(kubeconfigPath)
		return cfg, ns, nil
	}

	// 2. KUBECONFIG env / default ~/.kube/config.
	kubeEnv := os.Getenv("KUBECONFIG")
	if kubeEnv == "" {
		if home, err := os.UserHomeDir(); err == nil {
			candidate := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(candidate); err == nil {
				kubeEnv = candidate
			}
		}
	}
	if kubeEnv != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeEnv)
		if err == nil {
			log.Debug("using kubeconfig", zap.String("path", kubeEnv))
			ns := currentNSFromKubeconfig(kubeEnv)
			return cfg, ns, nil
		}
		log.Warn("kubeconfig found but failed to parse, trying in-cluster", zap.Error(err))
	}

	// 3. In-cluster (ServiceAccount token injection).
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, "", fmt.Errorf("no valid kubeconfig and in-cluster config failed: %w", err)
	}
	log.Info("using in-cluster config")
	ns := inClusterNamespace()
	return cfg, ns, nil
}

func inClusterNamespace() string {
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "default"
	}
	return strings.TrimSpace(string(data))
}

func currentNSFromKubeconfig(path string) string {
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: path},
		&clientcmd.ConfigOverrides{},
	)
	ns, _, err := loader.Namespace()
	if err != nil || ns == "" {
		return "default"
	}
	return ns
}

// CurrentNamespace returns the namespace associated with the active context.
func (c *Client) CurrentNamespace() string { return c.currentNS }

// ServerVersion returns a "<major>.<minor>" string or empty.
func (c *Client) ServerVersion() string { return c.serverVersion }

// ListNamespaces returns the names of all namespaces the current identity can see.
func (c *Client) ListNamespaces(ctx context.Context) ([]string, error) {
	list, err := c.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list.Items))
	for _, ns := range list.Items {
		names = append(names, ns.Name)
	}
	return names, nil
}

// GetNamespaces returns full Namespace objects.
func (c *Client) GetNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	list, err := c.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// SSRR performs a SelfSubjectRulesReview for the given namespace.
// Pass "" for cluster-wide rules (non-resource URLs, etc.).
func (c *Client) SSRR(ctx context.Context, namespace string) (*authzv1.SelfSubjectRulesReview, error) {
	review := &authzv1.SelfSubjectRulesReview{
		Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: namespace},
	}
	return c.cs.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, review, metav1.CreateOptions{})
}

// SSAR performs a SelfSubjectAccessReview for a specific verb/resource/namespace combination.
func (c *Client) SSAR(ctx context.Context, verb, resource, subresource, namespace string) (bool, string, error) {
	rar := &authzv1.ResourceAttributes{
		Verb:        verb,
		Resource:    resource,
		Subresource: subresource,
		Namespace:   namespace,
	}
	review := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: rar,
		},
	}
	resp, err := c.cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, "", err
	}
	return resp.Status.Allowed, resp.Status.Reason, nil
}

// WhoAmI attempts a TokenReview to discover identity details.
// Falls back to parsing the username from SSRR metadata when TokenReview is denied.
func (c *Client) WhoAmI(ctx context.Context) (username, uid string, groups []string, extra map[string][]string, err error) {
	// TokenReview with empty token means "review my own token".
	token, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	tr := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: strings.TrimSpace(string(token))},
	}
	resp, err := c.cs.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil || !resp.Status.Authenticated {
		// Graceful degradation: derive identity from SSRR response metadata later.
		return "", "", nil, nil, fmt.Errorf("TokenReview not permitted or unauthenticated: %w", err)
	}
	extraMap := make(map[string][]string, len(resp.Status.User.Extra))
	for k, v := range resp.Status.User.Extra {
		strs := make([]string, len(v))
		for i, s := range v {
			strs[i] = string(s)
		}
		extraMap[k] = strs
	}
	return resp.Status.User.Username, resp.Status.User.UID, resp.Status.User.Groups, extraMap, nil
}

// Clientset exposes the underlying kubernetes.Interface for collectors.
func (c *Client) Clientset() kubernetes.Interface { return c.cs }

// SSRRAs performs a SelfSubjectRulesReview while impersonating a given user.
// This creates a temporary clientset with impersonation headers so the API server
// evaluates SSRR as the target identity. Requires the caller to have
// "impersonate" permission on the target user/serviceaccount.
//
// The username should be in Kubernetes format, e.g.:
//
//	"system:serviceaccount:<namespace>:<name>"
func (c *Client) SSRRAs(ctx context.Context, username, namespace string) (*authzv1.SelfSubjectRulesReview, error) {
	impCS, err := c.impersonatingClientset(username)
	if err != nil {
		return nil, err
	}

	review := &authzv1.SelfSubjectRulesReview{
		Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: namespace},
	}
	return impCS.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, review, metav1.CreateOptions{})
}

// impersonatingClientset returns a cached clientset that impersonates the given
// user. Creating a new clientset for every SSRR call allocates TLS transports
// that churn the GC; caching avoids this.
func (c *Client) impersonatingClientset(username string) (kubernetes.Interface, error) {
	if c.impersonationCache == nil {
		c.impersonationCache = make(map[string]kubernetes.Interface)
	}
	if cs, ok := c.impersonationCache[username]; ok {
		return cs, nil
	}

	impCfg := rest.CopyConfig(c.restCfg)
	impCfg.Impersonate = rest.ImpersonationConfig{
		UserName: username,
	}
	impCfg.Timeout = c.timeout

	cs, err := kubernetes.NewForConfig(impCfg)
	if err != nil {
		return nil, fmt.Errorf("creating impersonating clientset for %q: %w", username, err)
	}
	c.impersonationCache[username] = cs
	return cs, nil
}

// SSRRWithToken performs a SelfSubjectRulesReview using a caller-supplied bearer
// token. This authenticates as the token's owner (typically a ServiceAccount)
// without requiring impersonation permission on the primary identity.
//
// Use this when a captured SA-token secret value can be replayed against the
// API server to discover that SA's effective permissions directly.
func (c *Client) SSRRWithToken(ctx context.Context, token, namespace string) (*authzv1.SelfSubjectRulesReview, error) {
	// Cache token-based clientsets using "token:<first16chars>" as key to avoid
	// creating hundreds of transports for the same captured token across namespaces.
	cacheKey := "token:" + token
	if len(token) > 16 {
		cacheKey = "token:" + token[:16]
	}
	if c.impersonationCache == nil {
		c.impersonationCache = make(map[string]kubernetes.Interface)
	}
	tokCS, ok := c.impersonationCache[cacheKey]
	if !ok {
		tokCfg := rest.AnonymousClientConfig(c.restCfg)
		tokCfg.BearerToken = token
		tokCfg.BearerTokenFile = ""
		tokCfg.Timeout = c.timeout

		var err error
		tokCS, err = kubernetes.NewForConfig(tokCfg)
		if err != nil {
			return nil, fmt.Errorf("creating token-authenticated clientset: %w", err)
		}
		c.impersonationCache[cacheKey] = tokCS
	}

	review := &authzv1.SelfSubjectRulesReview{
		Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: namespace},
	}
	return tokCS.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, review, metav1.CreateOptions{})
}
