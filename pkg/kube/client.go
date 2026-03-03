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
