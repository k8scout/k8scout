package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hac01/k8scout/pkg/ai"
	"github.com/hac01/k8scout/pkg/graph"
	"github.com/hac01/k8scout/pkg/kube"
	"github.com/hac01/k8scout/pkg/output"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const version = "0.1.0"

type Config struct {
	OutFile       string
	Namespace     string
	AllNamespaces bool
	Format        string
	TimeoutSecs   int
	LogLevel      string
	OpenAIKey     string
	OpenAIModel   string
	SkipSSAR      bool
	SkipAI        bool
	Kubeconfig    string
	ReviewerMode  bool
	Stealth       bool
}

func main() {
	cfg := &Config{}

	root := &cobra.Command{
		Use:   "k8scout",
		Short: "Kubernetes permission enumerator for authorized security assessment",
		Long: `k8scout enumerates the effective permissions of the current Kubernetes identity
(ServiceAccount token or kubeconfig credential), builds a cluster permission graph,
and produces a JSON report with optional AI-generated risk narrative.

This tool is designed for authorized security testing and defensive risk assessment only.
It never reads secret data values — only metadata.`,
		Version:      version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.ReviewerMode {
				return runReviewer(cfg)
			}
			return run(cfg)
		},
	}

	f := root.Flags()
	f.StringVar(&cfg.OutFile, "out", "k8scout-result.json", "Output JSON file path")
	f.StringVar(&cfg.Namespace, "namespace", "", "Single namespace to enumerate (overrides --all-namespaces)")
	f.BoolVar(&cfg.AllNamespaces, "all-namespaces", true, "Enumerate all accessible namespaces (default true)")
	f.StringVar(&cfg.Format, "format", "text", "Output format: json|text")
	f.IntVar(&cfg.TimeoutSecs, "timeout", 60, "Per-request timeout in seconds")
	f.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug|info|warn|error")
	f.StringVar(&cfg.OpenAIKey, "openai-key", "", "OpenAI API key for AI narrative (or set OPENAI_API_KEY env var)")
	f.StringVar(&cfg.OpenAIModel, "openai-model", "gpt-4o", "OpenAI model for risk narrative")
	f.BoolVar(&cfg.SkipSSAR, "skip-ssar", false, "Skip SelfSubjectAccessReview spot checks")
	f.BoolVar(&cfg.SkipAI, "skip-ai", false, "Skip OpenAI narrative generation")
	f.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "Path to kubeconfig (auto-detected if empty; in-cluster if running inside a pod)")
	f.BoolVar(&cfg.ReviewerMode, "reviewer-mode", false,
		"Reviewer mode: enumerate full cluster RBAC attack surface for all SAs + pod security checks. "+
			"Requires get,list on clusterroles, clusterrolebindings, roles, rolebindings, pods, nodes, workloads.")
	f.BoolVar(&cfg.Stealth, "stealth", false,
		"Skip SSRR and SSAR API calls to reduce audit log footprint. "+
			"Findings that require permission data will be limited. "+
			"Appends an audit_footprint block to the report showing what was skipped.")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cfg *Config) error {
	log := buildLogger(cfg.LogLevel)
	defer log.Sync() //nolint:errcheck

	log.Info("k8scout starting", zap.String("version", version))

	// Resolve OpenAI key from env if not set via flag.
	if cfg.OpenAIKey == "" {
		cfg.OpenAIKey = os.Getenv("OPENAI_API_KEY")
	}

	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout*100) // outer ctx
	defer cancel()

	// ── 1. Build Kubernetes client ─────────────────────────────────────────────
	client, err := kube.NewClient(cfg.Kubeconfig, timeout, log)
	if err != nil {
		return fmt.Errorf("building kube client: %w", err)
	}

	// ── 2. Determine namespaces to enumerate ──────────────────────────────────
	namespaces, err := resolveNamespaces(ctx, cfg, client, log)
	if err != nil {
		return err
	}
	log.Info("namespaces to enumerate", zap.Strings("namespaces", namespaces))

	// ── 3. Run collectors ─────────────────────────────────────────────────────
	result, err := kube.Enumerate(ctx, client, kube.EnumerateOptions{
		Namespaces: namespaces,
		SkipSSAR:   cfg.SkipSSAR || cfg.Stealth,
		Stealth:    cfg.Stealth,
		Log:        log,
	})
	if err != nil {
		// Non-fatal: we may have partial results.
		log.Warn("enumeration completed with errors", zap.Error(err))
	}

	// ── 4. Build permission graph ─────────────────────────────────────────────
	g := graph.Build(result, log)

	// ── 5. Run inference rules / risk scoring ─────────────────────────────────
	findings := graph.Infer(g, result, log)

	// ── 6. Assemble final report ──────────────────────────────────────────────
	meta := output.MetaInfo(version, cfg.TimeoutSecs, client.ServerVersion())
	meta.Stealth = cfg.Stealth
	report := output.Report{
		Meta:           meta,
		Identity:       result.Identity,
		Permissions:    result.Permissions,
		ClusterObjects: result.ClusterObjects,
		Graph:          g,
		RiskFindings:   findings,
		AuditFootprint: result.AuditFootprint,
	}

	// ── 7. Optional: AI narrative ─────────────────────────────────────────────
	if !cfg.SkipAI && cfg.OpenAIKey != "" {
		log.Info("requesting AI risk narrative", zap.String("model", cfg.OpenAIModel))
		narrative, aiErr := ai.GenerateNarrative(ctx, cfg.OpenAIKey, cfg.OpenAIModel, report, log)
		if aiErr != nil {
			log.Warn("AI narrative failed (continuing without it)", zap.Error(aiErr))
		} else {
			report.AINarrative = narrative
		}
	} else if !cfg.SkipAI && cfg.OpenAIKey == "" {
		log.Info("no OpenAI key provided; skipping AI narrative (use --openai-key or OPENAI_API_KEY)")
	}

	// ── 8. Write output ───────────────────────────────────────────────────────
	writer := output.New(cfg.Format, log)

	if err := writer.Print(report); err != nil {
		log.Error("printing report to stdout", zap.Error(err))
	}

	if cfg.OutFile != "" {
		if err := writer.WriteFile(report, cfg.OutFile); err != nil {
			return fmt.Errorf("writing JSON output to %s: %w", cfg.OutFile, err)
		}
		log.Info("JSON report written", zap.String("path", cfg.OutFile))
	}

	return nil
}

// runReviewer implements the --reviewer-mode flow:
//  1. Enumerate all RBAC objects, workloads, pods (with read-only access)
//  2. Compute effective permissions for every SA/user from RBAC rules (no SSRR per SA)
//  3. Analyze pod security contexts
//  4. Build a full-cluster permission graph
//  5. Run reviewer inference (per-SA risk checks + pod security findings)
//
// Minimum required RBAC for the reviewer account:
//
//	get,list: clusterroles, clusterrolebindings, roles, rolebindings
//	get,list: serviceaccounts, namespaces, pods, nodes
//	get,list: deployments, daemonsets, statefulsets, jobs, cronjobs
//	list:     secrets (metadata only — no get, so values are never read)
func runReviewer(cfg *Config) error {
	log := buildLogger(cfg.LogLevel)
	defer log.Sync() //nolint:errcheck

	log.Info("k8scout reviewer mode starting", zap.String("version", version))

	if cfg.OpenAIKey == "" {
		cfg.OpenAIKey = os.Getenv("OPENAI_API_KEY")
	}

	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout*100)
	defer cancel()

	// ── 1. Build Kubernetes client ─────────────────────────────────────────────
	client, err := kube.NewClient(cfg.Kubeconfig, timeout, log)
	if err != nil {
		return fmt.Errorf("building kube client: %w", err)
	}

	// ── 2. Determine namespaces ────────────────────────────────────────────────
	namespaces, err := resolveNamespaces(ctx, cfg, client, log)
	if err != nil {
		return err
	}
	log.Info("namespaces to enumerate", zap.Strings("namespaces", namespaces))

	// ── 3. Run standard collectors (skip SSAR — not needed for reviewer mode) ─
	result, err := kube.Enumerate(ctx, client, kube.EnumerateOptions{
		Namespaces: namespaces,
		SkipSSAR:   true, // SSAR only checks the reviewer's own permissions, not useful here
		Log:        log,
	})
	if err != nil {
		log.Warn("enumeration completed with errors", zap.Error(err))
	}

	// ── 4. Compute effective permissions for all RBAC subjects ────────────────
	log.Info("computing effective RBAC permissions for all subjects")
	allPerms := kube.ComputeAllEffectivePermissions(
		result.ClusterObjects.ClusterRoles,
		result.ClusterObjects.ClusterRoleBindings,
		result.ClusterObjects.Roles,
		result.ClusterObjects.RoleBindings,
		log,
	)

	// ── 5. Pod security analysis ───────────────────────────────────────────────
	log.Info("analyzing pod security configurations")
	podIssues := kube.AnalyzePodSecurity(result.ClusterObjects.Workloads, result.ClusterObjects.Pods)
	log.Info("pod security analysis complete", zap.Int("issues", len(podIssues)))

	reviewerResult := &kube.ReviewerEnumerateResult{
		EnumerationResult: result,
		AllIdentityPerms:  allPerms,
		PodSecurityIssues: podIssues,
	}

	// ── 6. Build reviewer permission graph ────────────────────────────────────
	g := graph.BuildReviewer(reviewerResult, log)

	// ── 7. Run reviewer inference rules ───────────────────────────────────────
	findings := graph.InferReviewer(g, reviewerResult, log)

	// ── 8. Assemble report ────────────────────────────────────────────────────
	summary := output.BuildReviewerSummary(findings, allPerms, podIssues, result.ClusterObjects)
	report := output.ReviewerReport{
		Meta:              output.MetaInfo(version, cfg.TimeoutSecs, client.ServerVersion()),
		ReviewerIdentity:  result.Identity,
		ClusterObjects:    result.ClusterObjects,
		AllIdentityPerms:  allPerms,
		PodSecurityIssues: podIssues,
		Graph:             g,
		RiskFindings:      findings,
		Summary:           summary,
	}

	// ── 9. Optional: AI narrative ─────────────────────────────────────────────
	if !cfg.SkipAI && cfg.OpenAIKey != "" {
		// Build a standard report skeleton for the AI summarizer (reuses same findings).
		aiReport := output.Report{
			Meta:         report.Meta,
			Identity:     report.ReviewerIdentity,
			RiskFindings: findings,
		}
		log.Info("requesting AI risk narrative", zap.String("model", cfg.OpenAIModel))
		narrative, aiErr := ai.GenerateNarrative(ctx, cfg.OpenAIKey, cfg.OpenAIModel, aiReport, log)
		if aiErr != nil {
			log.Warn("AI narrative failed (continuing without it)", zap.Error(aiErr))
		} else {
			report.AINarrative = narrative
		}
	}

	// ── 10. Write output ──────────────────────────────────────────────────────
	writer := output.New(cfg.Format, log)

	if err := writer.PrintReviewer(report); err != nil {
		log.Error("printing reviewer report to stdout", zap.Error(err))
	}

	if cfg.OutFile != "" {
		if err := writer.WriteReviewerFile(report, cfg.OutFile); err != nil {
			return fmt.Errorf("writing JSON output to %s: %w", cfg.OutFile, err)
		}
		log.Info("reviewer JSON report written", zap.String("path", cfg.OutFile))
	}

	return nil
}

func resolveNamespaces(ctx context.Context, cfg *Config, client *kube.Client, log *zap.Logger) ([]string, error) {
	if cfg.Namespace != "" {
		return []string{cfg.Namespace}, nil
	}
	if cfg.AllNamespaces {
		nsList, err := client.ListNamespaces(ctx)
		if err != nil {
			log.Warn("cannot list all namespaces, falling back to 'default'", zap.Error(err))
			return []string{"default"}, nil
		}
		return nsList, nil
	}
	// Detect current namespace from in-cluster token.
	ns := client.CurrentNamespace()
	if ns == "" {
		ns = "default"
	}
	return []string{ns}, nil
}

func buildLogger(level string) *zap.Logger {
	lvl := zapcore.InfoLevel
	switch level {
	case "debug":
		lvl = zapcore.DebugLevel
	case "warn":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	log, _ := cfg.Build()
	return log
}
