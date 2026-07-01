package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hac01/k8scout/pkg/ai"
	"github.com/hac01/k8scout/pkg/exploit"
	"github.com/hac01/k8scout/pkg/graph"
	"github.com/hac01/k8scout/pkg/kube"
	"github.com/hac01/k8scout/pkg/output"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const version = "0.1.0"

type Config struct {
	OutFile        string
	Namespace      string
	AllNamespaces  bool
	Format         string
	TimeoutSecs    int
	LogLevel       string
	OpenAIKey      string
	OpenAIModel    string
	SkipSSAR       bool
	SkipAI         bool
	Kubeconfig     string
	ReviewerMode   bool
	Stealth        bool
	WhatIfFile     string
	Active         bool
	KubeconfigList []string
	Recon          bool
	BruteforceNS   bool
	NSWordlist     string
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
			if cfg.Recon {
				return runRecon(cfg)
			}
			if len(cfg.KubeconfigList) > 0 {
				return runMultiCluster(cfg)
			}
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
	f.StringVar(&cfg.WhatIfFile, "what-if", "", "JSON file with what-if scenario to simulate")
	f.BoolVar(&cfg.Active, "active", false,
		"Enable active exploitation mode: exec into pods, extract tokens, probe metadata endpoints. "+
			"WARNING: This performs intrusive operations. Use only during authorized security testing.")
	f.StringArrayVar(&cfg.KubeconfigList, "kubeconfig-list", nil,
		"Kubeconfig paths for multi-cluster analysis (can be specified multiple times)")
	f.BoolVar(&cfg.Recon, "recon", false,
		"Recon mode: quickly display the current identity, its effective permissions (SSRR), "+
			"and which resources it can access (SSAR) — no graph, inference, or AI. "+
			"Combine with --bruteforce-ns to discover namespaces you cannot list.")
	f.BoolVar(&cfg.BruteforceNS, "bruteforce-ns", false,
		"Bruteforce namespace names (via a built-in wordlist or --ns-wordlist) to find namespaces "+
			"that are not listable cluster-wide. Only effective with --recon.")
	f.StringVar(&cfg.NSWordlist, "ns-wordlist", "",
		"Path to a newline-delimited namespace wordlist for --bruteforce-ns (defaults to a built-in list)")

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
	ctx, cancel := context.WithTimeout(context.Background(), timeout*10) // outer ctx: 10× per-request timeout
	defer cancel()

	// ── 1. Build Kubernetes client ─────────────────────────────────────────────
	client, err := kube.NewClient(cfg.Kubeconfig, timeout, log)
	if err != nil {
		return fmt.Errorf("building kube client: %w", err)
	}

	// ── 2. Determine namespaces to enumerate ──────────────────────────────────
	log.Info("resolving target namespaces")
	namespaces, err := resolveNamespaces(ctx, cfg, client, log)
	if err != nil {
		return err
	}
	log.Info("namespaces to enumerate", zap.Strings("namespaces", namespaces))

	// ── 3. Run collectors ─────────────────────────────────────────────────────
	result, err := kube.Enumerate(ctx, client, kube.EnumerateOptions{
		Namespaces:    namespaces,
		SkipSSAR:      cfg.SkipSSAR || cfg.Stealth,
		Stealth:       cfg.Stealth,
		ProbeKubelet:  !cfg.Stealth,
		ProbeMetadata: cfg.Active,
		Log:           log,
	})
	if err != nil {
		// Non-fatal: we may have partial results.
		log.Warn("enumeration completed with errors", zap.Error(err))
	}

	// ── 4. Build permission graph ─────────────────────────────────────────────
	g := graph.Build(result, log)

	// ── 5. Run inference rules / risk scoring ─────────────────────────────────
	findings := graph.Infer(g, result, log)

	// ── 5b. What-if simulation (optional) ────────────────────────────────────
	var whatIfResult *graph.WhatIfResult
	if cfg.WhatIfFile != "" {
		scenario, err := graph.LoadWhatIfScenario(cfg.WhatIfFile)
		if err != nil {
			log.Warn("failed to load what-if scenario", zap.Error(err))
		} else {
			r := graph.RunWhatIf(g, result, *scenario, log)
			whatIfResult = &r
		}
	}

	// ── 5c. Active exploitation (optional) ───────────────────────────────────
	var activeResult *exploit.ActiveResult
	if cfg.Active {
		log.Warn("=== ACTIVE EXPLOITATION MODE ENABLED ===")
		log.Warn("This mode performs intrusive operations (pod exec, credential extraction).")
		log.Warn("Use only during authorized security testing engagements.")
		activeResult = runActiveExploitation(ctx, client, result, log)
	}

	// ── 5d. Choke point analysis ─────────────────────────────────────────────
	goals := graph.HighValueTargets(g, result)
	var allScoredPaths []graph.ScoredPath
	for _, goal := range goals {
		for i := range g.Nodes {
			n := &g.Nodes[i]
			if n.Kind == graph.KindPod || n.Kind == graph.KindWorkload {
				paths := g.FindWeightedPaths(n.ID, goal.NodeID, graph.MaxAttackPathDepth, 3)
				allScoredPaths = append(allScoredPaths, paths...)
			}
		}
	}
	chokePoints := graph.FindChokePointsFromPaths(allScoredPaths, 0.5)

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
		WhatIf:         whatIfResult,
		ActiveResult:   activeResult,
		ChokePoints:    chokePoints,
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
		if cfg.Format == "sarif" {
			if err := writer.WriteSARIFFile(findings, meta, cfg.OutFile); err != nil {
				return fmt.Errorf("writing SARIF output to %s: %w", cfg.OutFile, err)
			}
			log.Info("SARIF report written", zap.String("path", cfg.OutFile))
		} else {
			if err := writer.WriteFile(report, cfg.OutFile); err != nil {
				return fmt.Errorf("writing JSON output to %s: %w", cfg.OutFile, err)
			}
			log.Info("JSON report written", zap.String("path", cfg.OutFile))
		}
	}

	return nil
}

// runRecon implements the --recon flow: a fast, low-footprint enumeration that reports
// the current identity, its effective permissions (SSRR), and the resources it can
// access (SSAR capability matrix). With --bruteforce-ns it also probes a wordlist of
// candidate namespace names to discover namespaces that cannot be listed cluster-wide.
func runRecon(cfg *Config) error {
	log := buildLogger(cfg.LogLevel)
	defer log.Sync() //nolint:errcheck

	log.Info("k8scout recon mode starting", zap.String("version", version))

	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout*10)
	defer cancel()

	// ── 1. Build Kubernetes client ─────────────────────────────────────────────
	client, err := kube.NewClient(cfg.Kubeconfig, timeout, log)
	if err != nil {
		return fmt.Errorf("building kube client: %w", err)
	}

	// ── 2. Determine base namespaces ───────────────────────────────────────────
	var namespaces []string
	if cfg.Namespace != "" {
		namespaces = []string{cfg.Namespace}
	} else {
		nsCtx, nsCancel := context.WithTimeout(ctx, 10*time.Second)
		listed, lerr := client.ListNamespaces(nsCtx)
		nsCancel()
		if lerr != nil {
			cur := client.CurrentNamespace()
			if cur == "" {
				cur = "default"
			}
			log.Warn("cannot list namespaces; using current (try --bruteforce-ns to discover more)",
				zap.String("namespace", cur), zap.Error(lerr))
			namespaces = []string{cur}
		} else {
			namespaces = listed
		}
	}

	// ── 3. Resolve namespace wordlist for bruteforce ──────────────────────────
	var wordlist []string
	if cfg.BruteforceNS {
		if cfg.NSWordlist != "" {
			wordlist, err = kube.LoadNamespaceWordlist(cfg.NSWordlist)
			if err != nil {
				return fmt.Errorf("loading namespace wordlist %q: %w", cfg.NSWordlist, err)
			}
		} else {
			wordlist = kube.DefaultNamespaceWordlist
		}
	}

	// ── 4. Run recon ───────────────────────────────────────────────────────────
	result := kube.Recon(ctx, client, kube.ReconOptions{
		Namespaces:        namespaces,
		BruteforceNS:      cfg.BruteforceNS,
		NamespaceWordlist: wordlist,
		Log:               log,
	})

	// ── 5. Output ──────────────────────────────────────────────────────────────
	writer := output.New(cfg.Format, log)
	if err := writer.PrintRecon(*result); err != nil {
		log.Error("printing recon report to stdout", zap.Error(err))
	}

	if cfg.OutFile != "" && cfg.Format == "json" {
		if err := writer.WriteReconFile(*result, cfg.OutFile); err != nil {
			return fmt.Errorf("writing recon JSON output to %s: %w", cfg.OutFile, err)
		}
		log.Info("recon JSON report written", zap.String("path", cfg.OutFile))
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout*10)
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

// runActiveExploitation performs active exploitation against accessible pods.
func runActiveExploitation(ctx context.Context, client *kube.Client, result *kube.EnumerationResult, log *zap.Logger) *exploit.ActiveResult {
	ar := &exploit.ActiveResult{}
	restCfg := client.RestConfig()
	cs := client.Clientset()

	// Target: pods where we have exec access (from SSAR checks).
	execNS := make(map[string]bool)
	for _, c := range result.Permissions.SSARChecks {
		if c.Allowed && c.Resource == "pods" && c.Subresource == "exec" && c.Verb == "create" {
			execNS[c.Namespace] = true
		}
	}

	for _, pod := range result.ClusterObjects.Pods {
		if !execNS[pod.Namespace] {
			continue
		}
		if pod.Phase != "Running" {
			continue
		}

		log.Info("active: targeting pod", zap.String("pod", pod.Namespace+"/"+pod.Name))

		// Extract SA token.
		token, err := exploit.ExtractSAToken(ctx, restCfg, cs, pod.Name, pod.Namespace, log)
		if err != nil {
			log.Debug("SA token extraction failed", zap.String("pod", pod.Name), zap.Error(err))
		} else {
			ar.Credentials = append(ar.Credentials, *token)
			ar.Results = append(ar.Results, exploit.ExploitResult{
				Step:    exploit.ExploitStep{Technique: "sa_token_read", Target: pod.Namespace + "/" + pod.Name},
				Success: true,
			})
		}

		// Extract env credentials.
		envCreds, err := exploit.ExtractEnvCredentials(ctx, restCfg, cs, pod.Name, pod.Namespace, log)
		if err != nil {
			log.Debug("env credential extraction failed", zap.String("pod", pod.Name), zap.Error(err))
		} else {
			ar.Credentials = append(ar.Credentials, envCreds...)
		}

		// Extract metadata credentials.
		metaCreds, err := exploit.ExtractMetadataCredentials(ctx, restCfg, cs, pod.Name, pod.Namespace, log)
		if err != nil {
			log.Debug("metadata credential extraction failed", zap.String("pod", pod.Name), zap.Error(err))
		} else {
			ar.Credentials = append(ar.Credentials, metaCreds...)
		}
	}

	log.Info("active exploitation complete",
		zap.Int("credentials_captured", len(ar.Credentials)),
		zap.Int("exploit_results", len(ar.Results)))

	return ar
}

// runMultiCluster enumerates multiple clusters and builds a merged graph.
func runMultiCluster(cfg *Config) error {
	log := buildLogger(cfg.LogLevel)
	defer log.Sync() //nolint:errcheck

	log.Info("k8scout multi-cluster mode", zap.String("version", version),
		zap.Int("clusters", len(cfg.KubeconfigList)))

	if cfg.OpenAIKey == "" {
		cfg.OpenAIKey = os.Getenv("OPENAI_API_KEY")
	}

	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout*10*time.Duration(len(cfg.KubeconfigList)))
	defer cancel()

	var clusters []graph.ClusterEnumerationResult

	for _, kubeconfigPath := range cfg.KubeconfigList {
		log.Info("enumerating cluster", zap.String("kubeconfig", kubeconfigPath))

		client, err := kube.NewClient(kubeconfigPath, timeout, log)
		if err != nil {
			log.Warn("failed to connect to cluster", zap.String("kubeconfig", kubeconfigPath), zap.Error(err))
			continue
		}

		namespaces, err := resolveNamespaces(ctx, cfg, client, log)
		if err != nil {
			log.Warn("namespace resolution failed", zap.String("kubeconfig", kubeconfigPath), zap.Error(err))
			continue
		}

		result, err := kube.Enumerate(ctx, client, kube.EnumerateOptions{
			Namespaces:    namespaces,
			SkipSSAR:      cfg.SkipSSAR || cfg.Stealth,
			Stealth:       cfg.Stealth,
			ProbeKubelet:  !cfg.Stealth,
			ProbeMetadata: cfg.Active,
			Log:           log,
		})
		if err != nil {
			log.Warn("enumeration completed with errors", zap.String("kubeconfig", kubeconfigPath), zap.Error(err))
		}

		// Derive cluster name from server version or kubeconfig path.
		clusterName := client.ServerVersion()
		if clusterName == "" {
			clusterName = kubeconfigPath
		}

		clusters = append(clusters, graph.ClusterEnumerationResult{
			ClusterName: clusterName,
			Server:      client.ServerVersion(),
			Result:      result,
		})
	}

	if len(clusters) == 0 {
		return fmt.Errorf("no clusters were successfully enumerated")
	}

	// Build merged multi-cluster graph.
	g := graph.BuildMultiCluster(clusters, log)

	// Run inference on each cluster's result individually, then merge findings.
	var allFindings []graph.RiskFinding
	for _, cluster := range clusters {
		clusterGraph := graph.Build(cluster.Result, log)
		findings := graph.Infer(clusterGraph, cluster.Result, log)
		for i := range findings {
			findings[i].ID = cluster.ClusterName + ":" + findings[i].ID
		}
		allFindings = append(allFindings, findings...)
	}

	meta := output.MetaInfo(version, cfg.TimeoutSecs, "multi-cluster")

	// Use first cluster's result for identity (the runner's identity).
	report := output.Report{
		Meta:         meta,
		Identity:     clusters[0].Result.Identity,
		Graph:        g,
		RiskFindings: allFindings,
	}

	writer := output.New(cfg.Format, log)
	if err := writer.Print(report); err != nil {
		log.Error("printing report to stdout", zap.Error(err))
	}

	if cfg.OutFile != "" {
		if cfg.Format == "sarif" {
			if err := writer.WriteSARIFFile(allFindings, meta, cfg.OutFile); err != nil {
				return fmt.Errorf("writing SARIF output: %w", err)
			}
		} else {
			if err := writer.WriteFile(report, cfg.OutFile); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
		}
		log.Info("multi-cluster report written", zap.String("path", cfg.OutFile))
	}

	return nil
}

func resolveNamespaces(ctx context.Context, cfg *Config, client *kube.Client, log *zap.Logger) ([]string, error) {
	if cfg.Namespace != "" {
		return []string{cfg.Namespace}, nil
	}

	// Detect current namespace from in-cluster token or kubeconfig.
	currentNS := client.CurrentNamespace()
	if currentNS == "" {
		currentNS = "default"
	}

	if cfg.AllNamespaces {
		// Use a short timeout — if the SA can't list namespaces, fail fast
		// and fall back to the current namespace rather than hanging.
		nsCtx, nsCancel := context.WithTimeout(ctx, 10*time.Second)
		defer nsCancel()

		nsList, err := client.ListNamespaces(nsCtx)
		if err != nil {
			log.Warn("cannot list namespaces, falling back to current namespace",
				zap.String("namespace", currentNS), zap.Error(err))
			return []string{currentNS}, nil
		}
		return nsList, nil
	}

	return []string{currentNS}, nil
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
