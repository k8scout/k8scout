package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

// PrintRecon writes the recon result to stdout (JSON or text based on format flag).
func (w *Writer) PrintRecon(r kube.ReconResult) error {
	if w.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	}
	printReconText(r)
	return nil
}

// WriteReconFile serializes the recon result to a JSON file.
func (w *Writer) WriteReconFile(r kube.ReconResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

func printReconText(r kube.ReconResult) {
	sep := strings.Repeat("─", 72)

	fmt.Printf("\n%s%s k8scout — Recon (identity, permissions & resources)%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, sep, colorReset)

	// ── Identity ──────────────────────────────────────────────────────────────
	fmt.Printf("%s▶ Identity%s\n", colorBold, colorReset)
	fmt.Printf("  Username   : %s\n", dashIfEmpty(r.Identity.Username))
	fmt.Printf("  UID        : %s\n", dashIfEmpty(r.Identity.UID))
	fmt.Printf("  Groups     : %s\n", dashIfEmpty(strings.Join(r.Identity.Groups, ", ")))
	fmt.Printf("  Namespace  : %s\n", dashIfEmpty(r.Identity.Namespace))
	if r.Identity.SAName != "" {
		fmt.Printf("  ServiceAcct: %s\n", r.Identity.SAName)
	}
	if r.Identity.InCluster {
		fmt.Printf("  Context    : in-cluster (pod=%s)\n", dashIfEmpty(r.Identity.PodName))
	}
	fmt.Println()

	// ── Namespace bruteforce ──────────────────────────────────────────────────
	if len(r.NamespaceProbes) > 0 {
		confirmed, forbidden := 0, 0
		for _, p := range r.NamespaceProbes {
			switch p.Status {
			case "confirmed":
				confirmed++
			case "forbidden":
				forbidden++
			}
		}
		fmt.Printf("%s▶ Namespace Bruteforce (%d probed → %d confirmed, %d access-denied)%s\n",
			colorBold, len(r.NamespaceProbes), confirmed, forbidden, colorReset)
		for _, p := range r.NamespaceProbes {
			if p.Status == "not_found" {
				continue // suppress noise for names that don't resolve
			}
			marker := colorGreen + "✓ exists" + colorReset
			detail := p.Method
			if p.Status == "forbidden" {
				marker = colorYellow + "? access denied" + colorReset
				detail = "namespace may exist but you cannot read it"
			}
			fmt.Printf("  %-26s %-22s %s\n", p.Namespace, marker, detail)
		}
		fmt.Println()
	}

	// ── Effective permissions (SSRR) ──────────────────────────────────────────
	if len(r.SSRRByNamespace) > 0 {
		fmt.Printf("%s▶ Effective Permissions (SelfSubjectRulesReview)%s\n", colorBold, colorReset)
		nss := make([]string, 0, len(r.SSRRByNamespace))
		for ns := range r.SSRRByNamespace {
			nss = append(nss, ns)
		}
		sort.Strings(nss)
		for _, ns := range nss {
			fmt.Printf("  %s[namespace: %s]%s\n", colorCyan, ns, colorReset)
			rules := r.SSRRByNamespace[ns]
			if len(rules) == 0 {
				fmt.Printf("    (no rules returned / denied)\n")
				continue
			}
			for _, rule := range rules {
				if len(rule.NonResourceURLs) > 0 {
					fmt.Printf("    %-32s verbs=[%s]\n",
						strings.Join(rule.NonResourceURLs, ","), strings.Join(rule.Verbs, ","))
					continue
				}
				grp := strings.Join(rule.APIGroups, ",")
				if grp == "" || grp == "\"\"" {
					grp = "core"
				}
				res := strings.Join(rule.Resources, ",")
				line := fmt.Sprintf("    %-32s verbs=[%s] apiGroups=[%s]", res, strings.Join(rule.Verbs, ","), grp)
				if len(rule.ResourceNames) > 0 {
					line += " names=[" + strings.Join(rule.ResourceNames, ",") + "]"
				}
				fmt.Println(line)
			}
		}
		fmt.Println()
	}

	// ── Accessible resources (SSAR capability matrix) ─────────────────────────
	fmt.Printf("%s▶ Accessible Resources (%d)%s\n", colorBold, len(r.Capabilities), colorReset)
	if len(r.Capabilities) == 0 {
		fmt.Printf("  (none detected via SSAR)\n\n")
		return
	}
	fmt.Printf("  %-34s %-18s %s\n", "Resource", "Namespace", "Allowed verbs")
	fmt.Printf("  %s\n", strings.Repeat("-", 68))
	for _, ra := range r.Capabilities {
		ns := ra.Namespace
		if ra.ClusterScope {
			ns = "(cluster)"
		}
		fmt.Printf("  %-34s %-18s %s\n", ra.Resource, ns, colorGreen+strings.Join(ra.AllowedVerbs, ",")+colorReset)
	}
	fmt.Println()
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
