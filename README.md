# k8scout

A single-binary Kubernetes security reconnaissance tool for authorized assessments. Drop it into a cluster, run it, and get a complete picture of every identity's effective permissions — plus an interactive graph of every privilege escalation path an attacker could exploit.

> **Intended use**: Penetration testing engagements, internal security reviews, and cluster hardening audits. Always obtain proper authorization before running against any cluster.

---

## What it does

Kubernetes RBAC is notoriously hard to reason about. ClusterRoles, RoleBindings, aggregated roles, group memberships — reading YAML doesn't tell you what a specific identity can *actually* do at runtime.

k8scout solves this by:

1. **Identifying who you are** — TokenReview to resolve the current username, UID, and group memberships
2. **Enumerating effective permissions** — SelfSubjectRulesReview per namespace, plus 22 targeted SelfSubjectAccessReview spot-checks for high-risk verb/resource pairs
3. **Mapping the full RBAC graph** — all ServiceAccounts (with cloud identity annotations), RoleBindings, ClusterRoles, and their relationships
4. **Discovering workloads** — Pods, Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, and their security postures
5. **Enumerating admission webhooks** — MutatingWebhookConfigurations and ValidatingWebhookConfigurations
6. **Detecting cloud identity bindings** — IRSA (AWS), Azure Workload Identity, GKE Workload Identity on service accounts
7. **Finding escalation paths** — 24 inference rules that combine permissions, workload configs, cloud bindings, and webhook posture to surface real attack vectors
8. **Tagging MITRE ATT&CK techniques** — every finding mapped to ATT&CK for Containers technique IDs
9. **Generating a report** — JSON output for pipelines, human-readable text summary, optional AI-powered executive narrative
10. **Interactive attack graph** — load the JSON into `web/graph.html` for a full D3.js visualization with the built-in Attack Chain Analyzer

---

## Quick start

**From your local machine** (uses `~/.kube/config` or `$KUBECONFIG`):

```bash
k8scout --format text --all-namespaces --out results.json
```

**Target a single namespace**:

```bash
k8scout --namespace production --format text
```

**With AI-generated risk summary**:

```bash
export OPENAI_API_KEY="sk-..."
k8scout --all-namespaces --out results.json
```

**Debug mode** (verbose logging):

```bash
k8scout --log-level debug --namespace dev
```

---

## Installation

### Pre-built binaries

Download the latest release from the [Releases](../../releases) page. All binaries are statically linked — no dependencies, just copy and run.

| Binary | Platform |
|---|---|
| `k8scout-linux-amd64` | Linux x86-64 |
| `k8scout-linux-arm64` | Linux ARM64 (Graviton, Ampere) |
| `k8scout-darwin-amd64` | macOS Intel |
| `k8scout-darwin-arm64` | macOS Apple Silicon |

```bash
chmod +x k8scout-linux-amd64
./k8scout-linux-amd64 --all-namespaces
```

### Build from source

Requires Go 1.22+.

```bash
git clone https://github.com/hac01/k8scout
cd k8scout

# Build for your local machine
make build

# Build a static Linux binary (for in-cluster deployment)
make build-linux

# Build all four release targets at once
make build-all

# Build multi-arch Docker image
make docker-build
```

**Available build targets:**

| Target | Output |
|---|---|
| `make build` | Native binary for current OS/arch |
| `make build-linux` | `k8scout-linux-amd64` — static ELF |
| `make build-linux-arm64` | `k8scout-linux-arm64` — static ELF |
| `make build-darwin` | `k8scout-darwin-amd64` |
| `make build-darwin-arm64` | `k8scout-darwin-arm64` |
| `make build-all` | All four release binaries |

---

## CLI reference

```
Usage: k8scout [flags]

Flags:
  --out string            Output file for JSON report (default "k8scout-result.json")
  --namespace string      Enumerate a single namespace instead of all
  --all-namespaces        Enumerate every accessible namespace (default true)
  --format string         Output format: text or json (default "text")
  --timeout int           Timeout per Kubernetes API call in seconds (default 60)
  --log-level string      Logging verbosity: debug | info | warn | error (default "info")
  --kubeconfig string     Path to kubeconfig (auto-detected if not set)
  --openai-key string     OpenAI API key (or set OPENAI_API_KEY env var)
  --openai-model string   OpenAI model for narrative generation (default "gpt-4o")
  --skip-ssar             Skip the 22 SelfSubjectAccessReview spot-checks
  --skip-ai               Skip AI narrative generation (default true)
  --reviewer-mode         Enumerate all service accounts in the cluster (requires broader RBAC)
  --version               Print version and exit
```

**Kubeconfig resolution order**: `--kubeconfig` flag → `$KUBECONFIG` env → `~/.kube/config` → in-cluster service account token.

---

## Deploying inside a cluster

For the realistic attacker perspective — enumerate permissions from inside the cluster:

```bash
# Create RBAC resources and run the Job
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/job.yaml

# Watch progress
make logs

# Pull results when done
make results
```

The Job runs as UID 65534 (nobody), read-only root filesystem, all Linux capabilities dropped, seccomp set to RuntimeDefault. Auto-cleans up 1 hour after completion.

---

## The web UI — Attack Chain Analyzer

Load your JSON report into `web/graph.html` in any browser (drag-and-drop, no server needed).

### Three panels

- **Findings & Attack Paths** — findings sorted by severity with MITRE ATT&CK badges, each with inline kubectl exploitation commands showing which identity to operate as. The Attack Paths tab runs BFS from your identity through the permission graph to high-value targets.
- **Permission graph** — force-directed D3.js graph with namespace hulls, risk score rings, and glow effects on critical nodes. Cross-namespace edges are highlighted in orange.
- **Node detail** — click any node for full metadata, risk score, blast radius, related findings, and all connections.

### Toolbar features

| Button | Function |
|---|---|
| `Open JSON` | Load a scan result |
| `Diff` | Load a second scan to compare against the first |
| `Cross-NS` | Toggle cross-namespace edge highlighting |
| `Export Report` | Download a self-contained HTML pentest report |
| `⛓` | Open Attack Chain Analyzer |

### Attack Chain Analyzer (⛓)

Select any service account from the dropdown to see a step-by-step attack chain built from its actual graph edges — specific kubectl commands using real resource names and real identities.

**AI modes** (requires OpenAI API key):

| Mode | What it generates |
|---|---|
| **AI Chain** | GPT-synthesized multi-hop attack chain with kubectl commands, pivot analysis, and second-order paths |
| **Blue Team** | Falco rules, Kubernetes audit policy entries, and Sigma rules for SIEM correlation |
| **Compare All SAs** | Ranks the top 5 riskiest service accounts in one prompt, explains attack chains for the top 2 |
| **Get Fix** (per finding) | Minimal RBAC change to remediate the finding, kubectl command, patched YAML, and side-effect analysis |

**Attack path playback** — click ▶ Play on any AI chain to step through the attack path animated on the graph (2s per step).

**Diff / Delta mode** — load a second JSON to see new findings, removed findings, new nodes, new edges, and risk score changes highlighted on the graph.

**Keyboard shortcuts**: `/` search · `F` fit · `+`/`-` zoom · `Esc` clear

---

## Risk findings and inference rules

24 rules run against the collected data and permission graph. All findings include MITRE ATT&CK for Containers technique IDs.

| Rule ID | Severity | Score | MITRE | What it catches |
|---|---|---|---|---|
| PRIVESC-CLUSTER-ADMIN-BINDING | CRITICAL | 10.0 | T1078.001 | Non-system identity bound to cluster-admin |
| PRIVESC-CREATE-CLUSTERROLEBINDING | CRITICAL | 10.0 | T1078.001 | Can create ClusterRoleBindings |
| PRIVESC-IMPERSONATE | CRITICAL | 9.8 | T1550 | Can impersonate users or service accounts |
| ESCAPE-NODE-COMPROMISE | CRITICAL | 9.8 | T1611 | hostPath to critical node paths + exec access |
| PRIVESC-MUTATING-WEBHOOK | CRITICAL | 9.5 | T1610 | Can patch MutatingWebhookConfigurations |
| CLOUD-IRSA-ESCALATION | CRITICAL | 9.5 | T1078.004 | SA with cloud IAM annotation bound to workload |
| PRIVESC-CREATE-ROLEBINDING | CRITICAL | 9.5 | T1078.001 | Can create RoleBindings |
| PRIVESC-PATCH-CLUSTERROLES | CRITICAL | 9.5 | T1078.001 | Can modify ClusterRoles directly |
| PRIVESC-CREATE-SA-TOKEN | CRITICAL | 9.0 | T1078.001 | Can mint tokens for any service account |
| PRIV-GET-SECRETS | CRITICAL | 9.0 | T1552.007 | Can read Secret values |
| TAKEOVER-PATCH-DAEMONSET | HIGH | 8.5 | T1610 | Can modify DaemonSets → code on every node |
| CONFIG-PRIVILEGED-CONTAINER | HIGH | 8.5 | T1611 | Privileged containers in the cluster |
| EXFIL-HELM-RELEASE | HIGH | 8.0 | T1552.007 | Helm release secrets accessible (may contain credentials) |
| CLOUD-PROJECTED-TOKEN-AUDIENCE | HIGH | 8.0 | T1078.004 | Projected SA token with non-Kubernetes audience (Vault, AWS STS, etc.) |
| CONFIG-WILDCARD-VERBS | HIGH | 8.0 | T1078.001 | Wildcard verbs or resources granted |
| CONFIG-HOST-NAMESPACE | HIGH | 8.0 | T1611 | Pods using hostPID or hostNetwork |
| TAKEOVER-PATCH-DEPLOYMENT | HIGH | 8.0 | T1610 | Can patch Deployments → workload takeover |
| ESCAPE-CREATE-POD | HIGH | 8.0 | T1610 | Can create Pods → node escape vectors |
| RUNTIME-EXEC-PODS | HIGH | 7.8 | T1609 | Can exec into running Pods |
| CONFIG-HOSTPATH-MOUNT | HIGH | 7.5 | T1611 | Sensitive host paths mounted (categorized by danger level) |
| PRIV-LIST-SECRETS | HIGH | 7.5 | T1552.007 | Can list Secret names across namespaces |
| RUNTIME-PORTFORWARD | MEDIUM | 5.5 | T1609 | Can port-forward to Pods |
| CONFIG-SECRETS-IN-ENV | MEDIUM | 5.0 | T1552.007 | Secrets exposed as environment variables |
| CONFIG-AUTOMOUNT-SA-TOKEN | LOW | 3.5 | T1552.007 | SA tokens auto-mounted in workloads |

---

## Cloud identity detection

k8scout detects service accounts annotated for cross-cloud IAM bindings:

| Cloud | Annotation | Rule |
|---|---|---|
| AWS EKS (IRSA) | `eks.amazonaws.com/role-arn` | CLOUD-IRSA-ESCALATION |
| Azure Workload Identity | `azure.workload.identity/client-id` | CLOUD-IRSA-ESCALATION |
| GKE Workload Identity | `iam.gke.io/gcp-service-account` | CLOUD-IRSA-ESCALATION |

When any of these SAs is bound to a running workload, the finding flags the cross-cloud escalation path — an attacker with exec access to that pod can obtain cloud provider credentials.

Projected service account tokens with non-Kubernetes audiences (`vault`, `sts.amazonaws.com`, etc.) are also flagged, as these tokens are valid outside the cluster.

---

## Output structure

```json
{
  "meta": { "tool": "k8scout", "version": "...", "timestamp": "...", "cluster": "..." },
  "identity": { "username": "system:serviceaccount:dev:ci-runner", "groups": [...] },
  "permissions": {
    "ssrr_by_namespace": { "dev": [...] },
    "ssar_checks": [{ "verb": "list", "resource": "secrets", "allowed": true }]
  },
  "cluster_objects": {
    "namespaces": [...],
    "workloads": [...],
    "secrets_meta": [...],
    "webhooks": [{ "name": "...", "kind": "Mutating", "failure_policy": "Fail" }]
  },
  "graph": { "nodes": [...], "edges": [...] },
  "risk_findings": [{
    "rule_id": "PRIVESC-CLUSTER-ADMIN-BINDING",
    "severity": "CRITICAL",
    "score": 10.0,
    "mitre_ids": ["T1078.001"],
    "affected_nodes": ["..."],
    "evidence": "..."
  }],
  "ai_narrative": { "summary": "...", "mitigations": ["..."], "model_used": "gpt-4o" }
}
```

Secret values are never read — only names and key names are collected unless the identity has confirmed GET permission.

---

## RBAC requirements

The tool's service account needs read-only access. `deploy/rbac.yaml` creates the appropriate ClusterRole:

- `namespaces`, `nodes`: get, list
- `serviceaccounts`, `secrets` (names only), `configmaps`: get, list
- `pods`, `deployments`, `daemonsets`, `statefulsets`, `jobs`, `cronjobs`: get, list
- `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`: get, list
- `mutatingwebhookconfigurations`, `validatingwebhookconfigurations`: get, list

SelfSubjectRulesReview and SelfSubjectAccessReview are always permitted in Kubernetes — used to check what the running identity can do.

---

## How it works

```
k8scout
 ├─ Build Kubernetes client (kubeconfig or in-cluster)
 ├─ Resolve target namespaces
 ├─ Enumerate (10 collection passes)
 │   ├─ Identity (TokenReview)
 │   ├─ Namespaces
 │   ├─ Permissions per namespace (SelfSubjectRulesReview)
 │   ├─ 22 spot-checks (SelfSubjectAccessReview)
 │   ├─ RBAC (ClusterRoles, RoleBindings, ServiceAccounts + cloud annotations)
 │   ├─ Workloads (Deployments, DaemonSets, StatefulSets, Jobs, CronJobs)
 │   ├─ Pods
 │   ├─ Secrets metadata (names + key names only; values when GET confirmed)
 │   ├─ Nodes
 │   └─ Admission webhooks (Mutating + Validating)
 ├─ Build permission graph (5 passes)
 │   ├─ Pass 1: SSRR/SSAR → permission edges
 │   ├─ Pass 2: RBAC binding expansion
 │   ├─ Pass 3: Workload → SA mappings
 │   ├─ Pass 4: Volume mount edges
 │   └─ Pass 5: Inferred edges (from 24 inference rules)
 ├─ Run inference engine → RiskFindings (with MITRE ATT&CK IDs)
 ├─ (Optional) Generate AI narrative
 └─ Write output (text to stdout, JSON to file)
```

---

## License

MIT
