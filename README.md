<p align="center">
  <img width="340" alt="k8scout logo" src="./web/img/k8scout_logo.png" />
</p>
<p align="center">
  <img alt="GitHub stars" src="https://img.shields.io/github/stars/k8scout/k8scout?style=flat" />
  <img alt="GitHub forks" src="https://img.shields.io/github/forks/k8scout/k8scout?style=flat" />
  <img alt="GitHub issues" src="https://img.shields.io/github/issues/k8scout/k8scout?style=flat" />
  <img alt="GitHub license" src="https://img.shields.io/github/license/k8scout/k8scout" />
</p>
<h1 align="center">k8scout</h1>

> **Beta** — A single-binary Kubernetes attack path engine for authorized security assessments.

Drop it into a compromised pod, run it, and get a map of every realistic escalation path — from your current foothold to cluster-admin, node access, secret theft, and cloud IAM roles.

---

## The idea

You have RCE in a Kubernetes pod. Now what?

k8scout answers that question. It automatically discovers what the compromised pod's service account can do, maps out the RBAC graph, and traces multi-step attack paths from your exact foothold to high-value targets.

It works in two modes:

- **Offensive mode** (default) — run from inside a compromised pod. Discovers your identity, permissions, and all reachable escalation paths from your current position.
- **Reviewer mode** (`--reviewer-mode`) — run with a read-only SA to audit the full cluster attack surface for all identities.

---

## What it finds

k8scout builds a weighted permission graph and runs Dijkstra-based pathfinding to discover realistic multi-step attack chains:

- **Pod to cluster-admin** — through RBAC bindings, workload mutation, or CRB creation
- **Container escape to node** — via privileged containers, hostPID, hostNetwork, dangerous capabilities, or hostPath mounts
- **Lateral movement** — exec into other pods, steal their SA tokens, pivot through their permissions
- **Secret and credential theft** — mounted SA tokens, secrets, configmaps with leaked credentials, orphaned tokens
- **Cloud IAM escalation** — IRSA (AWS), GKE Workload Identity, Azure Workload Identity, projected token audience abuse
- **Impersonation chains** — SA-to-SA takeover through impersonation permissions
- **Workload mutation** — patch a deployment to change its SA, then inherit that SA's permissions
- **Webhook injection** — mutating webhook control to inject into future workloads
- **GitOps operator abuse** — ArgoCD, Flux, External Secrets, and Vault operator privilege escalation
- **Misconfiguration detection** — dangling bindings, wildcard verbs, automounted tokens, plaintext secrets in env vars

Every finding includes MITRE ATT&CK technique IDs, a risk score, and step-by-step attack path with the actual graph nodes involved. 50 detection rules in total.

---

## Quick start

### From a compromised pod (primary use case)

```bash
# Copy the binary into the pod
kubectl cp k8scout-linux-amd64 <ns>/<pod>:/tmp/k8scout

# Run it
kubectl exec -it <ns>/<pod> -- chmod +x /tmp/k8scout
kubectl exec -it <ns>/<pod> -- /tmp/k8scout --out /tmp/result.json

# Pull the results
kubectl cp <ns>/<pod>:/tmp/result.json ./result.json

# This flow works exactly like this in you're revshell!
```

The binary auto-detects it's running in-cluster, identifies the pod and SA, and starts pathfinding from your exact foothold.

> **Intended use**: Penetration testing engagements, red team operations, internal security reviews, and cluster hardening audits. Always obtain proper authorization before running against any cluster.

### From your local machine

```bash
# Uses ~/.kube/config or $KUBECONFIG
k8scout --all-namespaces --out result.json

# Target a single namespace
k8scout --namespace production --out result.json
```

### Reviewer mode (full cluster audit)

```bash
# Deploy the read-only RBAC and job
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/job.yaml

# Or run directly with reviewer permissions
k8scout --reviewer-mode --all-namespaces --out result.json
```

### With AI narrative

```bash
export OPENAI_API_KEY="sk-..."
k8scout --all-namespaces --out result.json
```

---

## Installation

### Pre-built binaries

Download from the [Releases](../../releases) page. All binaries are statically linked with no dependencies.

| Binary | Platform |
|---|---|
| `k8scout-linux-amd64` | Linux x86-64 |
| `k8scout-linux-arm64` | Linux ARM64 |
| `k8scout-darwin-amd64` | macOS Intel |
| `k8scout-darwin-arm64` | macOS Apple Silicon |

### Build from source

Requires Go 1.22+.

```bash
git clone https://github.com/hac01/k8scout
cd k8scout
make build          # native binary
make build-linux    # static Linux amd64 binary
make build-all      # all four release targets
```

---

## How it works

```
k8scout (running inside compromised pod)
 |
 ├── 1. Detect foothold
 │     Pod name (HOSTNAME), SA (TokenReview), Node (downward API)
 │
 ├── 2. Discover permissions
 │     SSRR per namespace + ~30 concurrent SSAR spot-checks
 │     (always permitted, no RBAC needed)
 │
 ├── 3. Enumerate cluster objects (graceful degradation if denied)
 │     Namespaces, RBAC, Workloads, Pods, Secrets, Nodes, Webhooks, CRDs
 │
 ├── 4. Build attack graph
 │     Nodes: pods, SAs, roles, bindings, secrets, workloads, nodes, cloud identities
 │     Edges: runs_as, mounts, authenticates_as, can_exec, can_patch,
 │            can_impersonate, runs_on, assumes_cloud_role, granted_by, ...
 │
 ├── 5. Find attack paths (Dijkstra from foothold to high-value targets)
 │     Weighted by attacker effort — cheapest (most realistic) paths first
 │     Targets: cluster-admin, nodes, SA tokens, cloud IAM, privileged workloads
 │
 ├── 6. Run inference rules (50 rules with MITRE ATT&CK mapping)
 │
 ├── 7. Optional: AI risk narrative (GPT-4o)
 │
 └── 8. Output: text summary + JSON report
```

Even with a minimal SA that can't list pods or RBAC objects, the tool synthesizes the foothold graph from identity data alone and discovers what's reachable through SSRR/SSAR permissions.

---

## Attack graph visualization

Load the JSON report into `web/graph.html` in any browser (drag-and-drop, no server needed).

- **Attack Paths tab** — ranked by risk score, each showing the full multi-hop chain from foothold to target
- **Multi-chain view** — visualize overlapping attack paths simultaneously on a single graph
- **Force-directed graph** — all nodes and edges with color-coded categories and risk score rings
- **Focus mode** — dims structural noise to highlight attack-relevant nodes
- **RBAC toggle** — hides RBAC nodes but automatically shows them when part of an active attack path
- **Mini-map** — navigate large graphs without losing context
- **Node detail** — click any node for metadata, connections, and related findings
- **Export** — download a self-contained HTML pentest report

---

## CLI reference

```
k8scout [flags]

Flags:
  --out string            Output JSON file path (default "k8scout-result.json")
  --namespace string      Enumerate a single namespace
  --all-namespaces        Enumerate all accessible namespaces (default true)
  --format string         Output format: text | json (default "text")
  --timeout int           Per-request timeout in seconds (default 60)
  --log-level string      debug | info | warn | error (default "info")
  --kubeconfig string     Path to kubeconfig (auto-detected if not set)
  --reviewer-mode         Full cluster RBAC audit for all identities
  --stealth               Skip SSRR/SSAR to reduce audit log footprint
  --skip-ssar             Skip SSAR spot-checks only
  --openai-key string     OpenAI API key (or OPENAI_API_KEY env var)
  --openai-model string   OpenAI model (default "gpt-4o")
  --skip-ai               Skip AI narrative generation
```

---

## RBAC requirements

**When running from a compromised pod**: No special RBAC needed. SSRR and SSAR are always permitted. The tool gracefully degrades if the SA can't list cluster objects — it still discovers permissions and generates findings from what's available.

**For full enumeration** (recommended for the k8scout SA): read-only access defined in `deploy/rbac.yaml`:

- `namespaces`, `nodes`: get, list
- `serviceaccounts`, `secrets` (metadata only), `configmaps`: get, list
- `pods`, `deployments`, `daemonsets`, `statefulsets`, `jobs`, `cronjobs`: get, list
- `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`: get, list
- `mutatingwebhookconfigurations`, `validatingwebhookconfigurations`: get, list

Secret values are never read unless the identity has confirmed GET permission via SSAR.

---

## Beta feedback

k8scout is in active development. If you hit a bug, false positive, or a detection gap in your cluster, please [open an issue](../../issues). False positives and missed paths are especially useful — include the anonymized finding JSON if possible.

---

## License

MIT
