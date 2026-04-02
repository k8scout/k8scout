# k8scout System Analysis

## A. System Understanding (End-to-End)

**Pipeline:** Kubernetes API -> `kube.Enumerate()` -> `graph.Build()` -> `graph.Infer()` -> `output.Report` -> JSON + D3.js frontend

1. **Collection** (`pkg/kube`): Gathers identity (WhoAmI/TokenReview), SSRR per-namespace, SSAR spot-checks for ~26 high-risk verb/resource combos, RBAC objects, workloads, pods, secrets meta, configmaps, nodes, webhooks, CRDs.

2. **Graph construction** (`pkg/graph/builder.go`): 5 passes:
   - Pass 1: Identity -> abstract resource nodes via SSRR/SSAR
   - Pass 2: RBAC binding expansion (CRB/RB nodes -> role nodes, grants/granted_by edges to subjects)
   - Pass 3: Workload/Pod -> SA (`runs_as` edges)
   - Pass 4: Volume mounts (workload -> secret/configmap)
   - Pass 5: Role -> target capability edges (`buildRoleCapabilityEdges`) + foothold anchoring + concrete exec/portforward edges

3. **Inference** (`pkg/graph/inference.go`): ~40 single-step rules (check closures), then `emitInferredEdges`, then lateral movement findings, then multi-hop BFS pathfinding via `FindPaths`.

4. **Pathfinding** (`pkg/graph/traverse.go`): BFS all-simple-paths from foothold nodes to `HighValueTargets`, max depth 8, max 50 paths per goal. Paths are scored via `PathShape` (4-stage model: Foothold -> Bridge -> Capability -> Target).

5. **Goals** (`pkg/graph/goals.go`): 6 goal kinds -- ClusterAdmin, NodeExec, SecretAccess, IdentityTakeover, WorkloadTakeover, CloudEscalation.

---

## B. Key Problems

### B1. Graph has two disconnected subgraphs masquerading as one

The graph has **abstract resource type nodes** (e.g. `resource:default:secrets`) from Pass 1 (SSRR/SSAR) AND **concrete instance nodes** (e.g. `secret:default:my-secret`) from Pass 2-4. These are **not connected to each other**. The identity node points to `resource:default:pods/exec` but the BFS needs to reach `pod:default:target-pod`. The `buildConcreteReachabilityEdges` function patches this for exec/portforward, but **only when SSAR data exists** -- stealth mode, reviewer mode, or missing permissions leave this disconnected.

### B2. FindPaths is exponential BFS without pruning

`FindPaths` enumerates **all** simple paths between two nodes up to depth 8. In a moderately sized cluster (500 nodes, 2000 edges), this can produce a combinatorial explosion. There is no visited-globally pruning, no early termination for path quality, and each path copies the visited set (`map[string]bool`). The `MaxPathsPerGoal = 50` cap limits output but not computation.

### B3. nodeByID is O(n) linear scan

`nodeByID` iterates all nodes every call. It's called inside the inner loop of `FindPaths` (for every edge expansion), making path traversal O(paths x edges x nodes). This should be a hash map.

### B4. Edge directionality blocks realistic traversal

RBAC edges go: `binding -> role` (EdgeBoundTo) and `binding -> subject` (EdgeGrants). BFS from a pod follows: `pod -> [runs_as] -> SA -> [granted_by] -> binding -> [bound_to] -> role`. This 4-hop chain works **only because** the `EdgeGrantedBy` reverse edge was explicitly added. But the `EdgeBoundTo` direction (binding -> role) is correct for BFS from SA toward the role. So this actually works. However:

- `EdgeGrants` goes binding -> SA (wrong direction for forward BFS from SA). The `EdgeGrantedBy` reversal fixes this.
- But `EdgeBoundTo` goes binding -> role, which is the **right** direction when traversing binding -> role.

The chain `pod -> [runs_as] -> SA -> [granted_by] -> CRB -> [bound_to] -> clusterrole:cluster-admin` is 4 hops and works. This is actually well-designed.

### B5. Pod -> Node edges are missing

There is **no edge from pods to the node they run on**. `PodInfo.Node` is collected but never turned into a graph edge. This means the attack path `pod:X -> node:Y` (container escape) is invisible to BFS. The `emitInferredEdges` function adds `identity -> node` for "create pods" but not `pod -> node` for "I'm running on this node."

### B6. Workload -> Pod edges are missing

Pods know their owner (`OwnerKind`, `OwnerName`) but there's no edge from workload to its pods. Both point to the SA independently. This means the graph treats pods and workloads as parallel leaves rather than a hierarchy. Not critical (both reach SA via `runs_as`), but prevents paths like `exec into pod -> pod belongs to deployment -> deployment's other pods`.

### B7. Impersonation chain not modeled

SSAR checks for `impersonate users/serviceaccounts`, but there are no edges modeling who can be impersonated -> what that grants. If SA-A can impersonate SA-B, there should be `SA-A -> [can_impersonate] -> SA-B` edges linking to SA-B's entire permission set. Currently this is a single-step finding with no graph traversal.

### B8. Single-step rules dominate the findings

The 40+ `inferenceRule` entries are single-step detections (e.g., "can list secrets"). They check raw SSRR/SSAR data directly, bypassing the graph entirely. This means most findings are **not graph-derived** -- they're permission lookups with graph nodes listed as "affected." The graph machinery is mostly used only by `inferMultiHopFindings`.

---

## C. Attack Path Gaps -- Concrete Missing Chains

### C1. Container Escape -> Node
```
pod:ns:privileged-pod -[runs_on]-> node:worker-1 -[kubelet_access]-> SA tokens on node
```
**Missing:** No `runs_on` edge from pod to node. No modeling of kubelet credential access.

### C2. Exec -> Token Theft -> Lateral Movement
```
current-pod -[can_exec]-> target-pod -[runs_as]-> sa:ns:powerful-sa -[granted_by]-> crb:admin -[bound_to]-> clusterrole:cluster-admin
```
**Status:** This actually works if SSAR data is present (concrete exec edges exist). But the title/description don't make this clear.

### C3. Impersonation Chain
```
current-sa -[can_impersonate]-> sa:kube-system:admin-sa -[granted_by]-> crb:admin -[bound_to]-> clusterrole:cluster-admin
```
**Missing:** No impersonation edges to specific target identities.

### C4. Secret Token -> SA Takeover
```
pod:ns:app -[mounts]-> secret:ns:sa-token -[authenticates_as]-> sa:ns:other-sa -[granted_by]-> ...
```
**Missing:** No edge from SA token secrets back to the SA they authenticate. Secrets are dead-end nodes.

### C5. Workload Mutation -> SA Hijack
```
identity -[can_patch]-> workload:ns:target -[runs_as]-> sa:ns:powerful-sa -[granted_by]-> ...
```
**Partially present:** `emitInferredEdges` adds `identity -> SA` shortcut edges for patch-deployment, but this skips the workload node, so the path doesn't show the actual attack chain.

### C6. Cloud IAM Escalation
```
pod -[runs_as]-> sa:ns:irsa-sa -[cloud_identity]-> arn:aws:iam::123:role/admin
```
**Missing:** Cloud roles are metadata on SA nodes, not separate reachable graph nodes. Cannot model cloud-plane lateral movement.

### C7. HostPath -> Node Filesystem Access
```
workload:ns:app -[mounts_hostpath]-> node-filesystem:/ -[read_write]-> /etc/kubernetes/pki
```
**Missing:** HostPath mounts are metadata strings, not graph edges to node objects.

---

## D. Recommendations

### D1. Graph Model Changes

1. **Add `runs_on` edges from pods to nodes.** `PodInfo.Node` already has the data. Create `Edge{From: podID, To: "node:"+pod.Node, Kind: EdgeRunsOn}`. This enables container-escape paths.

2. **Add `authenticates_as` edges from SA-token secrets to their SA.** When `SecretMeta.Type == "kubernetes.io/service-account-token"`, parse the SA name and add an edge. This makes secrets intermediate nodes, not dead ends.

3. **Model impersonation targets.** When SSAR confirms `impersonate` on `serviceaccounts` or `users`, add edges to each SA in the cluster. The current identity effectively becomes that SA.

4. **Add cloud IAM nodes.** When an SA has `cloud_role` metadata, create a `KindCloudIdentity` node and an edge `SA -> [assumes_cloud_role] -> cloud:aws:arn:...`. This makes cloud escalation a BFS-traversable target.

5. **Replace `emitInferredEdges` shortcuts with proper multi-hop edges.** Instead of `identity -> SA` for "can patch deployment," add `identity -> [can_patch] -> workload -> [runs_as] -> SA`. This preserves the attack chain visible in the path.

6. **Add hostPath -> node edges.** When a workload has hostPath mounts (especially `/`, `/etc`, `/var/run/docker.sock`), add `workload -> [hostpath_escape] -> node`.

### D2. Inference Logic Changes

1. **Separate detection from pathfinding.** The `inferenceRule` pattern (40 single-step rules) and `inferMultiHopFindings` (BFS) are independent systems. The single-step rules should be kept for quick wins but clearly labeled as "capability detections," not "attack paths." Multi-hop findings should be the primary output.

2. **Add edge-composition rules.** Instead of just checking "can X do Y," compose: "can X do Y, and Y leads to Z, and Z grants W." This is what `FindPaths` does, but the single-step rules pre-empt it by firing first.

3. **Inference should enrich the graph, not just emit findings.** Move `emitInferredEdges` to run inside `Build`, not `Infer`. The graph should be complete before pathfinding begins.

### D3. Pathfinding (CRITICAL)

1. **Replace BFS all-paths with prioritized DFS or Dijkstra.** The current BFS finds all simple paths, which is exponential. Use a priority queue (A* or Dijkstra) where edge weights represent attacker effort/likelihood. Return the top-K highest-scoring paths.

2. **Index the adjacency list.** Build `map[string][]Edge` (outbound adjacency) once before traversal. Currently `FindPaths` scans all edges for every node expansion.

3. **Index nodeByID.** Build `map[string]*Node` once. The current O(n) scan per lookup is the single biggest performance bottleneck.

4. **Prune non-productive edges during traversal.** Edges like `SA -> [member_of] -> namespace` should not be followed during attack path BFS -- they lead to dead ends. Either mark edges as traversable/non-traversable or maintain a whitelist of edge kinds that represent attacker progress.

5. **Consider bidirectional BFS.** Start from both the foothold and the goal, meet in the middle. This dramatically reduces the search space for long paths.

### D4. Data Collection Changes

1. **Collect pod-to-node assignment** (already done -- `PodInfo.Node` exists). Just need to turn it into a graph edge.

2. **Collect NetworkPolicy data.** Missing entirely. Network policies constrain lateral movement -- a pod behind a strict NetworkPolicy cannot reach the API server, which breaks many attack chains. This is the biggest collection gap.

3. **Collect PodSecurityAdmission/PodSecurityPolicy data.** PSA labels on namespaces determine whether privileged pods can be created. Without this, "create pods -> node access" inferences may be false positives.

4. **Collect token volume projection details.** Already partially done (`VolumeRef.Audience`), but the audience should be linked to specific cloud provider endpoints.

---

## E. Mental Model Upgrade

### Current Model
```
Identity --SSRR/SSAR--> Abstract Resource Types
          (disconnected)
Workloads --runs_as--> SAs --granted_by--> Bindings --bound_to--> Roles
Pods (parallel leaves, same SA link)
Secrets (dead ends)
Nodes (isolated, only reached by inferred edges)
```

### Proposed Model
```
                    +-------- can_exec --------+
                    |                          v
FOOTHOLD POD --runs_on--> NODE <--hostpath_escape-- PRIVILEGED WORKLOAD
     |                                                    |
     +--runs_as--> SA --granted_by--> CRB --bound_to--> CLUSTERROLE
                    |                                      |
                    +--can_impersonate--> OTHER SA --------+
                    |
                    +--assumes_cloud_role--> CLOUD IAM ROLE

SECRETS --authenticates_as--> SA (bidirectional link)

WORKLOADS --owns--> PODS (hierarchy)
```

**Key design principles:**

1. **Pod is the primary foothold, not identity.** Every path should be expressible as starting from a pod. The identity is an abstraction; the pod is where code runs.

2. **Every edge must represent an attacker action.** `runs_as` = "steal this SA token." `can_exec` = "get shell in this pod." `runs_on` = "escape container to this host." `granted_by` = "this binding gives these permissions." No edges that don't correspond to an exploitation step.

3. **Goals are concrete nodes, not abstract concepts.** `clusterrole:cluster-admin` is a goal because reaching it means you can bind yourself to it. `node:worker-1` is a goal because reaching it means host code execution. `cloud:aws:arn:...` is a goal because reaching it means cloud-plane access.

4. **Scores should reflect attacker effort per hop.** A 2-hop path through a privileged pod (exec -> escape) is more dangerous than a 6-hop RBAC chain through obscure bindings. Score by path structure, not just hop count.

---

## F. Proposed Architecture Improvements

### Attack Path Engine

```go
// Replace BFS-all-paths with priority-based search
type PathFinder struct {
    graph      *AdjacencyIndex  // pre-built outbound adjacency map
    goals      map[string]GoalNode
    edgeWeight func(Edge) float64 // lower = easier for attacker
}

// Returns top-K paths from any foothold to any goal, ranked by total weight
func (pf *PathFinder) FindTopPaths(footholds []string, k int) []ScoredPath

type ScoredPath struct {
    Path        AttackPath
    TotalWeight float64  // sum of edge weights (lower = more dangerous)
    GoalKind    GoalKind
}
```

### Adjacency Index (solves B2, B3)

```go
type AdjacencyIndex struct {
    nodes    map[string]*Node           // O(1) lookup
    outbound map[string][]*Edge         // O(1) neighbor lookup
    inbound  map[string][]*Edge         // for reverse traversal
}
```

### Edge Weight Model

| Edge Kind | Weight | Rationale |
|-----------|--------|-----------|
| `runs_as` | 0.1 | Automatic -- token is mounted |
| `can_exec` | 1.0 | Requires active exploitation |
| `runs_on` + privileged | 0.5 | Known escape techniques |
| `runs_on` + unprivileged | 5.0 | Hard to escape |
| `granted_by` | 0.1 | Structural -- no attacker action |
| `bound_to` | 0.1 | Structural |
| `can_impersonate` | 1.5 | Requires API call |
| `hostpath_escape` | 1.0 | Read/write node filesystem |
| `can_patch` workload | 2.0 | Must modify deployment spec |

Lower total weight = easier/more realistic attack path. This naturally ranks "pod -> SA -> CRB -> cluster-admin" (weight 0.3) above "identity -> patch deployment -> wait for rollout -> new SA -> binding chain" (weight 3.0+).

### Scoring System

The current `ScoreByShape` is a good start but should incorporate:

1. **Path weight** (sum of edge weights, as above)
2. **Goal value** (cluster-admin=10, node=9, cloud=9.5, secret=8.5)
3. **Foothold realism** (in-cluster pod > exec-reachable pod > abstract identity)
4. **Environmental constraints** (NetworkPolicy, PSA, taints -- currently not collected)

Final score = `GoalValue x (1 / (1 + TotalWeight)) x FootholdMultiplier`

This produces scores where a 2-hop privileged-pod-to-cluster-admin path scores ~9.5, while a theoretical 6-hop RBAC chain from an abstract identity scores ~4.0.
