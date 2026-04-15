package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)


// Build constructs the permission graph from raw enumeration data.
// It runs five passes (as described in the design doc):
//   Pass 1 — Direct SSRR/SSAR edges
//   Pass 2 — RBAC binding expansion
//   Pass 3 — Workload → SA edges
//   Pass 4 — Volume mount edges
//   Pass 5 — Inference (handled separately in inference.go)
func Build(result *kube.EnumerationResult, log *zap.Logger) *Graph {
	nm := make(nodeMap)
	var edges []Edge

	// ── Register the current identity node ───────────────────────────────────
	identityID := "identity:" + result.Identity.Username
	identityNode := &Node{
		ID:        identityID,
		Kind:      KindIdentity,
		Name:      result.Identity.Username,
		Namespace: result.Identity.Namespace,
		Metadata:  map[string]string{"groups": strings.Join(result.Identity.Groups, ",")},
	}
	nm[identityID] = identityNode

	// ── Pass 1: SSRR → direct permission edges ───────────────────────────────
	for ns, rules := range result.Permissions.SSRRByNamespace {
		for _, rule := range rules {
			for _, verb := range rule.Verbs {
				ek := verbToEdgeKind(verb)
				if ek == "" {
					continue
				}
				for _, res := range rule.Resources {
					// Create a synthetic resource node representing the resource type.
					resID := resourceNodeID(res, ns)
					if _, ok := nm[resID]; !ok {
						nm[resID] = &Node{
							ID:        resID,
							Kind:      resourceToNodeKind(res),
							Name:      res,
							Namespace: ns,
						}
					}
					edges = append(edges, Edge{
						From:   identityID,
						To:     resID,
						Kind:   ek,
						Reason: fmt.Sprintf("SSRR rule in namespace %q", ns),
					})
				}
			}
		}
	}

	// Also layer SSAR checks as direct edges (more authoritative than SSRR).
	for _, check := range result.Permissions.SSARChecks {
		if !check.Allowed {
			continue
		}
		ek := verbToEdgeKind(check.Verb)
		if ek == "" {
			continue
		}
		ns := check.Namespace
		res := check.Resource
		if check.Subresource != "" {
			res = check.Resource + "/" + check.Subresource
		}
		resID := resourceNodeID(res, ns)
		if _, ok := nm[resID]; !ok {
			nm[resID] = &Node{
				ID:        resID,
				Kind:      resourceToNodeKind(check.Resource),
				Name:      res,
				Namespace: ns,
			}
		}
		edges = append(edges, Edge{
			From:   identityID,
			To:     resID,
			Kind:   ek,
			Reason: "SSAR confirmed",
		})
	}

	// ── Passes 2–4: shared object graph (RBAC, workloads, pods, secrets, nodes) ─
	objEdges := buildObjectGraph(nm, result)
	edges = append(edges, objEdges...)

	// ── Pass 5: foothold anchoring and concrete lateral-movement edges ────────
	//
	// 5a. Synthesize the foothold subgraph when running in-cluster.
	//     Even when the SA lacks list-pods permission, we know our own pod name
	//     (HOSTNAME), SA (TokenReview), and node (downward API). Create these
	//     nodes if they don't already exist so attack paths always start from
	//     a concrete foothold: pod → SA → identity → SSRR capabilities.
	if result.Identity.InCluster && result.Identity.PodName != "" {
		podID := "pod:" + result.Identity.Namespace + ":" + result.Identity.PodName

		// Create or update the foothold pod node.
		if _, ok := nm[podID]; !ok {
			nm[podID] = &Node{
				ID:        podID,
				Kind:      KindPod,
				Name:      result.Identity.PodName,
				Namespace: result.Identity.Namespace,
				Metadata:  map[string]string{},
			}
			log.Info("synthesized foothold pod node (SA cannot list pods)", zap.String("pod", podID))
		}
		n := nm[podID]
		if n.Metadata == nil {
			n.Metadata = map[string]string{}
		}
		n.Metadata["is_foothold"] = "true"
		if result.Identity.OwnerWorkload != "" {
			n.Metadata["owner_workload"] = result.Identity.OwnerWorkload
			n.Metadata["owner_workload_kind"] = result.Identity.OwnerWorkloadKind
		}
		if n.RiskScore < 5.0 {
			n.RiskScore = 5.0
		}
		log.Info("foothold node anchored", zap.String("pod", podID))

		// Synthesize the SA node and pod→SA edge if the SA is known.
		if result.Identity.SAName != "" {
			saID := "sa:" + result.Identity.Namespace + ":" + result.Identity.SAName
			if _, ok := nm[saID]; !ok {
				nm[saID] = &Node{
					ID:        saID,
					Kind:      KindServiceAccount,
					Name:      result.Identity.SAName,
					Namespace: result.Identity.Namespace,
					Metadata:  map[string]string{},
				}
				log.Info("synthesized SA node for foothold", zap.String("sa", saID))
			}
			// pod → runs_as → SA (if not already present).
			if !hasEdge(edges, podID, saID, EdgeRunsAs) {
				edges = append(edges, Edge{
					From:   podID,
					To:     saID,
					Kind:   EdgeRunsAs,
					Reason: "foothold pod runs as this SA",
				})
			}
			// SA → identity (so paths can flow: pod → SA → identity → SSRR targets).
			if !hasEdge(edges, saID, identityID, EdgeRunsAs) {
				edges = append(edges, Edge{
					From:   saID,
					To:     identityID,
					Kind:   EdgeRunsAs,
					Reason: "SA authenticates as this API identity",
				})
			}
		}

		// Synthesize the host node if known (informational — no runs_on edge
		// unless the pod is actually escapable; runs_on implies container escape).
		if result.Identity.NodeName != "" {
			nodeID := "node:" + result.Identity.NodeName
			if _, ok := nm[nodeID]; !ok {
				nm[nodeID] = &Node{
					ID:       nodeID,
					Kind:     KindNode,
					Name:     result.Identity.NodeName,
					Metadata: map[string]string{},
				}
				log.Info("synthesized node for foothold host", zap.String("node", nodeID))
			}
			nn := nm[nodeID]
			if nn.Metadata == nil {
				nn.Metadata = map[string]string{}
			}
			nn.Metadata["is_foothold_node"] = "true"
		}
	}

	// 5b. Bridge SA → identity for ALL modes (in-cluster and out-of-cluster).
	//     This ensures paths can flow: SA → identity → SSRR/SSAR targets.
	//     Weight is 0.1 (EdgeRunsAs) — a zero-effort transition since the SA IS the identity.
	//     Replaces the old EdgeInferred shortcut (weight 2.0) that hid the real chain.
	if result.Identity.SAName != "" {
		saID := saNodeID(result.Identity.Namespace, result.Identity.SAName)
		if nm[saID] != nil {
			if !hasEdge(edges, saID, identityID, EdgeRunsAs) {
				edges = append(edges, Edge{
					From:   saID,
					To:     identityID,
					Kind:   EdgeRunsAs,
					Reason: "SA authenticates as this API identity",
				})
			}
		}
	}

	// 5c. Emit concrete per-pod exec and portforward edges from SSAR checks.
	edges = append(edges, buildConcreteReachabilityEdges(nm, result, identityID)...)

	// 5d. Emit concrete identity → resource edges for all SSAR-confirmed permissions.
	//     This bridges the abstract/concrete gap: the identity gets edges to
	//     actual workloads, secrets, and SAs — not just abstract resource type nodes.
	edges = append(edges, buildConcreteIdentityEdges(nm, result, identityID)...)

	// ── Materialize nodeMap → []Node ─────────────────────────────────────────
	nodes := make([]Node, 0, len(nm))
	for _, n := range nm {
		nodes = append(nodes, *n)
	}

	g := &Graph{Nodes: nodes, Edges: edges}

	// ── Pass 6: Inferred edges (moved from inference.go) ─────────────────────
	// Must run before BuildIndex so the index includes inferred edges, and
	// before any pathfinding so all traversable edges are visible.
	emitInferredEdges(g, result)

	// ── Pass 7: Transitive SA capability edges ───────────────────────────────
	// Collapse RBAC chains: SA → granted_by → binding → bound_to → role → cap → target
	// into direct SA → cap → target edges. This reduces path length by 2-3 hops
	// and enables deeper multi-step attack chains within the depth limit.
	emitTransitiveSAEdges(g, log)

	// ── Pass 7b: Active enrichment — derived SA capability edges ─────────────
	// When SSRR was run as derived identities (via impersonation), create
	// concrete capability edges from those SAs to the resources they can access.
	// This is the key enabler for multi-level attack paths: the graph now knows
	// what SAs we can "become" AND what those SAs can do.
	emitDerivedSSRREdges(g, result, log)

	// ── Pass 8: Derived foothold edges ───────────────────────────────────────
	// When identity can patch/exec into a workload, model the full takeover:
	// the target workload's SA capabilities become reachable from the identity.
	emitDerivedFootholdEdges(g, result, log)

	// ── Pass 9: Node-derived expansion ──────────────────────────────────────
	// When an attacker escapes to a node (privileged pod → runs_on → node),
	// they gain access to SA tokens of all pods running on that node.
	// Emit node → [can_get] → SA edges for co-located pods.
	emitNodeDerivedEdges(g, result, log)

	// ── Pass 10: Mount-derived SA capabilities ──────────────────────────────
	// When a derived SA has no RBAC capability edges, infer that it can
	// access the secrets/configmaps mounted by its own workloads.
	emitMountDerivedSAEdges(g, log)

	// ── Build adjacency index for O(1) lookups during traversal ──────────────
	g.BuildIndex()

	log.Info("graph built",
		zap.Int("nodes", len(g.Nodes)),
		zap.Int("edges", len(g.Edges)),
		zap.Bool("in_cluster", result.Identity.InCluster))

	return g
}

// BuildReviewer constructs the permission graph for reviewer mode.
// Instead of a single current-identity node it creates nodes for ALL RBAC subjects
// whose effective permissions were computed from RBAC rules, giving a full cluster
// attack-surface view.
func BuildReviewer(result *kube.ReviewerEnumerateResult, log *zap.Logger) *Graph {
	nm := make(nodeMap)
	var edges []Edge

	// ── Pass 1-reviewer: one node per computed identity + RBAC-derived edges ──
	for _, ip := range result.AllIdentityPerms {
		nodeID := reviewerIdentityNodeID(ip)
		nodeKind := KindServiceAccount
		if ip.SubjectKind != "ServiceAccount" {
			nodeKind = KindIdentity
		}

		if _, ok := nm[nodeID]; !ok {
			nm[nodeID] = &Node{
				ID:        nodeID,
				Kind:      nodeKind,
				Name:      ip.Name,
				Namespace: ip.Namespace,
				Metadata: map[string]string{
					"subject":     ip.Subject,
					"bound_roles": strings.Join(ip.BoundRoles, "; "),
				},
			}
		}

		// Add permission edges from this identity's computed RBAC rules.
		for _, rule := range ip.Rules {
			for _, verb := range rule.Verbs {
				ek := verbToEdgeKind(verb)
				if ek == "" {
					continue
				}
				// Use the SA's own namespace as the edge scope; cluster-scoped resources get "".
				ns := ip.Namespace
				for _, res := range rule.Resources {
					resID := resourceNodeID(res, ns)
					if _, ok := nm[resID]; !ok {
						nm[resID] = &Node{
							ID:        resID,
							Kind:      resourceToNodeKind(res),
							Name:      res,
							Namespace: ns,
						}
					}
					edges = append(edges, Edge{
						From:   nodeID,
						To:     resID,
						Kind:   ek,
						Reason: fmt.Sprintf("RBAC rule for %s", ip.Subject),
					})
				}
			}
		}
	}

	// ── Passes 2–4: shared object graph ───────────────────────────────────────
	objEdges := buildObjectGraph(nm, result.EnumerationResult)
	edges = append(edges, objEdges...)

	nodes := make([]Node, 0, len(nm))
	for _, n := range nm {
		nodes = append(nodes, *n)
	}

	g := &Graph{Nodes: nodes, Edges: edges}
	g.BuildIndex()

	log.Info("reviewer graph built",
		zap.Int("nodes", len(g.Nodes)),
		zap.Int("edges", len(g.Edges)),
		zap.Int("identities", len(result.AllIdentityPerms)))

	return g
}

// ── Shared helper: passes 2–4 ─────────────────────────────────────────────────

// buildObjectGraph populates nm with RBAC/workload/pod/secret/node objects and returns
// the corresponding edges. Used by both Build (single identity) and BuildReviewer (all SAs).
func buildObjectGraph(nm nodeMap, result *kube.EnumerationResult) []Edge {
	var edges []Edge

	// Register namespace nodes.
	for _, ns := range result.ClusterObjects.Namespaces {
		id := "ns:" + ns.Name
		nm[id] = &Node{ID: id, Kind: KindNamespace, Name: ns.Name}
	}

	// Register ServiceAccount nodes so binding edges can reference them.
	for _, sa := range result.ClusterObjects.ServiceAccounts {
		id := saNodeID(sa.Namespace, sa.Name)
		if _, ok := nm[id]; !ok {
			meta := map[string]string{}
			if sa.IRSARole != "" {
				meta["cloud_role"] = sa.IRSARole
				meta["cloud_provider"] = "aws"
			} else if sa.AzureIdentity != "" {
				meta["cloud_role"] = sa.AzureIdentity
				meta["cloud_provider"] = "azure"
			} else if sa.GCPServiceAccount != "" {
				meta["cloud_role"] = sa.GCPServiceAccount
				meta["cloud_provider"] = "gcp"
			}
			node := &Node{
				ID:        id,
				Kind:      KindServiceAccount,
				Name:      sa.Name,
				Namespace: sa.Namespace,
			}
			if len(meta) > 0 {
				node.Metadata = meta
			}
			nm[id] = node
		} else {
			// Enrich existing node with cloud role metadata.
			existing := nm[id]
			if sa.IRSARole != "" {
				if existing.Metadata == nil {
					existing.Metadata = map[string]string{}
				}
				existing.Metadata["cloud_role"] = sa.IRSARole
				existing.Metadata["cloud_provider"] = "aws"
			} else if sa.AzureIdentity != "" {
				if existing.Metadata == nil {
					existing.Metadata = map[string]string{}
				}
				existing.Metadata["cloud_role"] = sa.AzureIdentity
				existing.Metadata["cloud_provider"] = "azure"
			} else if sa.GCPServiceAccount != "" {
				if existing.Metadata == nil {
					existing.Metadata = map[string]string{}
				}
				existing.Metadata["cloud_role"] = sa.GCPServiceAccount
				existing.Metadata["cloud_provider"] = "gcp"
			}
		}
		nsID := "ns:" + sa.Namespace
		if _, ok := nm[nsID]; ok {
			edges = append(edges, Edge{
				From:   id,
				To:     nsID,
				Kind:   EdgeMemberOf,
				Reason: "ServiceAccount in namespace",
			})
		}
	}

	// Register CRD nodes for dangerous operator CRDs.
	for _, crd := range result.ClusterObjects.CRDs {
		id := "crd:" + crd.Group + "/" + crd.Resource
		nm[id] = &Node{
			ID:   id,
			Kind: KindCRD,
			Name: crd.Kind,
			Metadata: map[string]string{
				"group":    crd.Group,
				"resource": crd.Resource,
				"scope":    crd.Scope,
			},
		}
	}

	// Register Webhook nodes.
	for _, wh := range result.ClusterObjects.Webhooks {
		wid := "webhook:" + wh.Name
		nm[wid] = &Node{
			ID:   wid,
			Kind: KindWebhook,
			Name: wh.Name,
			Metadata: map[string]string{
				"webhook_kind":    wh.Kind,
				"failure_policy":  wh.FailurePolicy,
				"service_name":    wh.ServiceName,
				"service_ns":      wh.ServiceNS,
			},
		}
	}

	// Pass 2: RBAC binding expansion.
	for _, cr := range result.ClusterObjects.ClusterRoles {
		id := "clusterrole:" + cr.Name
		nm[id] = &Node{ID: id, Kind: KindClusterRole, Name: cr.Name}
	}
	for _, r := range result.ClusterObjects.Roles {
		id := "role:" + r.Namespace + ":" + r.Name
		nm[id] = &Node{ID: id, Kind: KindRole, Name: r.Name, Namespace: r.Namespace}
	}
	for _, crb := range result.ClusterObjects.ClusterRoleBindings {
		crbID := "crb:" + crb.Name
		nm[crbID] = &Node{ID: crbID, Kind: KindClusterRoleBinding, Name: crb.Name}
		roleID := resolveRoleRefID(crb.RoleRef, "")
		edges = append(edges, Edge{From: crbID, To: roleID, Kind: EdgeBoundTo, Reason: "ClusterRoleBinding → role"})
		for _, subj := range crb.Subjects {
			if subjID := subjectNodeID(subj); subjID != "" {
				edges = append(edges, Edge{
					From:   crbID,
					To:     subjID,
					Kind:   EdgeGrants,
					Reason: fmt.Sprintf("ClusterRoleBinding %q grants %s", crb.Name, roleID),
				})
				// Reverse edge: SA → CRB so BFS can traverse workload → SA → binding → role.
				edges = append(edges, Edge{
					From:   subjID,
					To:     crbID,
					Kind:   EdgeGrantedBy,
					Reason: fmt.Sprintf("%s is subject of ClusterRoleBinding %q", subjID, crb.Name),
				})
			}
		}
	}
	for _, rb := range result.ClusterObjects.RoleBindings {
		rbID := "rb:" + rb.Namespace + ":" + rb.Name
		nm[rbID] = &Node{ID: rbID, Kind: KindRoleBinding, Name: rb.Name, Namespace: rb.Namespace}
		roleID := resolveRoleRefID(rb.RoleRef, rb.Namespace)
		edges = append(edges, Edge{From: rbID, To: roleID, Kind: EdgeBoundTo, Reason: "RoleBinding → role"})
		for _, subj := range rb.Subjects {
			if subjID := subjectNodeID(subj); subjID != "" {
				edges = append(edges, Edge{
					From:   rbID,
					To:     subjID,
					Kind:   EdgeGrants,
					Reason: fmt.Sprintf("RoleBinding %q in %q grants %s", rb.Name, rb.Namespace, roleID),
				})
				// Reverse edge: SA → RB so BFS can traverse workload → SA → binding → role.
				edges = append(edges, Edge{
					From:   subjID,
					To:     rbID,
					Kind:   EdgeGrantedBy,
					Reason: fmt.Sprintf("%s is subject of RoleBinding %q in %q", subjID, rb.Name, rb.Namespace),
				})
			}
		}
	}

	// Pass 3: Workload → SA (runs_as) edges + Pass 4: volume mount edges.
	for _, wl := range result.ClusterObjects.Workloads {
		wlID := "workload:" + wl.Namespace + ":" + wl.Name
		wlMeta := map[string]string{"workload_kind": wl.Kind}
		if len(wl.PrivilegedContainers) > 0 {
			wlMeta["privileged_containers"] = strings.Join(wl.PrivilegedContainers, ",")
		}
		if wl.HostPID {
			wlMeta["host_pid"] = "true"
		}
		if wl.HostNetwork {
			wlMeta["host_network"] = "true"
		}
		if wl.HostIPC {
			wlMeta["host_ipc"] = "true"
		}
		if len(wl.DangerousCapabilities) > 0 {
			wlMeta["dangerous_capabilities"] = strings.Join(wl.DangerousCapabilities, ",")
		}
		if len(wl.HostPathMounts) > 0 {
			wlMeta["host_path_mounts"] = strings.Join(wl.HostPathMounts, ",")
		}
		// Base risk score: all workloads are potential footholds; elevated for dangerous configs.
		wlRisk := workloadBaseRisk(len(wl.PrivilegedContainers) > 0, wl.HostPID, wl.HostNetwork, wl.HostIPC,
			len(wl.DangerousCapabilities) > 0, len(wl.HostPathMounts) > 0)
		nm[wlID] = &Node{
			ID:        wlID,
			Kind:      KindWorkload,
			Name:      wl.Name,
			Namespace: wl.Namespace,
			Metadata:  wlMeta,
			RiskScore: wlRisk,
		}
		if wl.ServiceAccount != "" {
			saID := saNodeID(wl.Namespace, wl.ServiceAccount)
			edges = append(edges, Edge{
				From:   wlID,
				To:     saID,
				Kind:   EdgeRunsAs,
				Reason: fmt.Sprintf("%s runs as %s", wl.Kind, wl.ServiceAccount),
			})
		}
		for _, vol := range wl.Volumes {
			switch vol.SourceKind {
			case "Secret":
				secID := "secret:" + wl.Namespace + ":" + vol.SourceName
				if _, ok := nm[secID]; !ok {
					nm[secID] = &Node{ID: secID, Kind: KindSecret, Name: vol.SourceName, Namespace: wl.Namespace}
				}
				edges = append(edges, Edge{From: wlID, To: secID, Kind: EdgeMounts, Reason: fmt.Sprintf("volume %q", vol.Name)})
			case "ConfigMap":
				cmID := "configmap:" + wl.Namespace + ":" + vol.SourceName
				if _, ok := nm[cmID]; !ok {
					nm[cmID] = &Node{ID: cmID, Kind: KindConfigMap, Name: vol.SourceName, Namespace: wl.Namespace}
				}
				edges = append(edges, Edge{From: wlID, To: cmID, Kind: EdgeMounts, Reason: fmt.Sprintf("volume %q", vol.Name)})
			}
		}
		// Env-injected secret references create the same reachability as volume mounts.
		for _, ref := range wl.EnvSecretRefs {
			secID := "secret:" + wl.Namespace + ":" + ref.SecretName
			if _, ok := nm[secID]; !ok {
				nm[secID] = &Node{ID: secID, Kind: KindSecret, Name: ref.SecretName, Namespace: wl.Namespace}
			}
			edges = append(edges, Edge{From: wlID, To: secID, Kind: EdgeMounts,
				Reason: fmt.Sprintf("env secret ref %s→%s", ref.Container, ref.SecretName)})
		}
	}

	// Pods.
	for _, pod := range result.ClusterObjects.Pods {
		podID := "pod:" + pod.Namespace + ":" + pod.Name
		podMeta := map[string]string{}
		if len(pod.PrivilegedContainers) > 0 {
			podMeta["privileged_containers"] = strings.Join(pod.PrivilegedContainers, ",")
		}
		if pod.HostPID {
			podMeta["host_pid"] = "true"
		}
		if pod.HostNetwork {
			podMeta["host_network"] = "true"
		}
		if pod.HostIPC {
			podMeta["host_ipc"] = "true"
		}
		if pod.OwnerKind != "" {
			podMeta["owner_workload_kind"] = pod.OwnerKind
			podMeta["owner_workload"] = pod.OwnerName
		}
		podRisk := workloadBaseRisk(len(pod.PrivilegedContainers) > 0, pod.HostPID, pod.HostNetwork, pod.HostIPC,
			len(pod.DangerousCapabilities) > 0, len(pod.HostPathMounts) > 0)
		podNode := &Node{
			ID:        podID,
			Kind:      KindPod,
			Name:      pod.Name,
			Namespace: pod.Namespace,
			RiskScore: podRisk,
		}
		if len(podMeta) > 0 {
			podNode.Metadata = podMeta
		}
		nm[podID] = podNode
		if pod.ServiceAccount != "" {
			saID := saNodeID(pod.Namespace, pod.ServiceAccount)
			edges = append(edges, Edge{From: podID, To: saID, Kind: EdgeRunsAs, Reason: "Pod runs as ServiceAccount"})
		}
		// Pod → Node edge: connects pods to the node they run on.
		// Only emitted for pods with dangerous security configs (privileged,
		// hostPID/Net/IPC, dangerous caps, hostPath) since those represent
		// a realistic container-escape path to the host.
		if pod.Node != "" {
			nodeID := "node:" + pod.Node
			if canEscapeToHost(pod.PrivilegedContainers, pod.HostPID, pod.HostNetwork, pod.HostIPC,
				pod.DangerousCapabilities, pod.HostPathMounts) {
				edges = append(edges, Edge{
					From:   podID,
					To:     nodeID,
					Kind:   EdgeRunsOn,
					Reason: "container escape: pod has dangerous security config on this node",
				})
			}
		}
		for _, vol := range pod.Volumes {
			switch {
			case vol.SourceKind == "Secret" && vol.SourceName != "":
				secID := "secret:" + pod.Namespace + ":" + vol.SourceName
				if _, ok := nm[secID]; !ok {
					nm[secID] = &Node{ID: secID, Kind: KindSecret, Name: vol.SourceName, Namespace: pod.Namespace}
				}
				edges = append(edges, Edge{From: podID, To: secID, Kind: EdgeMounts, Reason: "pod volume"})
			case vol.SourceKind == "ConfigMap" && vol.SourceName != "":
				cmID := "configmap:" + pod.Namespace + ":" + vol.SourceName
				if _, ok := nm[cmID]; !ok {
					nm[cmID] = &Node{ID: cmID, Kind: KindConfigMap, Name: vol.SourceName, Namespace: pod.Namespace}
				}
				edges = append(edges, Edge{From: podID, To: cmID, Kind: EdgeMounts, Reason: "pod volume"})
			}
		}
		// Pod → owning workload edge: enables traversal from a taken-over pod
		// to its controlling workload's sibling resources (mounts, SA, node).
		if pod.OwnerKind != "" && pod.OwnerName != "" {
			wlID := "workload:" + pod.Namespace + ":" + pod.OwnerName
			if nm[wlID] != nil {
				edges = append(edges, Edge{
					From:   podID,
					To:     wlID,
					Kind:   EdgeRunsAs, // pod "runs as" its workload context
					Reason: fmt.Sprintf("pod owned by %s/%s", pod.OwnerKind, pod.OwnerName),
				})
			}
		}
	}

	// Secret nodes from metadata — enrich with capture status.
	for _, sm := range result.ClusterObjects.SecretsMeta {
		secID := "secret:" + sm.Namespace + ":" + sm.Name
		meta := map[string]string{"type": sm.Type}
		if len(sm.Values) > 0 {
			meta["has_captured_values"] = "true"
			meta["value_keys"] = strings.Join(sm.DataKeys, ",")
		}
		if existing, ok := nm[secID]; ok {
			// Node already exists (created from volume mount); enrich its metadata.
			if existing.Metadata == nil {
				existing.Metadata = meta
			} else {
				for k, v := range meta {
					existing.Metadata[k] = v
				}
			}
		} else {
			nm[secID] = &Node{
				ID:        secID,
				Kind:      KindSecret,
				Name:      sm.Name,
				Namespace: sm.Namespace,
				Metadata:  meta,
			}
		}
	}

	// ConfigMap nodes from metadata — enrich with capture status.
	for _, cm := range result.ClusterObjects.ConfigMapsMeta {
		cmID := "configmap:" + cm.Namespace + ":" + cm.Name
		meta := map[string]string{}
		if len(cm.Data) > 0 {
			meta["has_captured_data"] = "true"
			meta["data_keys"] = strings.Join(cm.DataKeys, ",")
		}
		if existing, ok := nm[cmID]; ok {
			if existing.Metadata == nil {
				existing.Metadata = meta
			} else {
				for k, v := range meta {
					existing.Metadata[k] = v
				}
			}
		} else {
			nm[cmID] = &Node{
				ID:        cmID,
				Kind:      KindConfigMap,
				Name:      cm.Name,
				Namespace: cm.Namespace,
				Metadata:  meta,
			}
		}
	}

	// Node nodes.
	for _, n := range result.ClusterObjects.Nodes {
		nid := "node:" + n.Name
		nm[nid] = &Node{ID: nid, Kind: KindNode, Name: n.Name}
	}

	// Pass 5 (new): Role→target capability edges.
	edges = append(edges, buildRoleCapabilityEdges(nm, result)...)

	// Pass 6: SA token secret → SA edges (authenticates_as).
	// Kubernetes service-account-token secrets can be stolen and used to
	// authenticate as the owning SA. This creates traversable edges:
	//   pod → [mounts] → secret → [authenticates_as] → SA → ...
	for _, sm := range result.ClusterObjects.SecretsMeta {
		if sm.Type != "kubernetes.io/service-account-token" || sm.SAName == "" {
			continue
		}
		secID := "secret:" + sm.Namespace + ":" + sm.Name
		saID := saNodeID(sm.Namespace, sm.SAName)
		if nm[secID] != nil && nm[saID] != nil {
			edges = append(edges, Edge{
				From:   secID,
				To:     saID,
				Kind:   EdgeAuthenticatesAs,
				Reason: fmt.Sprintf("SA token secret authenticates as %s", sm.SAName),
			})
		}
	}

	// Pass 7: Cloud IAM identity nodes + edges.
	// When a SA has a cloud workload identity annotation, create a CloudIdentity
	// node and an assumes_cloud_role edge. This makes cloud escalation a
	// traversable target: pod → [runs_as] → SA → [assumes_cloud_role] → cloud:...
	for _, sa := range result.ClusterObjects.ServiceAccounts {
		cloudRole := sa.IRSARole
		provider := "aws"
		if cloudRole == "" {
			cloudRole = sa.GCPServiceAccount
			provider = "gcp"
		}
		if cloudRole == "" {
			cloudRole = sa.AzureIdentity
			provider = "azure"
		}
		if cloudRole == "" {
			continue
		}
		cloudID := "cloud:" + provider + ":" + cloudRole
		if _, ok := nm[cloudID]; !ok {
			nm[cloudID] = &Node{
				ID:   cloudID,
				Kind: KindCloudIdentity,
				Name: cloudRole,
				Metadata: map[string]string{
					"cloud_provider": provider,
					"cloud_role":     cloudRole,
				},
				RiskScore: 9.0,
			}
		}
		saID := saNodeID(sa.Namespace, sa.Name)
		if nm[saID] != nil {
			edges = append(edges, Edge{
				From:   saID,
				To:     cloudID,
				Kind:   EdgeAssumesCloudRole,
				Reason: fmt.Sprintf("SA annotated with %s cloud identity %q", provider, cloudRole),
			})
		}
	}

	// Mutating webhooks → workloads they can intercept.
	// A compromised mutating webhook can inject sidecars, modify images, or steal
	// tokens for all future pods in its intercept scope.
	for _, wh := range result.ClusterObjects.Webhooks {
		if wh.Kind != "Mutating" {
			continue
		}
		whID := "webhook:" + wh.Name
		if nm[whID] == nil {
			continue
		}
		for _, wl := range result.ClusterObjects.Workloads {
			if wh.HasNamespaceSelector && wh.ServiceNS != wl.Namespace {
				continue
			}
			wlID := "workload:" + wl.Namespace + ":" + wl.Name
			if nm[wlID] != nil {
				edges = append(edges, Edge{
					From:   whID,
					To:     wlID,
					Kind:   EdgeInferred,
					Reason: fmt.Sprintf("mutating webhook %q can intercept workload creation/updates", wh.Name),
				})
			}
		}
	}

	return edges
}

// buildRoleCapabilityEdges adds edges from Role/ClusterRole nodes to the actual
// resources those roles grant access to.  Without these edges, BFS terminates
// at the role node for any role that is not itself a goal (e.g. cluster-admin),
// making the full RBAC chain workload→SA→binding→role→target unreachable.
//
// Edges are added for the following high-risk patterns:
//   • list/get secrets          → EdgeCanList/EdgeCanGet to each secret node
//   • create pods/exec          → EdgeCanExec  to each pod node
//   • list/get nodes            → EdgeCanList  to each node node
//   • patch deployments/etc.    → EdgeCanPatch to each workload node
//   • create/patch CRBs         → EdgeCanCreate to clusterrole:cluster-admin
//   • wildcard (*/*) verbs      → EdgeInferred  to clusterrole:cluster-admin
//
// ClusterRoles apply cluster-wide (all namespaces); namespace-scoped Roles
// apply only within their own namespace.
func buildRoleCapabilityEdges(nm nodeMap, result *kube.EnumerationResult) []Edge {
	seen := make(map[string]bool)
	var edges []Edge

	addE := func(from, to string, kind EdgeKind, reason string) {
		if nm[from] == nil || nm[to] == nil {
			return
		}
		key := from + "|" + string(kind) + "|" + to
		if seen[key] {
			return
		}
		seen[key] = true
		edges = append(edges, Edge{From: from, To: to, Kind: kind, Reason: reason})
	}

	// allows returns true if the rule grants the given verb on the given resource
	// (handles "*" wildcards in both verbs and resources).
	allows := func(rule kube.PolicyRule, verb, resource string) bool {
		return containsAny(rule.Verbs, verb, "*") && containsAny(rule.Resources, resource, "*")
	}

	// emitForRole adds capability edges for a single role.
	// clusterScoped=true means the role's rules apply to all namespaces.
	emitForRole := func(roleID string, rules []kube.PolicyRule, roleNS string, clusterScoped bool) {
		for _, rule := range rules {
			// Wildcard-everything (cluster-admin equivalent) → single shortcut edge.
			if containsAny(rule.Verbs, "*") && containsAny(rule.Resources, "*") {
				addE(roleID, "clusterrole:cluster-admin", EdgeInferred,
					roleID+" has wildcard permissions equivalent to cluster-admin")
				continue
			}

			// secrets: list / get
			if allows(rule, "list", "secrets") || allows(rule, "get", "secrets") {
				ek := EdgeCanList
				if allows(rule, "get", "secrets") {
					ek = EdgeCanGet
				}
				for _, sm := range result.ClusterObjects.SecretsMeta {
					if !clusterScoped && sm.Namespace != roleNS {
						continue
					}
					addE(roleID, "secret:"+sm.Namespace+":"+sm.Name, ek,
						roleID+" grants secret access")
				}
			}

			// configmaps: get — may contain leaked kubeconfigs or credentials
			if allows(rule, "get", "configmaps") || allows(rule, "list", "configmaps") {
				ek := EdgeCanList
				if allows(rule, "get", "configmaps") {
					ek = EdgeCanGet
				}
				for _, cm := range result.ClusterObjects.ConfigMapsMeta {
					if !clusterScoped && cm.Namespace != roleNS {
						continue
					}
					cmID := "configmap:" + cm.Namespace + ":" + cm.Name
					addE(roleID, cmID, ek, roleID+" grants configmap access")
				}
			}

			// pods/exec: create — enables lateral movement into pods
			if allows(rule, "create", "pods/exec") {
				for _, pod := range result.ClusterObjects.Pods {
					if !clusterScoped && pod.Namespace != roleNS {
						continue
					}
					addE(roleID, "pod:"+pod.Namespace+":"+pod.Name, EdgeCanExec,
						roleID+" grants pods/exec")
				}
			}

			// create pods (bare) — attacker can create pods running as any SA in
			// the allowed namespace(s), and schedule them on any node. This is a
			// critical escalation vector: create privileged pod → SA takeover + node escape.
			if allows(rule, "create", "pods") && !allows(rule, "create", "pods/exec") {
				// → SA edges: can launch pod as any SA in scope
				for _, sa := range result.ClusterObjects.ServiceAccounts {
					if !clusterScoped && sa.Namespace != roleNS {
						continue
					}
					addE(roleID, saNodeID(sa.Namespace, sa.Name), EdgeCanCreate,
						roleID+" grants create pods — can run pod as this SA")
				}
				// → Node edges: can schedule on any node
				for _, n := range result.ClusterObjects.Nodes {
					addE(roleID, "node:"+n.Name, EdgeCanCreate,
						roleID+" grants create pods — can schedule on node")
				}
			}

			// nodes: list / get — access to node objects is a high-value step
			if allows(rule, "list", "nodes") || allows(rule, "get", "nodes") {
				for _, n := range result.ClusterObjects.Nodes {
					addE(roleID, "node:"+n.Name, EdgeCanList, roleID+" grants node access")
				}
			}

			// workload takeover: patch / update on deployment, daemonset, statefulset
			for _, wlRes := range []string{"deployments", "daemonsets", "statefulsets"} {
				if allows(rule, "patch", wlRes) || allows(rule, "update", wlRes) {
					for _, wl := range result.ClusterObjects.Workloads {
						if !clusterScoped && wl.Namespace != roleNS {
							continue
						}
						addE(roleID, "workload:"+wl.Namespace+":"+wl.Name, EdgeCanPatch,
							roleID+" grants patch on "+wlRes)
					}
					break // avoid duplicate edges for same workload from multiple wlRes entries
				}
			}

			// pods/portforward: create — network access to pod services
			if allows(rule, "create", "pods/portforward") {
				for _, pod := range result.ClusterObjects.Pods {
					if !clusterScoped && pod.Namespace != roleNS {
						continue
					}
					addE(roleID, "pod:"+pod.Namespace+":"+pod.Name, EdgeCanPortForward,
						roleID+" grants pods/portforward")
				}
			}

			// pod/workload delete — enables sabotage and forced rescheduling attacks
			if allows(rule, "delete", "pods") || allows(rule, "deletecollection", "pods") {
				for _, pod := range result.ClusterObjects.Pods {
					if !clusterScoped && pod.Namespace != roleNS {
						continue
					}
					addE(roleID, "pod:"+pod.Namespace+":"+pod.Name, EdgeCanDelete,
						roleID+" grants pod delete")
				}
			}
			for _, wlRes := range []string{"deployments", "daemonsets", "statefulsets"} {
				if allows(rule, "delete", wlRes) {
					for _, wl := range result.ClusterObjects.Workloads {
						if !clusterScoped && wl.Namespace != roleNS {
							continue
						}
						addE(roleID, "workload:"+wl.Namespace+":"+wl.Name, EdgeCanDelete,
							roleID+" grants delete on "+wlRes)
					}
					break
				}
			}

			// clusterrolebinding / rolebinding create/patch → can self-escalate to cluster-admin
			// A CRB grants cluster-wide, a RB can bind a ClusterRole within a namespace.
			if allows(rule, "create", "clusterrolebindings") || allows(rule, "patch", "clusterrolebindings") {
				addE(roleID, "clusterrole:cluster-admin", EdgeCanCreate,
					roleID+" can create/patch CRBs — cluster-admin escalation path")
			}
			if allows(rule, "create", "rolebindings") || allows(rule, "patch", "rolebindings") {
				addE(roleID, "clusterrole:cluster-admin", EdgeCanBind,
					roleID+" can create/patch RoleBindings — can bind ClusterRole within namespace")
			}

			// mutating webhook patch → can inject into all future workloads
			if allows(rule, "patch", "mutatingwebhookconfigurations") || allows(rule, "update", "mutatingwebhookconfigurations") {
				for _, wh := range result.ClusterObjects.Webhooks {
					if wh.Kind == "Mutating" {
						addE(roleID, "webhook:"+wh.Name, EdgeCanPatch,
							roleID+" can patch mutating webhook "+wh.Name)
					}
				}
			}

			// impersonate serviceaccounts → identity takeover of any SA in scope
			if allows(rule, "impersonate", "serviceaccounts") || allows(rule, "impersonate", "users") {
				for _, sa := range result.ClusterObjects.ServiceAccounts {
					if !clusterScoped && sa.Namespace != roleNS {
						continue
					}
					addE(roleID, saNodeID(sa.Namespace, sa.Name), EdgeCanImpersonate,
						roleID+" grants impersonation of SA "+sa.Namespace+"/"+sa.Name)
				}
			}

			// create serviceaccounts/token → mint tokens for any SA, equivalent to identity takeover
			if allows(rule, "create", "serviceaccounts/token") {
				for _, sa := range result.ClusterObjects.ServiceAccounts {
					if !clusterScoped && sa.Namespace != roleNS {
						continue
					}
					addE(roleID, saNodeID(sa.Namespace, sa.Name), EdgeCanCreate,
						roleID+" grants create SA tokens — identity takeover of "+sa.Namespace+"/"+sa.Name)
				}
			}

			// escalate / bind clusterroles → can self-assign cluster-admin
			if allows(rule, "escalate", "clusterroles") || allows(rule, "bind", "clusterroles") {
				addE(roleID, "clusterrole:cluster-admin", EdgeCanEscalate,
					roleID+" grants escalate/bind on clusterroles — cluster-admin path")
			}
			if allows(rule, "escalate", "roles") || allows(rule, "bind", "roles") {
				addE(roleID, "clusterrole:cluster-admin", EdgeCanEscalate,
					roleID+" grants escalate/bind on roles — privilege escalation path")
			}
		}
	}

	for _, cr := range result.ClusterObjects.ClusterRoles {
		roleID := "clusterrole:" + cr.Name
		emitForRole(roleID, cr.Rules, "", true)
	}
	for _, r := range result.ClusterObjects.Roles {
		roleID := "role:" + r.Namespace + ":" + r.Name
		emitForRole(roleID, r.Rules, r.Namespace, false)
	}

	return edges
}

// reviewerIdentityNodeID returns the graph node ID for a computed identity.
func reviewerIdentityNodeID(ip kube.IdentityPermissions) string {
	if ip.SubjectKind == "ServiceAccount" {
		return saNodeID(ip.Namespace, ip.Name)
	}
	return "identity:" + ip.Name
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func verbToEdgeKind(verb string) EdgeKind {
	switch verb {
	case "list", "watch":
		return EdgeCanList
	case "get":
		return EdgeCanGet
	case "create":
		return EdgeCanCreate
	case "patch", "update":
		return EdgeCanPatch
	case "delete", "deletecollection":
		return EdgeCanDelete
	case "impersonate":
		return EdgeCanImpersonate
	case "escalate":
		return EdgeCanEscalate
	case "bind":
		return EdgeCanBind
	case "*":
		return EdgeCanCreate // broad; will be enriched by inference
	}
	return ""
}

func resourceNodeID(resource, namespace string) string {
	if namespace == "" {
		return "resource:" + resource
	}
	return "resource:" + namespace + ":" + resource
}

func resourceToNodeKind(resource string) NodeKind {
	// Normalize subresource prefix.
	base := strings.Split(resource, "/")[0]
	switch base {
	case "secrets":
		return KindSecret
	case "configmaps":
		return KindConfigMap
	case "pods":
		return KindPod
	case "nodes":
		return KindNode
	case "serviceaccounts":
		return KindServiceAccount
	case "namespaces":
		return KindNamespace
	case "roles":
		return KindRole
	case "clusterroles":
		return KindClusterRole
	case "rolebindings":
		return KindRoleBinding
	case "clusterrolebindings":
		return KindClusterRoleBinding
	case "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs":
		return KindWorkload
	case "mutatingwebhookconfigurations", "validatingwebhookconfigurations":
		return KindWebhook
	}
	return KindWorkload // default
}

func saNodeID(ns, name string) string {
	return fmt.Sprintf("sa:%s:%s", ns, name)
}

func subjectNodeID(s kube.Subject) string {
	switch s.Kind {
	case "ServiceAccount":
		return saNodeID(s.Namespace, s.Name)
	case "User":
		return "identity:" + s.Name
	case "Group":
		return "group:" + s.Name
	}
	return ""
}

// buildConcreteReachabilityEdges emits per-pod can_exec and can_portforward edges
// from the current identity (and, when in-cluster, from the current pod node) to
// each specific pod in namespaces where SSAR confirmed exec/portforward access.
//
// This transforms abstract "can exec into pods in namespace X" permission data into
// traversable graph edges: identity → [can_exec] → pod:ns:name. BFS can then route
// paths like: current-pod → [can_exec] → target-pod → [runs_as] → sa → [granted_by] → binding → role.
func buildConcreteReachabilityEdges(nm nodeMap, result *kube.EnumerationResult, identityID string) []Edge {
	// Determine the "from" node for lateral movement edges.
	// When in-cluster, edges also originate from the specific pod we're running in.
	sources := []string{identityID}
	if result.Identity.InCluster && result.Identity.PodName != "" {
		podID := "pod:" + result.Identity.Namespace + ":" + result.Identity.PodName
		if _, ok := nm[podID]; ok {
			sources = append(sources, podID)
		}
	}

	// Index namespaces where exec / portforward are confirmed allowed.
	execNS := make(map[string]bool)
	pfNS := make(map[string]bool)
	for _, c := range result.Permissions.SSARChecks {
		if !c.Allowed {
			continue
		}
		if c.Resource == "pods" && c.Subresource == "exec" && c.Verb == "create" {
			execNS[c.Namespace] = true
		}
		if c.Resource == "pods" && c.Subresource == "portforward" && c.Verb == "create" {
			pfNS[c.Namespace] = true
		}
	}
	if len(execNS) == 0 && len(pfNS) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var edges []Edge

	addEdge := func(from, to string, kind EdgeKind, reason string) {
		key := from + "→" + string(kind) + "→" + to
		if !seen[key] {
			seen[key] = true
			edges = append(edges, Edge{
				From:   from,
				To:     to,
				Kind:   kind,
				Reason: reason,
			})
		}
	}

	for _, pod := range result.ClusterObjects.Pods {
		podID := "pod:" + pod.Namespace + ":" + pod.Name
		if _, ok := nm[podID]; !ok {
			continue // pod node not in graph (should not happen, but be safe)
		}
		for _, src := range sources {
			if execNS[pod.Namespace] {
				addEdge(src, podID, EdgeCanExec,
					fmt.Sprintf("SSAR confirmed: pods/exec create in namespace %q", pod.Namespace))
			}
			if pfNS[pod.Namespace] {
				addEdge(src, podID, EdgeCanPortForward,
					fmt.Sprintf("SSAR confirmed: pods/portforward create in namespace %q", pod.Namespace))
			}
		}
	}

	return edges
}

// buildConcreteIdentityEdges creates edges from the current identity (and foothold pod)
// to concrete cluster resources based on SSAR-confirmed permissions.
//
// This solves the "abstract vs concrete disconnect" (B1): SSRR/SSAR produces edges
// to abstract resource type nodes (e.g. resource:default:deployments) which are dead ends
// for pathfinding. This function adds edges to the actual resources (e.g. workload:default:nginx)
// so that attack chains like:
//
//	identity → [can_patch] → workload:ns:app → [runs_as] → SA → ... → cluster-admin
//
// are traversable without shortcut hacks.
func buildConcreteIdentityEdges(nm nodeMap, result *kube.EnumerationResult, identityID string) []Edge {
	sources := []string{identityID}
	if result.Identity.InCluster && result.Identity.PodName != "" {
		podID := "pod:" + result.Identity.Namespace + ":" + result.Identity.PodName
		if nm[podID] != nil {
			sources = append(sources, podID)
		}
	}

	seen := make(map[string]bool)
	var edges []Edge

	addEdge := func(from, to string, kind EdgeKind, reason string) {
		key := from + "|" + string(kind) + "|" + to
		if seen[key] {
			return
		}
		seen[key] = true
		edges = append(edges, Edge{
			From:   from,
			To:     to,
			Kind:   kind,
			Reason: reason,
		})
	}

	// Index SSAR results by (verb, resource, namespace).
	type permKey struct{ verb, resource, ns string }
	allowed := make(map[permKey]bool)
	for _, c := range result.Permissions.SSARChecks {
		if c.Allowed {
			res := c.Resource
			if c.Subresource != "" {
				res = c.Resource + "/" + c.Subresource
			}
			allowed[permKey{c.Verb, res, c.Namespace}] = true
		}
	}

	for _, src := range sources {
		// Patch deployments/daemonsets/statefulsets → concrete workload edges.
		// Enables: identity → [can_patch] → workload → [runs_as] → SA → ...
		for _, wl := range result.ClusterObjects.Workloads {
			var wlResource string
			switch wl.Kind {
			case "Deployment":
				wlResource = "deployments"
			case "DaemonSet":
				wlResource = "daemonsets"
			case "StatefulSet":
				wlResource = "statefulsets"
			default:
				continue
			}
			if allowed[permKey{"patch", wlResource, wl.Namespace}] {
				wlID := "workload:" + wl.Namespace + ":" + wl.Name
				if nm[wlID] != nil {
					addEdge(src, wlID, EdgeCanPatch,
						fmt.Sprintf("SSAR: can patch %s %s/%s", wl.Kind, wl.Namespace, wl.Name))
				}
			}
		}

		// Get/List secrets → concrete secret edges.
		// Enables: identity → [can_get] → secret:ns:name
		for _, sm := range result.ClusterObjects.SecretsMeta {
			if allowed[permKey{"get", "secrets", sm.Namespace}] {
				secID := "secret:" + sm.Namespace + ":" + sm.Name
				if nm[secID] != nil {
					addEdge(src, secID, EdgeCanGet,
						fmt.Sprintf("SSAR: can get secrets in %q", sm.Namespace))
				}
			} else if allowed[permKey{"list", "secrets", sm.Namespace}] {
				secID := "secret:" + sm.Namespace + ":" + sm.Name
				if nm[secID] != nil {
					addEdge(src, secID, EdgeCanList,
						fmt.Sprintf("SSAR: can list secrets in %q", sm.Namespace))
				}
			}
		}

		// Impersonate serviceaccounts → concrete SA edges.
		// Enables: identity → [can_impersonate] → SA → [granted_by] → CRB → ...
		if allowed[permKey{"impersonate", "serviceaccounts", ""}] {
			for _, sa := range result.ClusterObjects.ServiceAccounts {
				saID := saNodeID(sa.Namespace, sa.Name)
				if nm[saID] != nil {
					addEdge(src, saID, EdgeCanImpersonate,
						fmt.Sprintf("SSAR: can impersonate SA %s/%s", sa.Namespace, sa.Name))
				}
			}
		}
	}

	return edges
}

// workloadBaseRisk returns a base risk score for a workload/pod node.
// All workloads are potential attacker footholds; dangerous security configs raise the score.
func workloadBaseRisk(privileged, hostPID, hostNetwork, hostIPC, dangerousCaps, hostPath bool) float64 {
	if privileged {
		return 9.0
	}
	if hostPID || hostNetwork || hostIPC {
		return 7.5
	}
	if dangerousCaps || hostPath {
		return 7.0
	}
	return 3.0 // base score: workloads are always potential footholds
}

// canEscapeToHost returns true if a pod's security configuration allows
// container escape to the underlying host node.
func canEscapeToHost(privilegedContainers []string, hostPID, hostNetwork, hostIPC bool,
	dangerousCaps []string, hostPathMounts []string) bool {
	return len(privilegedContainers) > 0 ||
		hostPID || hostNetwork || hostIPC ||
		len(dangerousCaps) > 0 ||
		len(hostPathMounts) > 0
}

// resolveRoleRefID returns the graph node ID for a role reference.
// ns is the namespace of the binding — used only when the RoleRef targets a
// namespace-scoped Role (ClusterRoleBindings always reference ClusterRoles).
func resolveRoleRefID(ref kube.RoleRef, ns string) string {
	if ref.Kind == "ClusterRole" {
		return "clusterrole:" + ref.Name
	}
	return "role:" + ns + ":" + ref.Name
}

// hasEdge returns true if edges already contains an edge from→to with the given kind.
func hasEdge(edges []Edge, from, to string, kind EdgeKind) bool {
	for i := range edges {
		if edges[i].From == from && edges[i].To == to && edges[i].Kind == kind {
			return true
		}
	}
	return false
}

// ── Transitive SA capability edges ──────────────────────────────────────────

// emitTransitiveSAEdges resolves the RBAC chain for each ServiceAccount and
// creates direct SA → target capability edges. This collapses:
//
//	SA → [granted_by] → binding → [bound_to] → role → [can_*] → target
//
// into a single hop:
//
//	SA → [can_*] → target
//
// The original RBAC chain edges are preserved for visualization, but the
// shortcut edges enable Dijkstra to find deeper multi-step attack chains
// (e.g. pod → SA → secret → authenticates_as → SA₂ → target) within the
// depth limit.
func emitTransitiveSAEdges(g *Graph, log *zap.Logger) {
	// Build quick lookup maps from edge list (index not yet built).
	outbound := make(map[string][]int) // nodeID → edge indices
	for i := range g.Edges {
		outbound[g.Edges[i].From] = append(outbound[g.Edges[i].From], i)
	}

	// Capability edge kinds that should be propagated from roles to SAs.
	isCapabilityEdge := map[EdgeKind]bool{
		EdgeCanList: true, EdgeCanGet: true, EdgeCanCreate: true,
		EdgeCanPatch: true, EdgeCanDelete: true, EdgeCanExec: true,
		EdgeCanPortForward: true, EdgeCanImpersonate: true,
		EdgeCanEscalate: true, EdgeCanBind: true, EdgeInferred: true,
	}

	// Dedup: avoid emitting the same SA→kind→target edge twice.
	seen := make(map[string]bool)

	var newEdges []Edge
	count := 0

	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindServiceAccount {
			continue
		}
		saID := n.ID

		// Step 1: SA → [granted_by] → bindings
		for _, ei := range outbound[saID] {
			e := &g.Edges[ei]
			if e.Kind != EdgeGrantedBy {
				continue
			}
			bindingID := e.To

			// Step 2: binding → [bound_to] → role
			for _, bi := range outbound[bindingID] {
				be := &g.Edges[bi]
				if be.Kind != EdgeBoundTo {
					continue
				}
				roleID := be.To

				// Step 3: role → [capability] → target
				for _, ri := range outbound[roleID] {
					re := &g.Edges[ri]
					if !isCapabilityEdge[re.Kind] {
						continue
					}
					targetID := re.To
					key := saID + "|" + string(re.Kind) + "|" + targetID
					if seen[key] {
						continue
					}
					seen[key] = true

					newEdges = append(newEdges, Edge{
						From:   saID,
						To:     targetID,
						Kind:   re.Kind,
						Reason: fmt.Sprintf("transitive: %s via %s → %s", saID, bindingID, roleID),
					})
					count++
				}
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("transitive SA capability edges emitted", zap.Int("count", count))
	}
}

// ── Active enrichment: derived SSRR edges ───────────────────────────────────

// emitDerivedSSRREdges creates concrete capability edges for ServiceAccounts
// whose permissions were discovered via impersonated SSRR during active
// enrichment. This is the bridge that turns "we can become SA X" into
// "SA X can read secrets / patch workloads / escalate to cluster-admin."
//
// For each derived identity with enriched SSRR data, it creates the same
// kind of edges that buildConcreteIdentityEdges creates for the current
// identity — but sourced from the derived SA node instead.
func emitDerivedSSRREdges(g *Graph, result *kube.EnumerationResult, log *zap.Logger) {
	if len(result.DerivedIdentities) == 0 {
		return
	}

	// Build node lookup from current graph.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for _, di := range result.DerivedIdentities {
		saID := saNodeID(di.Namespace, di.SAName)

		// Ensure the SA node exists in the graph.
		if nodeByID[saID] == nil {
			n := Node{
				ID:        saID,
				Kind:      KindServiceAccount,
				Name:      di.SAName,
				Namespace: di.Namespace,
				Metadata: map[string]string{
					"enriched":        "true",
					"derived_via":     di.How,
				},
			}
			g.Nodes = append(g.Nodes, n)
			nodeByID[saID] = &g.Nodes[len(g.Nodes)-1]
		} else {
			// Mark existing node as enriched.
			n := nodeByID[saID]
			if n.Metadata == nil {
				n.Metadata = map[string]string{}
			}
			n.Metadata["enriched"] = "true"
		}

		addEdge := func(to string, kind EdgeKind, reason string) {
			if nodeByID[to] == nil {
				return
			}
			key := saID + "|" + string(kind) + "|" + to
			if seen[key] {
				return
			}
			seen[key] = true
			newEdges = append(newEdges, Edge{
				From:   saID,
				To:     to,
				Kind:   kind,
				Reason: reason,
			})
			count++
		}

		for ns, rules := range di.SSRRRules {
			for _, rule := range rules {
				// Patch workloads → concrete workload edges.
				for _, wlRes := range []string{"deployments", "daemonsets", "statefulsets"} {
					if containsAny(rule.Verbs, "patch", "update", "*") && containsAny(rule.Resources, wlRes, "*") {
						for _, wl := range result.ClusterObjects.Workloads {
							if wl.Namespace == ns {
								addEdge("workload:"+wl.Namespace+":"+wl.Name, EdgeCanPatch,
									fmt.Sprintf("enriched SSRR: %s can patch %s in %s", di.SAName, wlRes, ns))
							}
						}
					}
				}

				// Get/List secrets → concrete secret edges.
				if containsAny(rule.Verbs, "get", "*") && containsAny(rule.Resources, "secrets", "*") {
					for _, sm := range result.ClusterObjects.SecretsMeta {
						if sm.Namespace == ns {
							addEdge("secret:"+sm.Namespace+":"+sm.Name, EdgeCanGet,
								fmt.Sprintf("enriched SSRR: %s can get secrets in %s", di.SAName, ns))
						}
					}
				} else if containsAny(rule.Verbs, "list", "*") && containsAny(rule.Resources, "secrets", "*") {
					for _, sm := range result.ClusterObjects.SecretsMeta {
						if sm.Namespace == ns {
							addEdge("secret:"+sm.Namespace+":"+sm.Name, EdgeCanList,
								fmt.Sprintf("enriched SSRR: %s can list secrets in %s", di.SAName, ns))
						}
					}
				}

				// Exec into pods.
				if containsAny(rule.Verbs, "create", "*") && containsAny(rule.Resources, "pods/exec", "*") {
					for _, pod := range result.ClusterObjects.Pods {
						if pod.Namespace == ns {
							addEdge("pod:"+pod.Namespace+":"+pod.Name, EdgeCanExec,
								fmt.Sprintf("enriched SSRR: %s can exec in %s", di.SAName, ns))
						}
					}
				}

				// Create pods → SA takeover + node scheduling.
				if containsAny(rule.Verbs, "create", "*") && containsAny(rule.Resources, "pods", "*") &&
					!containsAny(rule.Resources, "pods/exec") {
					for _, sa := range result.ClusterObjects.ServiceAccounts {
						if sa.Namespace == ns {
							addEdge(saNodeID(sa.Namespace, sa.Name), EdgeCanCreate,
								fmt.Sprintf("enriched SSRR: %s can create pods as SA in %s", di.SAName, ns))
						}
					}
				}

				// Impersonate SAs.
				if containsAny(rule.Verbs, "impersonate", "*") &&
					containsAny(rule.Resources, "serviceaccounts", "users", "*") {
					for _, sa := range result.ClusterObjects.ServiceAccounts {
						if sa.Namespace == ns || ns == "" {
							addEdge(saNodeID(sa.Namespace, sa.Name), EdgeCanImpersonate,
								fmt.Sprintf("enriched SSRR: %s can impersonate SAs", di.SAName))
						}
					}
				}

				// Create/patch CRBs → cluster-admin escalation.
				if containsAny(rule.Verbs, "create", "patch", "*") &&
					containsAny(rule.Resources, "clusterrolebindings", "*") {
					addEdge("clusterrole:cluster-admin", EdgeCanCreate,
						fmt.Sprintf("enriched SSRR: %s can create/patch CRBs", di.SAName))
				}

				// Escalate/bind clusterroles → cluster-admin.
				if containsAny(rule.Verbs, "escalate", "bind", "*") &&
					containsAny(rule.Resources, "clusterroles", "*") {
					addEdge("clusterrole:cluster-admin", EdgeCanEscalate,
						fmt.Sprintf("enriched SSRR: %s can escalate clusterroles", di.SAName))
				}

				// Get/List nodes.
				if containsAny(rule.Verbs, "get", "list", "*") && containsAny(rule.Resources, "nodes", "*") {
					for _, n := range result.ClusterObjects.Nodes {
						addEdge("node:"+n.Name, EdgeCanList,
							fmt.Sprintf("enriched SSRR: %s can access nodes", di.SAName))
					}
				}
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("derived SSRR capability edges emitted",
			zap.Int("edges", count),
			zap.Int("derived_identities", len(result.DerivedIdentities)))
	}
}

// ── Derived foothold edges ──────────────────────────────────────────────────

// emitDerivedFootholdEdges models workload takeover as a path enrichment step.
// When the current identity (or foothold pod) can patch/create workloads or
// exec into pods, the target workload's SA becomes a "derived identity" whose
// capabilities are reachable. This function adds edges that connect takeover
// targets to their SA's downstream capabilities, enabling chains like:
//
//	pod(foothold) → SA → identity → [can_patch] → workload → [runs_as] → SA₂ → [can_get] → secret
//
// Without this pass, the chain stops at SA₂ when SA₂ has no direct capability
// edges (because RBAC objects may not be enumerated or the transitive pass
// didn't find bindings for SA₂).
//
// The derived enrichment also handles:
//   - Exec-reachable pods: exec into pod → that pod's SA capabilities
//   - Token-steal chains: secret(SA-token) → authenticates_as → SA → SA capabilities
func emitDerivedFootholdEdges(g *Graph, result *kube.EnumerationResult, log *zap.Logger) {
	// Build outbound index from current edge list.
	outbound := make(map[string][]int)
	for i := range g.Edges {
		outbound[g.Edges[i].From] = append(outbound[g.Edges[i].From], i)
	}

	// Node lookup.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	identityID := "identity:" + result.Identity.Username

	// Collect all SAs that the current identity can "become" through workload
	// takeover (patch/create) or exec. These are "derived SAs" — one pivot away.
	derivedSAs := make(map[string]string) // saID → reason

	// 1. Patching a workload → the workload's SA becomes a derived identity.
	for _, ei := range outbound[identityID] {
		e := &g.Edges[ei]
		if e.Kind != EdgeCanPatch && e.Kind != EdgeCanCreate {
			continue
		}
		wlNode := nodeByID[e.To]
		if wlNode == nil || (wlNode.Kind != KindWorkload && wlNode.Kind != KindPod) {
			continue
		}
		// Follow workload → [runs_as] → SA
		for _, wi := range outbound[e.To] {
			we := &g.Edges[wi]
			if we.Kind != EdgeRunsAs {
				continue
			}
			saNode := nodeByID[we.To]
			if saNode != nil && saNode.Kind == KindServiceAccount {
				derivedSAs[we.To] = fmt.Sprintf("workload takeover via %s %s", e.Kind, e.To)
			}
		}
	}

	// Also check from foothold pod if in-cluster.
	if result.Identity.InCluster && result.Identity.PodName != "" {
		footholdPodID := "pod:" + result.Identity.Namespace + ":" + result.Identity.PodName
		for _, ei := range outbound[footholdPodID] {
			e := &g.Edges[ei]
			if e.Kind != EdgeCanPatch && e.Kind != EdgeCanCreate {
				continue
			}
			wlNode := nodeByID[e.To]
			if wlNode == nil || (wlNode.Kind != KindWorkload && wlNode.Kind != KindPod) {
				continue
			}
			for _, wi := range outbound[e.To] {
				we := &g.Edges[wi]
				if we.Kind != EdgeRunsAs {
					continue
				}
				saNode := nodeByID[we.To]
				if saNode != nil && saNode.Kind == KindServiceAccount {
					if _, ok := derivedSAs[we.To]; !ok {
						derivedSAs[we.To] = fmt.Sprintf("workload takeover via %s %s (from foothold)", e.Kind, e.To)
					}
				}
			}
		}
	}

	// 2. Exec into a pod → that pod's SA becomes a derived identity.
	execSources := []string{identityID}
	if result.Identity.InCluster && result.Identity.PodName != "" {
		execSources = append(execSources, "pod:"+result.Identity.Namespace+":"+result.Identity.PodName)
	}
	for _, src := range execSources {
		for _, ei := range outbound[src] {
			e := &g.Edges[ei]
			if e.Kind != EdgeCanExec {
				continue
			}
			podNode := nodeByID[e.To]
			if podNode == nil || podNode.Kind != KindPod {
				continue
			}
			for _, pi := range outbound[e.To] {
				pe := &g.Edges[pi]
				if pe.Kind != EdgeRunsAs {
					continue
				}
				saNode := nodeByID[pe.To]
				if saNode != nil && saNode.Kind == KindServiceAccount {
					if _, ok := derivedSAs[pe.To]; !ok {
						derivedSAs[pe.To] = fmt.Sprintf("exec into pod %s", e.To)
					}
				}
			}
		}
	}

	// 3. Impersonation → target SA is a derived identity.
	for _, src := range execSources {
		for _, ei := range outbound[src] {
			e := &g.Edges[ei]
			if e.Kind != EdgeCanImpersonate {
				continue
			}
			saNode := nodeByID[e.To]
			if saNode != nil && saNode.Kind == KindServiceAccount {
				if _, ok := derivedSAs[e.To]; !ok {
					derivedSAs[e.To] = fmt.Sprintf("impersonation of %s", e.To)
				}
			}
		}
	}

	if len(derivedSAs) == 0 {
		return
	}

	// For each derived SA, check if it already has capability edges.
	// If not, try to synthesize them from SSRR data (when the derived SA
	// happens to be in a namespace where SSRR reported permissions).
	// Also, for SAs with known workloads, create identity-to-workload-SA
	// shortcut edges that help the pathfinder reach deeper targets.
	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for saID, reason := range derivedSAs {
		// Check if this derived SA has any outgoing capability edges already
		// (from transitive pass or RBAC enumeration).
		hasCapabilities := false
		for _, ei := range outbound[saID] {
			e := &g.Edges[ei]
			switch e.Kind {
			case EdgeCanList, EdgeCanGet, EdgeCanCreate, EdgeCanPatch, EdgeCanDelete,
				EdgeCanExec, EdgeCanPortForward, EdgeCanImpersonate,
				EdgeCanEscalate, EdgeCanBind, EdgeInferred, EdgeAssumesCloudRole:
				hasCapabilities = true
			}
			if hasCapabilities {
				break
			}
		}

		// Mark the SA as a derived foothold for path classification.
		if saNode := nodeByID[saID]; saNode != nil {
			if saNode.Metadata == nil {
				saNode.Metadata = map[string]string{}
			}
			saNode.Metadata["derived_foothold"] = "true"
			saNode.Metadata["derived_via"] = reason
		}

		// If the SA has no capability edges and we have workloads that run as this SA,
		// create workload→SA traversal shortcut from identity through the workload chain.
		// This ensures the pathfinder can discover: identity → workload → SA → (SA's targets).
		if !hasCapabilities {
			// Check if any workloads/pods use this SA and have interesting properties
			// (privileged, hostPID, etc.) that create container escape edges.
			for _, wi := range outbound[saID] {
				we := &g.Edges[wi]
				// SA might have runs_on/mounts/authenticates_as from workloads that
				// run as this SA (reverse direction). Check outbound for cloud roles.
				if we.Kind == EdgeAssumesCloudRole {
					hasCapabilities = true
					break
				}
			}
		}

		// Create identity → SA edge if not already present, to enable
		// the pathfinder to reach this SA as a pivot point.
		key := identityID + "|derived|" + saID
		if !seen[key] {
			seen[key] = true
			// Don't duplicate if identity already reaches this SA via existing edges.
			alreadyReachable := false
			for _, ei := range outbound[identityID] {
				if g.Edges[ei].To == saID {
					alreadyReachable = true
					break
				}
			}
			if !alreadyReachable {
				newEdges = append(newEdges, Edge{
					From:   identityID,
					To:     saID,
					Kind:   EdgeInferred,
					Reason: fmt.Sprintf("derived foothold: %s", reason),
				})
				count++
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("derived foothold edges emitted",
			zap.Int("derived_sas", len(derivedSAs)),
			zap.Int("new_edges", count))
	}
}

// ── Node-derived expansion ─────────────────────���────────────────────────────

// emitNodeDerivedEdges models what an attacker gains after escaping to a node:
// access to SA tokens of all pods running on that node.
//
// On a Kubernetes node, every pod's SA token is mounted at a well-known path
// (/var/run/secrets/kubernetes.io/serviceaccount/token). An attacker with host
// access can read any pod's token and authenticate as that pod's SA.
//
// This creates edges: node → [can_get] → SA for every pod scheduled on that node.
// It also models kubelet-adjacent access: the node identity can read secrets
// mounted by its pods (via the Node authorizer).
func emitNodeDerivedEdges(g *Graph, result *kube.EnumerationResult, log *zap.Logger) {
	// Build node → pods index from pod data.
	nodePods := make(map[string][]kube.PodInfo)
	for _, pod := range result.ClusterObjects.Pods {
		if pod.Node != "" {
			nodePods[pod.Node] = append(nodePods[pod.Node], pod)
		}
	}

	if len(nodePods) == 0 {
		return
	}

	// Node lookup.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for nodeName, pods := range nodePods {
		nodeID := "node:" + nodeName
		if nodeByID[nodeID] == nil {
			continue
		}

		// Check if this node is reachable (has inbound runs_on edges).
		reachable := false
		for i := range g.Edges {
			if g.Edges[i].To == nodeID && g.Edges[i].Kind == EdgeRunsOn {
				reachable = true
				break
			}
		}
		if !reachable {
			continue // Only emit for nodes the attacker can actually reach
		}

		for _, pod := range pods {
			if pod.ServiceAccount == "" {
				continue
			}
			saID := saNodeID(pod.Namespace, pod.ServiceAccount)
			key := nodeID + "|" + saID
			if seen[key] {
				continue
			}
			seen[key] = true

			newEdges = append(newEdges, Edge{
				From:   nodeID,
				To:     saID,
				Kind:   EdgeCanGet,
				Reason: fmt.Sprintf("host access: steal SA token from pod %s/%s on this node", pod.Namespace, pod.Name),
			})
			count++
		}

		// Model host-mounted credential paths: if any pod on this node mounts
		// sensitive hostPath directories, the node gives access to those credentials.
		for _, pod := range pods {
			for _, hp := range pod.HostPathMounts {
				if isCredentialPath(hp) {
					// Host credential path → potential cluster-admin access.
					adminID := "clusterrole:cluster-admin"
					key := nodeID + "|hostcred|" + adminID
					if !seen[key] {
						seen[key] = true
						newEdges = append(newEdges, Edge{
							From:     nodeID,
							To:       adminID,
							Kind:     EdgeInferred,
							Reason:   fmt.Sprintf("host credential: pod %s/%s mounts %s", pod.Namespace, pod.Name, hp),
							Inferred: true,
						})
						count++
					}
					break // one credential path is enough
				}
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("node-derived expansion edges emitted", zap.Int("count", count))
	}
}

// isCredentialPath returns true if a hostPath mount is a well-known credential location.
func isCredentialPath(path string) bool {
	credPaths := []string{
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/pki",
		"/root/.kube",
		"/home",
		"/var/lib/kubelet/kubeconfig",
	}
	for _, cp := range credPaths {
		if strings.HasPrefix(path, cp) {
			return true
		}
	}
	return false
}

// ── Mount-derived SA capabilities ───────────────────────────────────────────

// emitMountDerivedSAEdges handles the common case where a derived SA has no
// RBAC capability edges (RBAC not enumerated, impersonation unavailable) but
// we know the SA's workloads mount secrets. Taking over the workload gives
// filesystem access to those mounted secrets regardless of RBAC.
//
// For each SA without capability edges, find workloads/pods that run as it,
// collect their mounted secrets/configmaps, and emit SA → [can_get] → target
// edges. These model: "I took over this SA's workload, so I can read its mounts."
func emitMountDerivedSAEdges(g *Graph, log *zap.Logger) {
	// Build outbound index.
	outbound := make(map[string][]int)
	inbound := make(map[string][]int)
	for i := range g.Edges {
		outbound[g.Edges[i].From] = append(outbound[g.Edges[i].From], i)
		inbound[g.Edges[i].To] = append(inbound[g.Edges[i].To], i)
	}

	// Node lookup.
	nodeByID := make(map[string]*Node)
	for i := range g.Nodes {
		nodeByID[g.Nodes[i].ID] = &g.Nodes[i]
	}

	// Capability edge kinds.
	isCapability := map[EdgeKind]bool{
		EdgeCanList: true, EdgeCanGet: true, EdgeCanCreate: true,
		EdgeCanPatch: true, EdgeCanDelete: true, EdgeCanExec: true,
		EdgeCanPortForward: true, EdgeCanImpersonate: true,
		EdgeCanEscalate: true, EdgeCanBind: true,
	}

	seen := make(map[string]bool)
	var newEdges []Edge
	count := 0

	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindServiceAccount {
			continue
		}

		// Check if this SA already has capability edges.
		hasCaps := false
		for _, ei := range outbound[n.ID] {
			if isCapability[g.Edges[ei].Kind] {
				hasCaps = true
				break
			}
		}
		if hasCaps {
			continue // SA already has known capabilities; no need for heuristics
		}

		// Find workloads/pods that run_as this SA (reverse edges).
		for _, ei := range inbound[n.ID] {
			e := &g.Edges[ei]
			if e.Kind != EdgeRunsAs {
				continue
			}
			wlNode := nodeByID[e.From]
			if wlNode == nil || (wlNode.Kind != KindWorkload && wlNode.Kind != KindPod) {
				continue
			}

			// Collect this workload/pod's mounted secrets and configmaps.
			for _, mi := range outbound[e.From] {
				me := &g.Edges[mi]
				if me.Kind != EdgeMounts {
					continue
				}
				targetNode := nodeByID[me.To]
				if targetNode == nil {
					continue
				}
				if targetNode.Kind != KindSecret && targetNode.Kind != KindConfigMap {
					continue
				}

				key := n.ID + "|mount_derived|" + me.To
				if seen[key] {
					continue
				}
				seen[key] = true

				newEdges = append(newEdges, Edge{
					From:   n.ID,
					To:     me.To,
					Kind:   EdgeCanGet,
					Reason: fmt.Sprintf("mount-derived: %s's workload %s mounts this resource", n.Name, wlNode.Name),
				})
				count++
			}
		}
	}

	if count > 0 {
		g.Edges = append(g.Edges, newEdges...)
		log.Info("mount-derived SA capability edges emitted", zap.Int("count", count))
	}
}
