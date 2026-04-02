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
	// These passes run after buildObjectGraph so all pod nodes exist in nm.
	//
	// 5a. Mark the current pod as the execution foothold when running in-cluster.
	//     This drives "YOU ARE HERE" visualization and prioritizes this pod as the
	//     first BFS start node in attack path generation.
	if result.Identity.InCluster && result.Identity.PodName != "" {
		podID := "pod:" + result.Identity.Namespace + ":" + result.Identity.PodName
		if n, ok := nm[podID]; ok {
			if n.Metadata == nil {
				n.Metadata = map[string]string{}
			}
			n.Metadata["is_foothold"] = "true"
			if result.Identity.OwnerWorkload != "" {
				n.Metadata["owner_workload"] = result.Identity.OwnerWorkload
				n.Metadata["owner_workload_kind"] = result.Identity.OwnerWorkloadKind
			}
			// Elevate the risk score so the foothold node is visually prominent.
			if n.RiskScore < 5.0 {
				n.RiskScore = 5.0
			}
			log.Info("foothold node anchored", zap.String("pod", podID))
		}
		// Also mark the node (Linux host) we're running on, if known.
		if result.Identity.NodeName != "" {
			nodeID := "node:" + result.Identity.NodeName
			if n, ok := nm[nodeID]; ok {
				if n.Metadata == nil {
					n.Metadata = map[string]string{}
				}
				n.Metadata["is_foothold_node"] = "true"
			}
		}
	}

	// 5b. Emit concrete per-pod exec and portforward edges from SSAR checks.
	edges = append(edges, buildConcreteReachabilityEdges(nm, result, identityID)...)

	// 5c. Emit concrete identity → resource edges for all SSAR-confirmed permissions.
	//     This bridges the abstract/concrete gap (B1): the identity gets edges to
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
			if vol.SourceKind == "Secret" && vol.SourceName != "" {
				secID := "secret:" + pod.Namespace + ":" + vol.SourceName
				if _, ok := nm[secID]; !ok {
					nm[secID] = &Node{ID: secID, Kind: KindSecret, Name: vol.SourceName, Namespace: pod.Namespace}
				}
				edges = append(edges, Edge{From: podID, To: secID, Kind: EdgeMounts, Reason: "pod volume"})
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

			// clusterrolebinding create/patch → can self-escalate to cluster-admin
			if allows(rule, "create", "clusterrolebindings") || allows(rule, "patch", "clusterrolebindings") {
				addE(roleID, "clusterrole:cluster-admin", EdgeCanCreate,
					roleID+" can create/patch CRBs — cluster-admin escalation path")
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
				From:     from,
				To:       to,
				Kind:     kind,
				Reason:   reason,
				Inferred: true,
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
					fmt.Sprintf("inferred: pods/exec create allowed in namespace %q", pod.Namespace))
			}
			if pfNS[pod.Namespace] {
				addEdge(src, podID, EdgeCanPortForward,
					fmt.Sprintf("inferred: pods/portforward create allowed in namespace %q", pod.Namespace))
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
			From:     from,
			To:       to,
			Kind:     kind,
			Reason:   reason,
			Inferred: true,
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
