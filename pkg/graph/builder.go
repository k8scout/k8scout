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

	// ── Materialize nodeMap → []Node ─────────────────────────────────────────
	nodes := make([]Node, 0, len(nm))
	for _, n := range nm {
		nodes = append(nodes, *n)
	}

	log.Info("graph built",
		zap.Int("nodes", len(nodes)),
		zap.Int("edges", len(edges)))

	return &Graph{Nodes: nodes, Edges: edges}
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

	log.Info("reviewer graph built",
		zap.Int("nodes", len(nodes)),
		zap.Int("edges", len(edges)),
		zap.Int("identities", len(result.AllIdentityPerms)))

	return &Graph{Nodes: nodes, Edges: edges}
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
		roleID := resolveRoleRefID(crb.RoleRef)
		edges = append(edges, Edge{From: crbID, To: roleID, Kind: EdgeBoundTo, Reason: "ClusterRoleBinding → role"})
		for _, subj := range crb.Subjects {
			if subjID := subjectNodeID(subj); subjID != "" {
				edges = append(edges, Edge{
					From:   crbID,
					To:     subjID,
					Kind:   EdgeGrants,
					Reason: fmt.Sprintf("ClusterRoleBinding %q grants %s", crb.Name, roleID),
				})
			}
		}
	}
	for _, rb := range result.ClusterObjects.RoleBindings {
		rbID := "rb:" + rb.Namespace + ":" + rb.Name
		nm[rbID] = &Node{ID: rbID, Kind: KindRoleBinding, Name: rb.Name, Namespace: rb.Namespace}
		roleID := resolveRoleRefID(rb.RoleRef)
		edges = append(edges, Edge{From: rbID, To: roleID, Kind: EdgeBoundTo, Reason: "RoleBinding → role"})
		for _, subj := range rb.Subjects {
			if subjID := subjectNodeID(subj); subjID != "" {
				edges = append(edges, Edge{
					From:   rbID,
					To:     subjID,
					Kind:   EdgeGrants,
					Reason: fmt.Sprintf("RoleBinding %q in %q grants %s", rb.Name, rb.Namespace, roleID),
				})
			}
		}
	}

	// Pass 3: Workload → SA (runs_as) edges + Pass 4: volume mount edges.
	for _, wl := range result.ClusterObjects.Workloads {
		wlID := "workload:" + wl.Namespace + ":" + wl.Name
		nm[wlID] = &Node{
			ID:        wlID,
			Kind:      KindWorkload,
			Name:      wl.Name,
			Namespace: wl.Namespace,
			Metadata:  map[string]string{"workload_kind": wl.Kind},
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
		nm[podID] = &Node{ID: podID, Kind: KindPod, Name: pod.Name, Namespace: pod.Namespace}
		if pod.ServiceAccount != "" {
			saID := saNodeID(pod.Namespace, pod.ServiceAccount)
			edges = append(edges, Edge{From: podID, To: saID, Kind: EdgeRunsAs, Reason: "Pod runs as ServiceAccount"})
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

func resolveRoleRefID(ref kube.RoleRef) string {
	if ref.Kind == "ClusterRole" {
		return "clusterrole:" + ref.Name
	}
	return "role::" + ref.Name // namespace unknown at this point
}
