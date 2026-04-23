package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
)

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
		interceptsPods := "false"
		if wh.InterceptsPods {
			interceptsPods = "true"
		}
		nm[wid] = &Node{
			ID:   wid,
			Kind: KindWebhook,
			Name: wh.Name,
			Metadata: map[string]string{
				"webhook_kind":    wh.Kind,
				"failure_policy":  wh.FailurePolicy,
				"service_name":    wh.ServiceName,
				"service_ns":      wh.ServiceNS,
				"intercepts_pods": interceptsPods,
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

	// Mutating webhooks: backend linkage and offensive capability edges.
	for _, wh := range result.ClusterObjects.Webhooks {
		if wh.Kind != "Mutating" {
			continue
		}
		whID := "webhook:" + wh.Name
		if nm[whID] == nil {
			continue
		}

		// Backend linkage: workload → [serves_webhook] → webhook.
		// Match webhook's backend Service to workloads in the same namespace with the same name.
		if wh.ServiceName != "" && wh.ServiceNS != "" {
			for _, wl := range result.ClusterObjects.Workloads {
				if wl.Namespace != wh.ServiceNS {
					continue
				}
				if wl.Name == wh.ServiceName || strings.HasPrefix(wl.Name, wh.ServiceName+"-") {
					wlID := "workload:" + wl.Namespace + ":" + wl.Name
					if nm[wlID] != nil {
						edges = append(edges, Edge{
							From:   wlID,
							To:     whID,
							Kind:   EdgeServesWebhook,
							Reason: fmt.Sprintf("workload %s/%s backs webhook %q via Service %s/%s", wl.Namespace, wl.Name, wh.Name, wh.ServiceNS, wh.ServiceName),
						})
					}
				}
			}
			// Also check pods directly (some webhook backends are bare pods or matched by service selectors).
			for _, pod := range result.ClusterObjects.Pods {
				if pod.Namespace != wh.ServiceNS {
					continue
				}
				if pod.OwnerName == wh.ServiceName || strings.HasPrefix(pod.OwnerName, wh.ServiceName+"-") {
					podID := "pod:" + pod.Namespace + ":" + pod.Name
					if nm[podID] != nil {
						edges = append(edges, Edge{
							From:   podID,
							To:     whID,
							Kind:   EdgeServesWebhook,
							Reason: fmt.Sprintf("pod %s/%s backs webhook %q", pod.Namespace, pod.Name, wh.Name),
						})
					}
				}
			}
		}

		// Offensive capability: webhook → [can_mutate_workloads] → target workloads.
		// Only emitted for pod-intercepting mutating webhooks.
		if !wh.InterceptsPods {
			continue
		}
		for _, wl := range result.ClusterObjects.Workloads {
			if wh.HasNamespaceSelector && wh.ServiceNS != wl.Namespace {
				continue
			}
			wlID := "workload:" + wl.Namespace + ":" + wl.Name
			if nm[wlID] != nil {
				edges = append(edges, Edge{
					From:     whID,
					To:       wlID,
					Kind:     EdgeCanMutateWorkloads,
					Reason:   fmt.Sprintf("mutating webhook %q intercepts pod creation — can inject sidecars, replace SA, modify security context", wh.Name),
					Inferred: true,
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
//   - list/get secrets          → EdgeCanList/EdgeCanGet to each secret node
//   - create pods/exec          → EdgeCanExec  to each pod node
//   - list/get nodes            → EdgeCanList  to each node node
//   - patch deployments/etc.    → EdgeCanPatch to each workload node
//   - create/patch CRBs         → EdgeCanCreate to clusterrole:cluster-admin
//   - wildcard (*/*) verbs      → EdgeInferred  to clusterrole:cluster-admin
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
