package graph

import (
	"fmt"

	"github.com/hac01/k8scout/pkg/kube"
)

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
