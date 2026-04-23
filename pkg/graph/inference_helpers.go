package graph

import (
	"fmt"
	"strings"

	"github.com/hac01/k8scout/pkg/kube"
	"go.uber.org/zap"
)

// ── Inferred edges (Pass 5) ────────────────────────────────────────────────────

// emitInferredEdges adds inferred edges to the graph based on observed permissions.
func emitInferredEdges(g *Graph, r *kube.EnumerationResult) {
	// Ensure clusterrole:cluster-admin exists as a traversal target.
	// The builder only adds nodes it can enumerate; if the identity lacks
	// list-clusterroles permission the node won't be present, but inferred
	// edges still target it and FindPaths requires the node to exist.
	const clusterAdminID = "clusterrole:cluster-admin"
	if g.nodeByID(clusterAdminID) == nil {
		g.Nodes = append(g.Nodes, Node{
			ID:   clusterAdminID,
			Kind: KindClusterRole,
			Name: "cluster-admin",
		})
	}

	identityID := "identity:" + r.Identity.Username

	// NOTE: Pod→SA and SA→identity bridges are now created by Build() in builder.go
	// using EdgeRunsAs (weight 0.1) — the realistic chain. The old EdgeInferred
	// shortcuts (weight 2.0) that bypassed intermediate nodes have been removed.
	//
	// Concrete identity → resource edges (patch workloads, get secrets,
	// impersonate SAs) are created by buildConcreteIdentityEdges in builder.go.
	//
	// Only true inferred escalations remain below: create bindings → cluster-admin,
	// escalate/bind → cluster-admin, create pods → node scheduling.
	for _, c := range r.Permissions.SSARChecks {
		if !c.Allowed {
			continue
		}
		switch {
		case c.Resource == "pods" && c.Verb == "create":
			// create pods → inferred node access (scheduling)
			for _, node := range r.ClusterObjects.Nodes {
				nodeID := "node:" + node.Name
				g.Edges = append(g.Edges, Edge{
					From:     identityID,
					To:       nodeID,
					Kind:     EdgeInferred,
					Reason:   "inferred: create pod → schedule on node (subject to PSA/taints)",
					Inferred: true,
				})
			}

		case (c.Resource == "rolebindings" || c.Resource == "clusterrolebindings") && c.Verb == "create":
			g.Edges = append(g.Edges, Edge{
				From:     identityID,
				To:       "clusterrole:cluster-admin",
				Kind:     EdgeInferred,
				Reason:   "inferred: create " + c.Resource + " → escalation to cluster-admin",
				Inferred: true,
			})

		case c.Resource == "clusterroles" && (c.Verb == "escalate" || c.Verb == "bind"):
			g.Edges = append(g.Edges, Edge{
				From:     identityID,
				To:       "clusterrole:cluster-admin",
				Kind:     EdgeInferred,
				Reason:   fmt.Sprintf("inferred: %s clusterroles → bind self to cluster-admin", c.Verb),
				Inferred: true,
			})
		}
	}
}

// ── SA usage index ────────────────────────────────────────────────────────────

// buildSAUsageIndex scans the graph for runs_as edges and returns a map from
// SA node ID to the list of workload/pod node IDs that run as that SA.
// Used to enrich reviewer findings with workload context and to distinguish
// "privilege in use" from "privilege with no execution foothold".
func buildSAUsageIndex(g *Graph) map[string][]string {
	idx := make(map[string][]string)
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Kind == EdgeRunsAs {
			idx[e.To] = append(idx[e.To], e.From)
		}
	}
	return idx
}

// buildWorkloadUsageEvidence returns human-readable evidence lines describing
// which workloads use a given SA, and whether any are privileged.
// If no workloads use the SA, returns a single line noting the lack of foothold.
func buildWorkloadUsageEvidence(g *Graph, workloadIDs []string) []string {
	if len(workloadIDs) == 0 {
		return []string{
			"No running pods or workloads use this ServiceAccount — " +
				"privilege exists but there is no direct execution foothold.",
		}
	}
	lines := make([]string, 0, len(workloadIDs)+1)
	lines = append(lines, fmt.Sprintf("Used by %d running workload/pod(s):", len(workloadIDs)))
	for _, wid := range workloadIDs {
		n := g.nodeByID(wid)
		if n == nil {
			continue
		}
		extra := ""
		if m := n.Metadata; m != nil {
			if m["privileged_containers"] != "" {
				extra += " [PRIVILEGED]"
			}
			if m["host_pid"] == "true" || m["host_network"] == "true" || m["host_ipc"] == "true" {
				extra += " [HOST-PID/NET/IPC]"
			}
		}
		lines = append(lines, fmt.Sprintf("  • %s (%s/%s)%s", wid, n.Namespace, n.Name, extra))
	}
	return lines
}

// isPrivilegedWorkload returns true if any workload in workloadIDs has privileged
// or host-namespace security properties.
func isPrivilegedWorkload(g *Graph, workloadIDs []string) bool {
	for _, wid := range workloadIDs {
		n := g.nodeByID(wid)
		if n == nil {
			continue
		}
		m := n.Metadata
		if m == nil {
			continue
		}
		if m["privileged_containers"] != "" || m["host_pid"] == "true" ||
			m["host_network"] == "true" || m["host_ipc"] == "true" {
			return true
		}
	}
	return false
}

// ipHasPermission checks whether a computed IdentityPermissions grants verb on resource.
// Wildcard verbs ("*") and wildcard resources ("*") match anything.
func ipHasPermission(ip kube.IdentityPermissions, verb, resource string) bool {
	for _, rule := range ip.Rules {
		if containsAny(rule.Verbs, verb, "*") && containsAny(rule.Resources, resource, "*") {
			return true
		}
	}
	return false
}

// reviewerFindingNodeID returns the graph node ID for a computed identity's SA node.
func reviewerFindingNodeID(ip kube.IdentityPermissions) string {
	if ip.SubjectKind == "ServiceAccount" {
		return fmt.Sprintf("sa:%s:%s", ip.Namespace, ip.Name)
	}
	return "identity:" + ip.Name
}

// currentPodNodeID returns the graph node ID for the specific pod k8scout is
// currently running inside, or "" when not running in-cluster or pod name is unknown.
// This is the most concrete possible foothold — the exact execution context.
func currentPodNodeID(r *kube.EnumerationResult) string {
	if r.Identity.InCluster && r.Identity.PodName != "" && r.Identity.Namespace != "" {
		return "pod:" + r.Identity.Namespace + ":" + r.Identity.PodName
	}
	return ""
}

// goalKindMITRE maps a GoalKind to its relevant MITRE ATT&CK for Containers IDs.
func goalKindMITRE(kind GoalKind) []string {
	switch kind {
	case ClusterAdmin:
		return []string{"T1078.001"} // Valid Accounts: Local Accounts
	case NodeExec:
		return []string{"T1611"} // Escape to Host
	case SecretAccess:
		return []string{"T1552.007"} // Unsecured Credentials: Container API
	case IdentityTakeover:
		return []string{"T1078.004"} // Valid Accounts: Cloud Accounts
	case WorkloadTakeover:
		return []string{"T1610"} // Deploy Container
	case CloudEscalation:
		return []string{"T1078.004"} // Valid Accounts: Cloud Accounts
	case EnumerationVantage:
		return []string{"T1613"} // Container and Resource Discovery
	case CredentialAccess:
		return []string{"T1552.007"} // Unsecured Credentials: Container API
	case StrongerFoothold:
		return []string{"T1610"} // Deploy Container
	default:
		return nil
	}
}

// severityFromScore converts a numeric score to a Severity label.
func severityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.5:
		return SeverityHigh
	case score >= 5.0:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// formatPathDescription builds a human-readable chain representation of a path:
//
//	sa:default:app → [can_create] → resource:default:clusterrolebindings → [inferred] → clusterrole:cluster-admin
func formatPathDescription(path AttackPath) string {
	if len(path) == 0 {
		return ""
	}
	var b strings.Builder
	for i, step := range path {
		if i > 0 && step.Edge != nil {
			b.WriteString(fmt.Sprintf(" → [%s] → ", step.Edge.Kind))
		}
		// Prefer name + kind label for readability; fall back to raw ID.
		if step.Node.Name != "" && step.Node.Name != step.Node.ID {
			b.WriteString(fmt.Sprintf("%s (%s)", step.Node.ID, step.Node.Kind))
		} else {
			b.WriteString(step.Node.ID)
		}
	}
	return b.String()
}

// buildPathEvidence returns one evidence string per hop (edge traversal).
func buildPathEvidence(path AttackPath) []string {
	if len(path) < 2 {
		return nil
	}
	evidence := make([]string, 0, len(path)-1)
	for i := 1; i < len(path); i++ {
		step := path[i]
		prev := path[i-1]
		edgeLabel := ""
		if step.Edge != nil {
			edgeLabel = string(step.Edge.Kind)
			if step.Edge.Reason != "" {
				edgeLabel += ": " + step.Edge.Reason
			}
		}
		evidence = append(evidence, fmt.Sprintf("%s --(%s)--> %s", prev.Node.ID, edgeLabel, step.Node.ID))
	}
	return evidence
}

// pathAffectedNodes extracts all node IDs from a path in traversal order.
func pathAffectedNodes(path AttackPath) []string {
	ids := make([]string, len(path))
	for i, step := range path {
		ids[i] = step.Node.ID
	}
	return ids
}

// classifyPathStages analyzes an attack path and returns the progressive stages
// of the attack. Each stage represents a distinct pivot or escalation point:
//
//	Stage 0: Initial foothold (pod, workload, or identity)
//	Stage 1+: Each new SA, identity, or capability gained along the path
//
// Stages are identified by transitions between node roles:
//   - Pod/Workload → SA transition = new identity gained
//   - SA → capability edge = new capability gained
//   - Secret + authenticates_as = credential theft
//   - Cloud identity = cloud escalation
func classifyPathStages(path AttackPath) []AttackStage {
	if len(path) == 0 {
		return nil
	}

	var stages []AttackStage
	stageNum := 0

	// Stage 0: the starting node.
	startNode := path[0].Node
	stages = append(stages, AttackStage{
		Stage:       0,
		Label:       stageLabel(startNode.Kind, true),
		NodeID:      startNode.ID,
		Description: fmt.Sprintf("Start: %s %s", startNode.Kind, startNode.Name),
	})

	prevSA := "" // track the last SA we "became"
	if startNode.Kind == KindServiceAccount {
		prevSA = startNode.ID
	}

	for i := 1; i < len(path); i++ {
		step := path[i]
		node := step.Node
		edge := step.Edge

		if edge == nil {
			continue
		}

		switch {
		// Gaining a new SA identity (via runs_as, authenticates_as, or impersonate).
		case node.Kind == KindServiceAccount && node.ID != prevSA &&
			(edge.Kind == EdgeRunsAs || edge.Kind == EdgeAuthenticatesAs || edge.Kind == EdgeCanImpersonate):
			stageNum++
			label := "Identity Pivot"
			desc := fmt.Sprintf("Gain SA identity: %s", node.Name)
			if edge.Kind == EdgeAuthenticatesAs {
				label = "Credential Theft"
				desc = fmt.Sprintf("Steal SA token → become %s", node.Name)
			} else if edge.Kind == EdgeCanImpersonate {
				label = "Impersonation"
				desc = fmt.Sprintf("Impersonate SA %s", node.Name)
			}
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: label,
				NodeID: node.ID, Description: desc,
			})
			prevSA = node.ID

		// Workload takeover via patch/create.
		case (node.Kind == KindWorkload || node.Kind == KindPod) &&
			(edge.Kind == EdgeCanPatch || edge.Kind == EdgeCanCreate || edge.Kind == EdgeCanExec):
			stageNum++
			label := "Workload Takeover"
			desc := fmt.Sprintf("%s %s/%s", edge.Kind, node.Namespace, node.Name)
			if edge.Kind == EdgeCanExec {
				label = "Lateral Movement"
				desc = fmt.Sprintf("Exec into %s/%s", node.Namespace, node.Name)
			}
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: label,
				NodeID: node.ID, Description: desc,
			})

		// Container escape to host.
		case node.Kind == KindNode && edge.Kind == EdgeRunsOn:
			stageNum++
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: "Container Escape",
				NodeID: node.ID, Description: fmt.Sprintf("Escape to node %s", node.Name),
			})

		// Node pivot: stealing SA tokens of co-located pods via host access.
		// Emitted when the previous step landed on a node and we traverse a
		// host-access can_get edge (node-derived expansion in builder Pass 9).
		case node.Kind == KindServiceAccount && edge.Kind == EdgeCanGet &&
			i > 0 && path[i-1].Node.Kind == KindNode:
			stageNum++
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: "Node Pivot",
				NodeID:      node.ID,
				Description: fmt.Sprintf("Steal SA token from co-located pod → %s/%s", node.Namespace, node.Name),
			})
			prevSA = node.ID

		// Visibility Gain / Namespace Discovery: reaching a resource-type node
		// via a list/get capability expands recon reach.
		case strings.HasPrefix(node.ID, "resource:") &&
			(edge.Kind == EdgeCanList || edge.Kind == EdgeCanGet):
			stageNum++
			label := "Visibility Gain"
			resName := node.ID[strings.LastIndex(node.ID, ":")+1:]
			if resName == "namespaces" {
				label = "Namespace Discovery"
			}
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: label,
				NodeID:      node.ID,
				Description: fmt.Sprintf("%s %s", edge.Kind, resName),
			})

		// Credential Pivot: reaching a secret via a can_get capability before
		// the terminal step (so mid-path credential access is distinguished
		// from the final "Data Access" step).
		case node.Kind == KindSecret && edge.Kind == EdgeCanGet && i != len(path)-1:
			stageNum++
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: "Credential Pivot",
				NodeID:      node.ID,
				Description: fmt.Sprintf("Read secret %s/%s → fresh credentials", node.Namespace, node.Name),
			})

		// Cloud role assumption.
		case node.Kind == KindCloudIdentity && edge.Kind == EdgeAssumesCloudRole:
			stageNum++
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: "Cloud Escalation",
				NodeID: node.ID, Description: fmt.Sprintf("Assume cloud role %s", node.Name),
			})

		// Reaching a high-value target (cluster-admin, secret, etc.) via capability edge.
		case i == len(path)-1:
			stageNum++
			label := "Target Reached"
			desc := fmt.Sprintf("Access %s %s", node.Kind, node.Name)
			if edge.Kind == EdgeCanGet || edge.Kind == EdgeCanList {
				label = "Data Access"
				desc = fmt.Sprintf("Read %s %s/%s", node.Kind, node.Namespace, node.Name)
			} else if node.Kind == KindClusterRole && node.Name == "cluster-admin" {
				label = "Cluster Admin"
				desc = "Full cluster control via cluster-admin"
			}
			stages = append(stages, AttackStage{
				Stage: stageNum, Label: label,
				NodeID: node.ID, Description: desc,
			})
		}
	}

	return stages
}

// stageLabel returns a human-readable label for the starting node kind.
func stageLabel(kind NodeKind, isStart bool) string {
	if !isStart {
		return string(kind)
	}
	switch kind {
	case KindPod:
		return "Initial Foothold (Pod)"
	case KindWorkload:
		return "Initial Foothold (Workload)"
	case KindServiceAccount:
		return "SA Entry Point"
	case KindIdentity:
		return "Identity Entry Point"
	default:
		return "Entry Point"
	}
}

// isDuplicatePath returns true if the path's terminal node is already covered
// by an existing single-step finding. This prevents multi-hop from re-flagging
// goals that are directly surfaced by existing rules (e.g. ruleClusterAdminBinding
// already flags crb:* nodes; rulePrivilegedContainers already flags workload nodes).
// Paths with 2+ hops are never considered duplicates since no single-step rule
// covers a chained attack path.
func isDuplicatePath(path AttackPath, existing []RiskFinding) bool {
	if len(path) != 2 {
		// Only suppress 1-hop paths; multi-hop findings are always novel.
		return false
	}
	targetID := path[len(path)-1].Node.ID
	for _, f := range existing {
		for _, n := range f.AffectedNodes {
			if n == targetID {
				return true
			}
		}
	}
	return false
}

// footholdNodesForIdentity returns all realistic attacker-controlled start nodes for
// the current identity, ordered from most-concrete (workload/pod) to most-abstract
// (identity node). This drives realistic attack chains of the form:
//
//	Pod → SA → Binding → Role → Goal
//
// Priority order:
//  1. The specific pod k8scout is running in (when in-cluster) — the most concrete foothold.
//  2. All other pods/workloads running as the current SA — broader foothold set.
//  3. The SA node itself — identity pivot point.
//  4. The abstract identity node — fallback for non-SA identities.
func footholdNodesForIdentity(g *Graph, r *kube.EnumerationResult) []string {
	seen := make(map[string]bool)
	var starts []string

	addStart := func(id string) {
		if !seen[id] && g.nodeByID(id) != nil {
			seen[id] = true
			starts = append(starts, id)
		}
	}

	// Priority 1: the specific pod we are running inside (in-cluster mode only).
	// This is the most actionable foothold — paths starting here reflect what the
	// current binary can actually do right now.
	if podID := currentPodNodeID(r); podID != "" {
		addStart(podID)
	}

	// Priority 2 & 3: all pods/workloads running as the current SA + the SA itself.
	username := r.Identity.Username
	if strings.HasPrefix(username, "system:serviceaccount:") {
		parts := strings.SplitN(strings.TrimPrefix(username, "system:serviceaccount:"), ":", 2)
		if len(parts) == 2 {
			saID := saNodeID(parts[0], parts[1])
			// Pods and workloads that run_as this SA.
			for i := range g.Edges {
				e := &g.Edges[i]
				if e.Kind == EdgeRunsAs && e.To == saID {
					addStart(e.From) // workload:<ns>:<name> or pod:<ns>:<name>
				}
			}
			// The SA node itself (identity pivot).
			addStart(saID)
		}
	}

	// Priority 3.5: pods reachable via exec from the current identity or foothold pod.
	// These represent workloads the attacker can move into — exec gives shell access,
	// which is equivalent to running AS that pod's SA. Paths starting from these
	// pods score as foothold-anchored (pod-start) because the exec step is implicit.
	// This surfaces realistic chains: exec into privileged pod → steal SA token → escalate.
	execSources := []string{"identity:" + username}
	if podID := currentPodNodeID(r); podID != "" {
		execSources = append(execSources, podID)
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Kind != EdgeCanExec {
			continue
		}
		for _, src := range execSources {
			if e.From == src {
				addStart(e.To) // pod reachable via exec — treat as secondary foothold
				break
			}
		}
	}

	// Priority 4: abstract identity node — fallback for human users and non-SA identities.
	addStart("identity:" + username)

	return starts
}

// inferLateralMovementFindings surfaces exec and portforward reachability from the
// current foothold to other pods in the cluster. It emits at most one finding per
// lateral movement vector (exec vs portforward), listing all reachable pods.
//
// This is only meaningful when concrete reachability edges were added by
// buildConcreteReachabilityEdges — i.e. when SSAR confirmed exec/portforward access.
// The finding is separate from multi-hop because it represents direct lateral movement
// capability (one hop) rather than an escalation chain.
func inferLateralMovementFindings(g *Graph, r *kube.EnumerationResult, log *zap.Logger) []RiskFinding {
	if len(r.ClusterObjects.Pods) == 0 {
		return nil
	}

	// Determine foothold source nodes.
	var sourceIDs []string
	if podID := currentPodNodeID(r); podID != "" {
		sourceIDs = append(sourceIDs, podID)
	}
	sourceIDs = append(sourceIDs, "identity:"+r.Identity.Username)

	// Build index of (from,kind) → reachable pod IDs from the graph edges.
	execTargets := make(map[string]bool)   // pod IDs reachable via can_exec
	pfTargets := make(map[string]bool)     // pod IDs reachable via can_portforward

	srcSet := make(map[string]bool, len(sourceIDs))
	for _, s := range sourceIDs {
		srcSet[s] = true
	}

	for i := range g.Edges {
		e := &g.Edges[i]
		if !srcSet[e.From] {
			continue
		}
		switch e.Kind {
		case EdgeCanExec:
			execTargets[e.To] = true
		case EdgeCanPortForward:
			pfTargets[e.To] = true
		}
	}

	if len(execTargets) == 0 && len(pfTargets) == 0 {
		return nil
	}

	var findings []RiskFinding

	makeEvidence := func(targetSet map[string]bool) []string {
		ev := make([]string, 0, len(targetSet))
		for podID := range targetSet {
			n := g.nodeByID(podID)
			if n != nil {
				privileged := ""
				if m := n.Metadata; m != nil {
					if m["privileged_containers"] != "" {
						privileged = " [PRIVILEGED]"
					} else if m["host_pid"] == "true" || m["host_network"] == "true" || m["host_ipc"] == "true" {
						privileged = " [HOST-NS]"
					}
				}
				ev = append(ev, fmt.Sprintf("%s (%s/%s)%s", podID, n.Namespace, n.Name, privileged))
			} else {
				ev = append(ev, podID)
			}
		}
		return ev
	}

	foothold := "current identity"
	if podID := currentPodNodeID(r); podID != "" {
		foothold = podID
	}

	if len(execTargets) > 0 {
		ev := makeEvidence(execTargets)
		findings = append(findings, RiskFinding{
			RuleID:   "LATERAL-EXEC-REACHABILITY",
			Severity: SeverityHigh,
			Score:    8.0,
			Title: fmt.Sprintf("Lateral movement: can exec into %d pod(s) from foothold",
				len(execTargets)),
			Description: fmt.Sprintf(
				"From %s, the current identity has pods/exec create permission in one or more namespaces. "+
					"This enables direct shell access to %d running pod(s) without additional escalation. "+
					"An attacker can use this to pivot across workloads, steal tokens, or read secrets.",
				foothold, len(execTargets)),
			Evidence: append([]string{fmt.Sprintf("Foothold: %s", foothold)}, ev...),
			AffectedNodes: func() []string {
				ids := make([]string, 0, len(execTargets))
				for id := range execTargets { ids = append(ids, id) }
				return ids
			}(),
			MITREIDs:   []string{"T1609"},
			Mitigation: "Restrict pods/exec create permission to specific resourceNames or dedicated debug accounts. " +
				"Use NetworkPolicies and PodSecurityAdmission to limit blast radius. " +
				"Audit all exec events via Kubernetes audit logging.",
		})
		log.Info("lateral exec finding", zap.Int("pods", len(execTargets)), zap.String("foothold", foothold))
	}

	if len(pfTargets) > 0 {
		ev := makeEvidence(pfTargets)
		findings = append(findings, RiskFinding{
			RuleID:   "LATERAL-PORTFORWARD-REACHABILITY",
			Severity: SeverityMedium,
			Score:    6.0,
			Title: fmt.Sprintf("Lateral movement: can portforward to %d pod(s) from foothold",
				len(pfTargets)),
			Description: fmt.Sprintf(
				"From %s, the current identity can portforward to %d pod(s). "+
					"Port-forward allows TCP tunneling to any port of the target pod — "+
					"useful for reaching internal services, databases, and management endpoints.",
				foothold, len(pfTargets)),
			Evidence: append([]string{fmt.Sprintf("Foothold: %s", foothold)}, ev...),
			AffectedNodes: func() []string {
				ids := make([]string, 0, len(pfTargets))
				for id := range pfTargets { ids = append(ids, id) }
				return ids
			}(),
			MITREIDs:   []string{"T1090"},
			Mitigation: "Restrict pods/portforward create permission. " +
				"Use NetworkPolicies to prevent unauthorized pod-to-pod TCP tunneling.",
		})
		log.Info("lateral portforward finding", zap.Int("pods", len(pfTargets)), zap.String("foothold", foothold))
	}

	return findings
}

// inferMultiHopFindings traverses the graph from all realistic foothold nodes toward
// high-value targets and emits one RiskFinding per discovered attack path.
// It must be called after emitInferredEdges so that inferred edges are visible.
//
// Start nodes are ordered concrete-to-abstract (workload/pod → SA → identity) so that
// realistic paths (e.g. Pod → SA → CRB → ClusterRole) are emitted first and the
// per-goal cap is reached before redundant abstract paths.
func inferMultiHopFindings(g *Graph, r *kube.EnumerationResult, existing []RiskFinding, log *zap.Logger) []RiskFinding {
	startIDs := footholdNodesForIdentity(g, r)
	if len(startIDs) == 0 {
		return nil
	}

	goals := HighValueTargets(g, r)
	if len(goals) == 0 {
		return nil
	}

	var findings []RiskFinding
	// Track emitted-path fingerprints globally across all start nodes to avoid
	// duplicating the same node sequence from different abstract start points.
	emittedPaths := make(map[string]bool)

	for _, goal := range goals {
		emitted := 0

		for _, startID := range startIDs {
			if goal.NodeID == startID {
				continue // start IS the goal
			}

			// Use weighted pathfinding: returns paths sorted by attacker effort
			// (lowest weight first = most realistic/dangerous).
			scored := g.FindWeightedPaths(startID, goal.NodeID, MaxAttackPathDepth, MaxPathsPerGoal-emitted)

			for _, sp := range scored {
				if emitted >= MaxPathsPerGoal {
					break
				}
				if isDuplicatePath(sp.Path, existing) {
					continue
				}
				fingerprint := pathFingerprint(sp.Path)
				if emittedPaths[fingerprint] {
					continue
				}
				emittedPaths[fingerprint] = true

				numHops := len(sp.Path) - 1
				shape := ClassifyPath(sp.Path)
				score := ScoreByShape(shape, goal.BaseScore, numHops)

				stages := classifyPathStages(sp.Path)

				findings = append(findings, RiskFinding{
					RuleID:   "MULTIHOP-ESCALATION",
					Severity: severityFromScore(score),
					Score:    score,
					Title:    BuildPathTitle(sp.Path, goal, shape),
					Description: fmt.Sprintf("%s\n\nTarget: %s — %s",
						formatPathDescription(sp.Path), goal.GoalKind, goal.Description),
					Evidence:      buildPathEvidence(sp.Path),
					AffectedNodes: pathAffectedNodes(sp.Path),
					MITREIDs:      goalKindMITRE(goal.GoalKind),
					AttackPath:    sp.Path,
					PathWeight:    sp.Weight,
					AttackStages:  stages,
					ChainShape:    ChainShapeFromPathShape(shape),
					Mitigation: fmt.Sprintf("Break the attack path by removing at least one edge. "+
						"Review permissions and workload configurations along: %s",
						formatPathDescription(sp.Path)),
				})
				emitted++

				log.Info("multi-hop finding",
					zap.String("start", startID),
					zap.String("goal_kind", string(goal.GoalKind)),
					zap.String("goal_node", goal.NodeID),
					zap.Int("hops", numHops),
					zap.Int("stages", len(stages)),
					zap.Float64("score", score),
					zap.Float64("weight", sp.Weight))
			}

			if emitted >= MaxPathsPerGoal {
				break
			}
		}
	}

	return findings
}

// pathFingerprint returns a stable string key for an attack path based on its
// ordered node IDs. Used to deduplicate paths discovered from different start nodes.
func pathFingerprint(path AttackPath) string {
	ids := make([]string, len(path))
	for i, step := range path {
		ids[i] = step.Node.ID
	}
	return strings.Join(ids, "→")
}

// ── Reviewer multi-hop: workload-centric paths ────────────────────────────────

// maxReviewerPathsPerWorkload caps the number of paths emitted per workload node.
const maxReviewerPathsPerWorkload = 5

// maxReviewerMultiHopTotal caps the total reviewer multi-hop findings across all workloads.
const maxReviewerMultiHopTotal = 300

// inferReviewerMultiHopFindings generates realistic attack chains starting from
// every pod/workload in the cluster, tracing through their ServiceAccount and RBAC
// bindings to reach high-value targets. This produces findings such as:
//
//	Pod X → SA Y → ClusterRoleBinding Z → cluster-admin
//
// Unlike inferMultiHopFindings (which starts from the current identity), this
// function covers the full cluster attack surface regardless of who is running the scan.
// It is intended for reviewer mode only.
func inferReviewerMultiHopFindings(g *Graph, r *kube.EnumerationResult, existing []RiskFinding, log *zap.Logger) []RiskFinding {
	goals := HighValueTargets(g, r)
	if len(goals) == 0 {
		return nil
	}

	var findings []RiskFinding
	emittedPaths := make(map[string]bool)
	total := 0

	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind != KindWorkload && n.Kind != KindPod {
			continue
		}
		if total >= maxReviewerMultiHopTotal {
			log.Info("reviewer multi-hop total cap reached", zap.Int("cap", maxReviewerMultiHopTotal))
			break
		}

		workloadPaths := 0

		for _, goal := range goals {
			if goal.NodeID == n.ID {
				continue // workload is the goal — not a useful attack path
			}
			if workloadPaths >= maxReviewerPathsPerWorkload {
				break
			}

			scored := g.FindWeightedPaths(n.ID, goal.NodeID, MaxAttackPathDepth, maxReviewerPathsPerWorkload-workloadPaths)
			for _, sp := range scored {
				if total >= maxReviewerMultiHopTotal || workloadPaths >= maxReviewerPathsPerWorkload {
					break
				}
				if len(sp.Path) < 3 {
					continue
				}
				if isDuplicatePath(sp.Path, existing) {
					continue
				}
				fp := pathFingerprint(sp.Path)
				if emittedPaths[fp] {
					continue
				}
				emittedPaths[fp] = true

				numHops := len(sp.Path) - 1
				shape := ClassifyPath(sp.Path)
				score := ScoreByShape(shape, goal.BaseScore, numHops)

				stages := classifyPathStages(sp.Path)

				findings = append(findings, RiskFinding{
					RuleID:   "MULTIHOP-ESCALATION",
					Severity: severityFromScore(score),
					Score:    score,
					Title:    BuildPathTitle(sp.Path, goal, shape),
					Description: fmt.Sprintf(
						"Foothold: %s (%s/%s)\n\n%s\n\nTarget: %s — %s",
						n.Kind, n.Namespace, n.Name,
						formatPathDescription(sp.Path),
						goal.GoalKind, goal.Description),
					Evidence:      buildPathEvidence(sp.Path),
					AffectedNodes: pathAffectedNodes(sp.Path),
					MITREIDs:      goalKindMITRE(goal.GoalKind),
					AttackPath:    sp.Path,
					PathWeight:    sp.Weight,
					AttackStages:  stages,
					ChainShape:    ChainShapeFromPathShape(shape),
					Mitigation: fmt.Sprintf(
						"Break the attack path by removing at least one edge. "+
							"Review permissions and workload configurations along: %s",
						formatPathDescription(sp.Path)),
				})
				workloadPaths++
				total++

				log.Info("reviewer multi-hop finding",
					zap.String("foothold", n.ID),
					zap.String("goal_kind", string(goal.GoalKind)),
					zap.String("goal_node", goal.NodeID),
					zap.Int("hops", numHops),
					zap.Int("stages", len(stages)),
					zap.Float64("score", score),
					zap.Float64("weight", sp.Weight))
			}
		}
	}

	return findings
}

// ── Utility ───────────────────────────────────────────────────────────────────

func containsAny(slice []string, vals ...string) bool {
	for _, s := range slice {
		for _, v := range vals {
			if s == v {
				return true
			}
		}
	}
	return false
}
