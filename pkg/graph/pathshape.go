package graph

import "fmt"

// PathNodeRole classifies the role a node plays in a 4-stage attack chain:
//
//	Foothold → Bridge → Capability → Target
type PathNodeRole int

const (
	RoleFoothold   PathNodeRole = iota // pod, workload — realistic execution entry point
	RoleBridge                         // SA, binding, role, clusterrole, secret-as-token, cloud identity, webhook
	RoleCapability                     // edge that grants a dangerous action (exec, secret-read, bind, escalate, etc.)
	RoleTarget                         // the final high-value goal node
	RoleOther                          // any other node (namespace, config, etc.)
)

// PathShape summarises the structure of an attack path in terms of the 4-stage model.
type PathShape struct {
	StartRole        PathNodeRole
	HasBridge        bool
	HasCapability    bool
	FullChain        bool   // true when Foothold+Bridge+Capability+Target all present
	BridgeLabel      string // e.g. "sa:default:myapp"
	CapabilityLabel  string // e.g. "pods/exec", "secret list", "cluster-admin escalation"
}

// nodeRoleOf classifies a single graph node into a PathNodeRole.
func nodeRoleOf(n Node) PathNodeRole {
	switch n.Kind {
	case KindPod, KindWorkload:
		return RoleFoothold
	case KindServiceAccount, KindClusterRoleBinding, KindRoleBinding, KindClusterRole, KindRole, KindSecret, KindWebhook, KindCloudIdentity:
		return RoleBridge
	default:
		return RoleOther
	}
}

// capabilityLabelForEdge returns a human-readable capability label for an edge
// that grants a dangerous action, or "" if the edge is not capability-bearing.
func capabilityLabelForEdge(e Edge) string {
	switch e.Kind {
	case EdgeRunsOn:
		return "container escape"
	case EdgeCanExec:
		return "pods/exec"
	case EdgeCanPortForward:
		return "pods/portforward"
	case EdgeCanGet:
		return "secret get"
	case EdgeCanList:
		return "secret list"
	case EdgeCanCreate:
		return "resource create"
	case EdgeCanDelete:
		return "resource delete"
	case EdgeCanPatch:
		return "workload mutation"
	case EdgeCanImpersonate:
		return "impersonation"
	case EdgeCanBind:
		return "role bind"
	case EdgeCanEscalate:
		return "role escalate"
	case EdgeAuthenticatesAs:
		return "token theft"
	case EdgeAssumesCloudRole:
		return "cloud role assumption"
	case EdgeInferred:
		if e.Reason != "" {
			return "escalation"
		}
		return ""
	default:
		return ""
	}
}

// ClassifyPath analyses an attack path and returns a PathShape describing its
// structural role composition. The classification is:
//   - Start node role → StartRole
//   - Any intermediate bridge node → HasBridge / BridgeLabel
//   - Any capability-bearing edge → HasCapability / CapabilityLabel
//   - FullChain = StartRole is Foothold AND HasBridge AND HasCapability
func ClassifyPath(path AttackPath) PathShape {
	if len(path) == 0 {
		return PathShape{}
	}

	shape := PathShape{
		StartRole: nodeRoleOf(*path[0].Node),
	}

	// Scan the intermediate nodes (not first, not last) for bridge roles.
	for i := 1; i < len(path)-1; i++ {
		step := path[i]
		role := nodeRoleOf(*step.Node)
		if role == RoleBridge && !shape.HasBridge {
			shape.HasBridge = true
			shape.BridgeLabel = step.Node.ID
		}
		// Check the edge arriving at this node for a capability signal.
		if step.Edge != nil {
			if label := capabilityLabelForEdge(*step.Edge); label != "" && !shape.HasCapability {
				shape.HasCapability = true
				shape.CapabilityLabel = label
			}
		}
	}

	// Also check the final edge for a capability signal (e.g. secret-read on the target).
	if last := path[len(path)-1]; last.Edge != nil {
		if label := capabilityLabelForEdge(*last.Edge); label != "" && !shape.HasCapability {
			shape.HasCapability = true
			shape.CapabilityLabel = label
		}
	}

	// Retroactive capability: if the final node is the cluster-admin clusterrole,
	// treat that as an implicit cluster-admin authority capability even if no explicit
	// capability edge was found in the path.
	if !shape.HasCapability {
		finalNode := path[len(path)-1].Node
		if finalNode.ID == "clusterrole:cluster-admin" {
			shape.HasCapability = true
			shape.CapabilityLabel = "cluster-admin authority"
		}
	}

	// A first-node bridge is still a bridge (e.g. SA-start paths).
	if shape.StartRole == RoleBridge && !shape.HasBridge {
		shape.HasBridge = true
		shape.BridgeLabel = path[0].Node.ID
	}

	shape.FullChain = shape.StartRole == RoleFoothold && shape.HasBridge && shape.HasCapability

	return shape
}

// ScoreByShape computes the risk score for a path given its structural shape,
// the goal's base score, and the number of hops.
//
// Scoring tiers:
//   - Full chain (foothold+bridge+capability+target): highest — base+4.0, small hop penalty
//   - Foothold-only (no bridge/capability): base+3.0, moderate hop penalty
//   - SA/binding bridge start: slight penalty
//   - Abstract identity / other: larger penalty
func ScoreByShape(shape PathShape, baseScore float64, numHops int) float64 {
	var score float64
	switch {
	case shape.FullChain:
		score = baseScore + 4.0 - (0.15 * float64(numHops))
	case shape.StartRole == RoleFoothold:
		score = baseScore + 3.0 - (0.2 * float64(numHops))
	case shape.StartRole == RoleBridge:
		score = baseScore - 1.0 - (0.3 * float64(numHops))
	default:
		score = baseScore - 3.0 - (0.5 * float64(numHops))
	}
	if score > 10.0 {
		score = 10.0
	}
	if score < 1.0 {
		score = 1.0
	}
	return score
}

// ScoreByWeight computes the risk score combining goal value and path weight.
// Lower weight = easier attack = higher score.
//
//	score = GoalValue × (1 / (1 + Weight)) × FootholdMultiplier
//
// Produces scores where a 2-hop privileged-pod-to-cluster-admin (weight ~0.3)
// scores ~9.5, while a theoretical 6-hop RBAC chain (weight ~3.0) scores ~4.0.
func ScoreByWeight(shape PathShape, baseScore, weight float64) float64 {
	multiplier := 1.0
	switch {
	case shape.FullChain:
		multiplier = 1.4
	case shape.StartRole == RoleFoothold:
		multiplier = 1.3
	case shape.StartRole == RoleBridge:
		multiplier = 0.9
	default:
		multiplier = 0.7
	}
	score := baseScore * (1.0 / (1.0 + weight)) * multiplier
	if score > 10.0 {
		score = 10.0
	}
	if score < 1.0 {
		score = 1.0
	}
	return score
}

// BuildPathTitle generates a human-readable title for an attack path finding.
// Full-chain paths are labeled "FOOTHOLD CHAIN: start → bridge → capability → goal (N-hop)".
// Other paths fall back to shorter forms.
func BuildPathTitle(path AttackPath, goal GoalNode, shape PathShape) string {
	if len(path) == 0 {
		return fmt.Sprintf("Escalation path to %s", goal.GoalKind)
	}
	numHops := len(path) - 1
	startNode := *path[0].Node
	startName := startNode.Name
	if startName == "" {
		startName = startNode.ID
	}

	switch {
	case shape.FullChain:
		bridgePart := ""
		if shape.BridgeLabel != "" {
			bridgePart = fmt.Sprintf(" → %s", shape.BridgeLabel)
		}
		capPart := ""
		if shape.CapabilityLabel != "" {
			capPart = fmt.Sprintf(" → %s", shape.CapabilityLabel)
		}
		return fmt.Sprintf("FOOTHOLD CHAIN: %s%s%s → %s (%d-hop)",
			startName, bridgePart, capPart, goal.GoalKind, numHops)

	case shape.StartRole == RoleFoothold:
		prefix := startNode.Name
		if startNode.Kind == KindPod {
			prefix = "pod/" + startNode.Name
		}
		if prefix == "" {
			prefix = startNode.ID
		}
		return fmt.Sprintf("FOOTHOLD CHAIN: %s → %s (%d-hop)", prefix, goal.GoalKind, numHops)

	case shape.StartRole == RoleBridge && startNode.Kind == KindServiceAccount:
		return fmt.Sprintf("SA escalation: %s → %s (%d-hop)", startName, goal.GoalKind, numHops)

	default:
		return fmt.Sprintf("Escalation path to %s (%d-hop)", goal.GoalKind, numHops)
	}
}
