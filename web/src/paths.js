// paths.js
// Attack path computation (BFS), classification, scoring

/* ================================================================
   ATTACK PATH COMPUTATION (BFS)
   ================================================================ */
// edgeNodeId is in utils.js

function computeAttackPaths() {
  if (!graphData) { computedPaths = []; return; }
  const { nodes, edges } = graphData;

  // Build adjacency list (attack-relevant edges only)
  const adj = {};
  nodes.forEach(n => { adj[n.id] = []; });
  edges.forEach(e => {
    const sid = edgeNodeId(e.source || e.from);
    const tid = edgeNodeId(e.target || e.to);
    if (!sid || !tid) return;
    if (ATTACK_EDGE_KINDS.has(e.kind)) {
      if (!adj[sid]) adj[sid] = [];
      adj[sid].push({ kind: e.kind, to: tid });
    }
  });

  // Source nodes ordered by attack realism:
  // 1. Pods/Workloads — the most concrete foothold an attacker would land on
  // 2. SAs used by running pods — realistic identity pivot points
  // 3. SAs with no workloads — privilege-in-isolation, lower priority
  // 4. Identities — catch-all for non-SA human/system accounts
  const sourcesFoothold = nodes.filter(n => n.kind === 'Pod' || n.kind === 'Workload').map(n => n.id);
  const sourcesUsedSA   = nodes.filter(n =>
    (n.kind === 'ServiceAccount' || n.kind === 'Identity') && saWithWorkload.has(n.id)
  ).map(n => n.id);
  const sourcesOther    = nodes.filter(n =>
    (n.kind === 'ServiceAccount' || n.kind === 'Identity') && !saWithWorkload.has(n.id)
  ).map(n => n.id);
  let sources = [...sourcesFoothold, ...sourcesUsedSA, ...sourcesOther];
  if (!sources.length) {
    sources = nodes.filter(n => (adj[n.id] || []).length > 0).map(n => n.id);
  }

  // High-value target detection — expanded set
  function isTarget(n) {
    if (!n) return false;
    if (n.kind === 'ClusterRole') return true;
    if (n.kind === 'ClusterRoleBinding') return true;
    if (n.kind === 'Node') return true;
    if (n.kind === 'Secret') return true;  // ALL secrets are targets
    if (n.kind === 'RoleBinding' || n.kind === 'Role') return (n.risk_score||0) >= 5;
    if ((n.risk_score||0) >= 6) return true;
    // Resource nodes representing high-value API access
    const id = n.id || '';
    if (id.includes('secrets') || id.includes('clusterrole') || id.includes('pods/exec')) return true;
    return false;
  }

  const MAX_PATHS = 50, MAX_DEPTH = 12;
  const paths = [];

  // Per-source BFS with per-path visited tracking (finds multiple distinct paths)
  for (const srcId of sources) {
    if (paths.length >= MAX_PATHS) break;

    // Use DFS with backtracking to find diverse paths
    const localPaths = [];
    const MAX_LOCAL = 8;

    function dfs(nodeId, pathNodes, pathEdges, visited) {
      if (localPaths.length >= MAX_LOCAL || paths.length + localPaths.length >= MAX_PATHS) return;
      const node = nodeById[nodeId];
      const hitTarget = pathNodes.length > 1 && isTarget(node);
      if (hitTarget) {
        localPaths.push({ nodes: [...pathNodes], edges: [...pathEdges] });
        // Continue exploring past low-value targets to find higher-value ones behind them
        // (e.g., Secret → SA → ClusterRole). Stop only at terminal targets or depth limit.
        if ((node.risk_score||0) >= 9 || node.kind === 'Node' || node.kind === 'ClusterRoleBinding') return;
      }
      if (pathNodes.length >= MAX_DEPTH) return;
      for (const step of (adj[nodeId] || [])) {
        if (!visited.has(step.to)) {
          visited.add(step.to);
          dfs(step.to, [...pathNodes, step.to], [...pathEdges, step.kind], visited);
          visited.delete(step.to);
        }
      }
    }

    dfs(srcId, [srcId], [], new Set([srcId]));

    // De-duplicate against global paths (by nodes signature)
    const globalSigs = new Set(paths.map(p => p.nodes.join('→')));
    for (const p of localPaths) {
      const sig = p.nodes.join('→');
      if (!globalSigs.has(sig)) {
        globalSigs.add(sig);
        paths.push(p);
        if (paths.length >= MAX_PATHS) break;
      }
    }
  }

  // Sort: impact score desc, then prefer paths starting from pods/workloads, then path length asc
  const isConcreteFoothold = id => {
    const n = nodeById[id];
    return n && (n.kind === 'Pod' || n.kind === 'Workload');
  };
  paths.sort((a, b) => {
    const ia = pathImpactType(a), ib = pathImpactType(b);
    if (ia.score !== ib.score) return ib.score - ia.score;
    const ta = nodeById[a.nodes[a.nodes.length-1]];
    const tb = nodeById[b.nodes[b.nodes.length-1]];
    if ((ta?.risk_score||0) !== (tb?.risk_score||0)) return (tb?.risk_score||0) - (ta?.risk_score||0);
    // Prefer paths that start from a concrete foothold (pod/workload)
    const aFoothold = isConcreteFoothold(a.nodes[0]) ? 0 : 1;
    const bFoothold = isConcreteFoothold(b.nodes[0]) ? 0 : 1;
    if (aFoothold !== bFoothold) return aFoothold - bFoothold;
    return a.nodes.length - b.nodes.length;
  });

  computedPaths = paths;
}

// importFindingPaths merges backend-computed attack_path data from risk_findings
// into computedPaths. The backend's weighted paths are authoritative: when a
// frontend-computed path shares the same node signature, we overwrite the
// metadata with the backend's values (title, score, weight, stages, shape) so
// the UI always reflects backend truth. Backend-only paths that the frontend
// DFS didn't discover are appended as fresh entries.
function importFindingPaths() {
  if (!graphData) return;
  const sigIndex = new Map();
  computedPaths.forEach((p, i) => sigIndex.set(p.nodes.join('→'), i));

  (graphData.findings || []).forEach(f => {
    const ap = f.attack_path;
    if (!ap || ap.length < 2) return;

    // Convert []PathStep → {nodes, edges} internal format.
    const nodes = ap.map(s => s.node && s.node.id).filter(Boolean);
    const edges = ap.slice(1).map(s => (s.edge && s.edge.kind) || 'inferred');
    if (nodes.length < 2) return;

    const backendMeta = {
      _findingId:   f.id,
      _score:       f.score,
      _title:       f.title,
      _weight:      f.path_weight,
      _stages:      f.attack_stages || null,
      _chainShape:  f.chain_shape || null,
      _mitreIds:    f.mitre_ids || [],
      _ruleId:      f.rule_id || null,
      _backend:     true,
    };

    const sig = nodes.join('→');
    const existingIdx = sigIndex.get(sig);
    if (existingIdx != null) {
      // Overwrite metadata on the frontend-DFS path so backend wins.
      Object.assign(computedPaths[existingIdx], backendMeta);
      return;
    }
    sigIndex.set(sig, computedPaths.length);
    computedPaths.push({ nodes, edges, ...backendMeta });
  });

  // Re-sort so newly imported high-score paths surface at the top. Backend
  // paths use their own score; frontend-only paths fall back to pathImpactType.
  computedPaths.sort((a, b) => {
    const sa = (a._score != null) ? a._score : pathImpactType(a).score;
    const sb = (b._score != null) ? b._score : pathImpactType(b).score;
    if (sa !== sb) return sb - sa;
    const wa = (a._weight != null) ? a._weight : Number.POSITIVE_INFINITY;
    const wb = (b._weight != null) ? b._weight : Number.POSITIVE_INFINITY;
    if (wa !== wb) return wa - wb;
    return a.nodes.length - b.nodes.length;
  });
}

// synthesisePathFromFinding converts a finding's backend attack_path into the
// frontend path shape and pushes it into computedPaths. Returns the new index,
// or -1 if the finding has no usable path. Idempotent on signature.
function synthesisePathFromFinding(f) {
  if (!f) return -1;
  const ap = f.attack_path;
  if (!ap || ap.length < 2) return -1;
  const nodes = ap.map(s => s.node && s.node.id).filter(Boolean);
  const edges = ap.slice(1).map(s => (s.edge && s.edge.kind) || 'inferred');
  if (nodes.length < 2) return -1;
  const sig = nodes.join('→');
  const existing = computedPaths.findIndex(p => p.nodes.join('→') === sig);
  if (existing >= 0) return existing;
  computedPaths.push({
    nodes, edges,
    _findingId:  f.id,
    _score:      f.score,
    _title:      f.title,
    _weight:     f.path_weight,
    _stages:     f.attack_stages || null,
    _chainShape: f.chain_shape || null,
    _mitreIds:   f.mitre_ids || [],
    _ruleId:     f.rule_id || null,
    _backend:    true,
  });
  return computedPaths.length - 1;
}

/* ================================================================
   ATTACK PATH CLASSIFICATION & SCORING
   ================================================================ */
function classifyPathPhases(path) {
  const phases = {
    initialAccess:   { nodeId: path.nodes[0],                     label: 'Initial Access',        present: true },
    credTheft:       { nodeId: null, edgeKind: null, stepIdx: -1,  label: 'Credential Theft',      present: false },
    privEsc:         { nodeId: null, edgeKind: null, stepIdx: -1,  label: 'Privilege Escalation',  present: false },
    lateralMovement: { nodeId: null, edgeKind: null, stepIdx: -1,  label: 'Lateral Movement',      present: false },
    impact:          { nodeId: path.nodes[path.nodes.length - 1], label: 'Impact',                present: true },
  };

  // Edge→phase taxonomy aligned with backend classifyPathStages:
  //   runs_as / authenticates_as / can_impersonate = identity pivot (cred theft)
  //   mounts / assumes_cloud_role                  = cred / cloud theft
  //   grants / bound_to / granted_by / can_bind / can_escalate / inferred = priv esc
  //   can_exec / can_portforward / runs_on / can_create / can_patch      = lateral / takeover
  const PRIVESC_EDGES = new Set(['grants','bound_to','granted_by','can_bind','can_escalate','inferred']);
  const LATERAL_EDGES = new Set(['can_exec','can_portforward','runs_on','can_create','can_patch']);
  const CRED_EDGES    = new Set(['mounts','authenticates_as','assumes_cloud_role','runs_as','can_impersonate']);

  path.edges.forEach((ek, i) => {
    if (CRED_EDGES.has(ek) && !phases.credTheft.present) {
      phases.credTheft = { nodeId: path.nodes[i+1], edgeKind: ek, stepIdx: i, label: 'Credential Theft', present: true };
    }
    if (PRIVESC_EDGES.has(ek) && !phases.privEsc.present) {
      phases.privEsc = { nodeId: path.nodes[i+1], edgeKind: ek, stepIdx: i, label: 'Privilege Escalation', present: true };
    }
    if (LATERAL_EDGES.has(ek) && !phases.lateralMovement.present) {
      phases.lateralMovement = { nodeId: path.nodes[i+1], edgeKind: ek, stepIdx: i, label: 'Lateral Movement', present: true };
    }
  });

  return phases;
}

function pathImpactType(path) {
  const target = nodeById[path.nodes[path.nodes.length - 1]];
  if (!target) return { type: 'UNKNOWN', score: 0, label: 'Unknown' };
  if (target.kind === 'Node') return { type: 'NODE_BREAKOUT', score: 10, label: 'Node Breakout' };
  if (target.kind === 'ClusterRoleBinding') return { type: 'CLUSTER_ADMIN', score: 9.5, label: 'Cluster-Admin Binding' };
  if (target.kind === 'ClusterRole') {
    const n = (target.name||'').toLowerCase();
    if (n === 'cluster-admin' || n.includes('admin') || n.includes('manager'))
      return { type: 'CLUSTER_ADMIN', score: 9, label: 'Cluster-Admin Role' };
    return { type: 'PRIVESC', score: 8, label: 'ClusterRole PrivEsc' };
  }
  if (target.kind === 'Secret') {
    const meta = target.metadata || {};
    const crossNs = path.nodes.some(id => {
      const n = nodeById[id];
      return n && n.namespace && n.namespace !== target.namespace;
    });
    // SA tokens are always critical (usable for impersonation)
    if (meta.type === 'kubernetes.io/service-account-token')
      return { type: 'SECRET_EXFIL', score: 9.5, label: 'SA Token Theft' };
    // Secrets with captured values are high-value
    if (meta.has_captured_values === 'true')
      return { type: 'SECRET_EXFIL', score: 9, label: 'Critical Secret Exfil' };
    return { type: 'SECRET_EXFIL', score: crossNs ? 8 : 7, label: crossNs ? 'Cross-NS Secret Exfil' : 'Secret Exfil' };
  }
  if (target.kind === 'CloudIdentity') {
    return { type: 'CLOUD_ESCALATION', score: 9.5, label: 'Cloud IAM Takeover' };
  }
  if (target.kind === 'RoleBinding') return { type: 'PRIVESC', score: 7.5, label: 'RoleBinding PrivEsc' };
  // Resource node representing exec/create on pods
  const tid = target.id || '';
  if (tid.includes('pods/exec')) return { type: 'NODE_BREAKOUT', score: 8.5, label: 'Pod Exec → Escape' };
  if (tid.includes('clusterrolebinding')) return { type: 'CLUSTER_ADMIN', score: 9, label: 'Cluster-Admin' };
  if (tid.includes('secrets')) return { type: 'SECRET_EXFIL', score: 7, label: 'Secret Access' };
  if ((target.risk_score||0) >= 8) return { type: 'PRIVESC', score: 8, label: 'Critical Escalation' };
  if ((target.risk_score||0) >= 6) return { type: 'PRIVESC', score: 7, label: 'High-Risk Escalation' };
  if ((target.risk_score||0) >= 4) return { type: 'LATERAL_MOVE', score: 5, label: 'Lateral Movement' };
  return { type: 'CONFIG', score: 3, label: 'Config Disclosure' };
}

function getPathNarrative(path) {
  const src    = nodeById[path.nodes[0]];
  const target = nodeById[path.nodes[path.nodes.length - 1]];
  const impact = pathImpactType(path);
  const phases = classifyPathPhases(path);
  const pivotNode = nodeById[phases.privEsc.nodeId] || nodeById[phases.lateralMovement.nodeId];

  let parts = [src?.name || src?.id || '?'];
  if (pivotNode && pivotNode.id !== src?.id) parts.push(pivotNode.name || pivotNode.id || '?');
  if (target.id !== (pivotNode?.id)) parts.push(target.name || target.id || '?');
  return parts.map(p => p.split(':').pop()).join(' → ');
}

