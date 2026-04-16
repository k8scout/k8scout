// queries.js
// BloodHound-style pre-built graph queries

/* ================================================================
   QUERIES TAB — BloodHound-style pre-built graph queries
   ================================================================ */

// State for multi-path navigation in the query results panel.
let queryResults = [];    // array of { nodes: [], edges: [] } path objects OR node-id strings
let queryResultIdx = 0;   // currently displayed result index
let queryResultType = ''; // 'path' | 'enum'

// Standard forward-only adjacency over ATTACK_EDGE_KINDS.
function buildQueryAdj() {
  const adj = {};
  const edgeKindMap = {};
  if (!graphData) return { adj, edgeKindMap };
  graphData.nodes.forEach(n => { adj[n.id] = []; });
  graphData.edges.forEach(e => {
    const sid = edgeNodeId(e.source || e.from);
    const tid = edgeNodeId(e.target || e.to);
    if (!sid || !tid) return;
    if (ATTACK_EDGE_KINDS.has(e.kind)) {
      if (!adj[sid]) adj[sid] = [];
      adj[sid].push({ kind: e.kind, to: tid });
      edgeKindMap[`${sid}\u2192${tid}`] = e.kind;
    }
  });
  return { adj, edgeKindMap };
}

// Extended adjacency that also adds REVERSED 'grants' edges (CRB→SA becomes SA→CRB)
// so BFS from an Identity/SA can traverse the RBAC binding chain:
//   SA --[granted_by]--> CRB --[bound_to]--> ClusterRole:cluster-admin
// Without this, the binding chain is invisible to forward BFS from SA nodes.
function buildQueryAdjFull() {
  const { adj, edgeKindMap } = buildQueryAdj();
  if (!graphData) return { adj, edgeKindMap };
  graphData.edges.forEach(e => {
    if (e.kind !== 'grants') return;
    const sid = edgeNodeId(e.source || e.from); // CRB
    const tid = edgeNodeId(e.target || e.to);   // SA/Identity
    if (!sid || !tid) return;
    if (!adj[tid]) adj[tid] = [];
    adj[tid].push({ kind: 'granted_by', to: sid });
  });
  return { adj, edgeKindMap };
}

// BFS from a set of source IDs towards nodes that satisfy targetFn.
// Returns the shortest path object { nodes: [], edges: [] } or null.
function bfsShortestPath(sourceIds, targetFn, adj) {
  const visited = new Map(); // nodeId → parent nodeId
  const queue = [];
  for (const sid of sourceIds) {
    if (!visited.has(sid)) {
      visited.set(sid, null);
      queue.push(sid);
    }
  }
  let found = null;
  outer: while (queue.length) {
    const cur = queue.shift();
    for (const { to } of (adj[cur] || [])) {
      if (visited.has(to)) continue;
      visited.set(to, cur);
      if (targetFn(nodeById[to])) {
        found = to;
        break outer;
      }
      queue.push(to);
    }
  }
  if (!found) return null;
  // Reconstruct path.
  const pathNodes = [];
  let cur = found;
  while (cur !== null) {
    pathNodes.unshift(cur);
    cur = visited.get(cur);
  }
  const pathEdges = [];
  for (let i = 0; i < pathNodes.length - 1; i++) {
    pathEdges.push({ from: pathNodes[i], to: pathNodes[i + 1] });
  }
  return { nodes: pathNodes, edges: pathEdges };
}

// Run BFS from ALL Identity/ServiceAccount sources and collect up to MAX_PATHS shortest paths
// (one per distinct source→target pair) satisfying targetFn.
function bfsAllSources(targetFn, adj) {
  const MAX_PATHS = 30;
  const sources = graphData.nodes.filter(n =>
    n.kind === 'Identity' || n.kind === 'ServiceAccount'
  ).map(n => n.id);

  const seen = new Set(); // "srcId→tgtId" dedup
  const paths = [];
  for (const sid of sources) {
    if (paths.length >= MAX_PATHS) break;
    const path = bfsShortestPath([sid], targetFn, adj);
    if (!path) continue;
    const key = `${path.nodes[0]}\u2192${path.nodes[path.nodes.length - 1]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    paths.push(path);
  }
  return paths;
}

// Map from query id → function that returns results (path[] or nodeId[]).
const QUERIES = {
  // ── Path Queries ──────────────────────────────────────────────────────────

  // IMPROVED: uses buildQueryAdjFull() so the binding chain SA→CRB→ClusterRole
  // is visible to BFS (reversed 'grants' edges allow SA→CRB traversal).
  clusteradmin: () => {
    const { adj } = buildQueryAdjFull();
    return bfsAllSources(n => n && (
      (n.kind === 'ClusterRole' || n.kind === 'ClusterRoleBinding') &&
      (n.id || '').toLowerCase().includes('cluster-admin')
    ), adj);
  },

  anysecret: ({ adj }) => bfsAllSources(
    n => n && n.kind === 'Secret',
    adj
  ),

  anynode: ({ adj }) => bfsAllSources(
    n => n && n.kind === 'Node',
    adj
  ),

  privpod: ({ adj }) => bfsAllSources(
    n => n && (n.kind === 'Workload' || n.kind === 'Pod') && (n.risk_score || 0) >= 7,
    adj
  ),

  // NEW: shortest path where at least one hop uses can_impersonate.
  // Targets any resource node that is the object of a can_impersonate edge.
  impersonate: ({ adj }) => {
    const impersonateTargets = new Set();
    graphData.edges.forEach(e => {
      if (e.kind === 'can_impersonate')
        impersonateTargets.add(edgeNodeId(e.target || e.to));
    });
    if (!impersonateTargets.size) return [];
    return bfsAllSources(n => n && impersonateTargets.has(n.id), adj);
  },

  // NEW: shortest path to any Secret in the kube-system namespace.
  kubesystem: ({ adj }) => bfsAllSources(
    n => n && n.kind === 'Secret' &&
         (n.namespace === 'kube-system' || (n.id || '').startsWith('secret:kube-system:')),
    adj
  ),

  // NEW: shortest path to a ServiceAccount that carries a cloud IAM annotation.
  cloudiam_path: ({ adj }) => bfsAllSources(
    n => n && n.kind === 'ServiceAccount' && n.metadata && n.metadata.cloud_role,
    adj
  ),

  // NEW: shortest path to any admission Webhook node.
  webhook: ({ adj }) => bfsAllSources(
    n => n && n.kind === 'Webhook',
    adj
  ),

  // ── Enumeration Queries ───────────────────────────────────────────────────

  // IMPROVED: uses raw binding data + reverse BFS through the full
  // grants/bound_to chain instead of checking only direct 1-hop edges.
  alladmins: () => {
    if (!graphData) return [];
    const results = new Set();

    // Pass 1 — raw binding data (most reliable when available).
    const rawCRBs = rawGraphData?.cluster_objects?.cluster_role_bindings || [];
    rawCRBs.forEach(crb => {
      if (crb.role_ref?.name === 'cluster-admin') {
        (crb.subjects || []).forEach(s => {
          if (s.kind === 'ServiceAccount')
            results.add(`sa:${s.namespace}:${s.name}`);
          else
            results.add(`identity:${s.name}`);
        });
      }
    });

    // Pass 2 — reverse BFS from cluster-admin nodes through bound_to + grants.
    const adminNodeIds = new Set(
      graphData.nodes
        .filter(n => (n.kind === 'ClusterRole' || n.kind === 'ClusterRoleBinding') &&
                     (n.id || '').toLowerCase().includes('cluster-admin'))
        .map(n => n.id)
    );
    // Build reverse adj for binding edges only.
    const revAdj = {};
    graphData.edges.forEach(e => {
      if (e.kind !== 'grants' && e.kind !== 'bound_to') return;
      const tid = edgeNodeId(e.target || e.to);
      const sid = edgeNodeId(e.source || e.from);
      if (!revAdj[tid]) revAdj[tid] = [];
      revAdj[tid].push(sid);
    });
    const visited = new Set(adminNodeIds);
    const queue = [...adminNodeIds];
    while (queue.length) {
      const cur = queue.shift();
      for (const src of (revAdj[cur] || [])) {
        if (visited.has(src)) continue;
        visited.add(src);
        const n = nodeById[src];
        if (n && (n.kind === 'Identity' || n.kind === 'ServiceAccount'))
          results.add(src);
        queue.push(src);
      }
    }

    return [...results].filter(id => nodeById[id]);
  },

  execaccess: () => {
    if (!graphData) return [];
    const execSources = new Set();
    graphData.edges.forEach(e => {
      if (e.kind === 'can_exec')
        execSources.add(edgeNodeId(e.source || e.from));
    });
    return [...execSources].filter(id => {
      const n = nodeById[id];
      return n && (n.kind === 'Identity' || n.kind === 'ServiceAccount');
    });
  },

  // IMPROVED: checks both graph metadata AND raw SA annotation fields
  // (irsa_role, azure_identity, gcp_service_account).
  cloudiam: () => {
    if (!graphData) return [];
    const results = new Set();
    graphData.nodes.forEach(n => {
      if ((n.kind === 'Identity' || n.kind === 'ServiceAccount') &&
          n.metadata && n.metadata.cloud_role)
        results.add(n.id);
    });
    const rawSAs = rawGraphData?.cluster_objects?.service_accounts || [];
    rawSAs.forEach(sa => {
      if (sa.irsa_role || sa.azure_identity || sa.gcp_service_account)
        results.add(`sa:${sa.namespace}:${sa.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  crossns: () => {
    if (!graphData) return [];
    const results = [];
    const seen = new Set();
    graphData.edges.forEach(e => {
      const sid = edgeNodeId(e.source || e.from);
      const tid = edgeNodeId(e.target || e.to);
      if (!sid || !tid) return;
      const sn = nodeById[sid], tn = nodeById[tid];
      if (!sn || !tn) return;
      const sns = sn.namespace || '';
      const tns = tn.namespace || '';
      if (!sns || !tns || sns === tns) return;
      // Deduplicate by src+tgt pair.
      const key = `${sid}|${tid}`;
      if (seen.has(key)) return;
      seen.add(key);
      results.push({ nodes: [sid, tid], edges: [{ from: sid, to: tid, kind: e.kind }] });
    });
    return results;
  },

  // NEW: principals (SA/Identity) bound to any ClusterRole that has '*' verbs or resources.
  wildrole: () => {
    if (!graphData) return [];
    const results = new Set();
    // Find wildcard ClusterRole names from raw data.
    const rawRoles = rawGraphData?.cluster_objects?.cluster_roles || [];
    const wildcardRoleIds = new Set(
      rawRoles
        .filter(r => (r.rules || []).some(rule =>
          (rule.verbs || []).includes('*') || (rule.resources || []).includes('*')
        ))
        .map(r => 'clusterrole:' + r.name)
    );
    if (!wildcardRoleIds.size) return [];
    // Find CRBs whose bound_to target is a wildcard ClusterRole.
    const wildcardCRBs = new Set();
    graphData.edges.forEach(e => {
      if (e.kind !== 'bound_to') return;
      const tid = edgeNodeId(e.target || e.to);
      const sid = edgeNodeId(e.source || e.from);
      if (wildcardRoleIds.has(tid)) wildcardCRBs.add(sid);
    });
    // Find SA/Identity nodes granted by those CRBs.
    graphData.edges.forEach(e => {
      if (e.kind !== 'grants') return;
      const sid = edgeNodeId(e.source || e.from);
      const tid = edgeNodeId(e.target || e.to);
      if (!wildcardCRBs.has(sid)) return;
      const n = nodeById[tid];
      if (n && (n.kind === 'Identity' || n.kind === 'ServiceAccount'))
        results.add(tid);
    });
    return [...results];
  },

  // NEW: Identity/SA nodes whose risk_score is >= 7 (HIGH/CRITICAL via inference).
  overprivsa: () => {
    if (!graphData) return [];
    return graphData.nodes
      .filter(n => (n.kind === 'Identity' || n.kind === 'ServiceAccount') &&
                   (n.risk_score || 0) >= 7)
      .map(n => n.id);
  },

  // NEW: Workload/Pod nodes that run as the 'default' service account.
  defaultsa: () => {
    if (!graphData) return [];
    const defaultSAIds = new Set(
      graphData.nodes
        .filter(n => n.kind === 'ServiceAccount' && n.name === 'default')
        .map(n => n.id)
    );
    const results = new Set();
    graphData.edges.forEach(e => {
      if (e.kind !== 'runs_as') return;
      const tid = edgeNodeId(e.target || e.to);
      if (defaultSAIds.has(tid))
        results.add(edgeNodeId(e.source || e.from));
    });
    return [...results];
  },

  // NEW: Identity/SA nodes that have any can_delete edge.
  deleters: () => {
    if (!graphData) return [];
    const results = new Set();
    graphData.edges.forEach(e => {
      if (e.kind !== 'can_delete') return;
      const sid = edgeNodeId(e.source || e.from);
      const n = nodeById[sid];
      if (n && (n.kind === 'Identity' || n.kind === 'ServiceAccount'))
        results.add(sid);
    });
    return [...results];
  },

  // NEW: principals with can_bind or can_escalate edges — these allow creating
  // role bindings or writing roles with permissions the identity doesn't currently hold.
  bindescalate: () => {
    if (!graphData) return [];
    const results = new Set();
    graphData.edges.forEach(e => {
      if (e.kind !== 'can_bind' && e.kind !== 'can_escalate') return;
      const sid = edgeNodeId(e.source || e.from);
      const n = nodeById[sid];
      if (n && (n.kind === 'Identity' || n.kind === 'ServiceAccount'))
        results.add(sid);
    });
    return [...results];
  },

  // NEW: Secret nodes where values were actually captured during the scan
  // (metadata.has_captured_values = "true"), meaning the scanner had GET access.
  capturedsecrets: () => {
    if (!graphData) return [];
    return graphData.nodes
      .filter(n => n.kind === 'Secret' && n.metadata?.has_captured_values === 'true')
      .map(n => n.id);
  },

  // NEW: Workload/Pod nodes whose containers have dangerous Linux capabilities
  // (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH).
  dangerouscaps: () => {
    if (!graphData) return [];
    const results = new Set();
    const wls = rawGraphData?.cluster_objects?.workloads || [];
    wls.forEach(wl => {
      if ((wl.dangerous_capabilities || []).length > 0)
        results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    const pods = rawGraphData?.cluster_objects?.pods || [];
    pods.forEach(pod => {
      if ((pod.dangerous_capabilities || []).length > 0)
        results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  // NEW: ServiceAccount nodes that have no incoming runs_as edge — no workload
  // currently uses them, but they may still hold powerful RBAC permissions.
  orphanedsa: () => {
    if (!graphData) return [];
    const usedSAs = new Set();
    graphData.edges.forEach(e => {
      if (e.kind === 'runs_as')
        usedSAs.add(edgeNodeId(e.target || e.to));
    });
    return graphData.nodes
      .filter(n => n.kind === 'ServiceAccount' && !usedSAs.has(n.id))
      .map(n => n.id);
  },

  // NEW: principals with can_portforward edges — enables TCP tunneling to pod
  // ports, bypassing NetworkPolicies.
  portforward: () => {
    if (!graphData) return [];
    const results = new Set();
    graphData.edges.forEach(e => {
      if (e.kind !== 'can_portforward') return;
      const sid = edgeNodeId(e.source || e.from);
      const n = nodeById[sid];
      if (n && (n.kind === 'Identity' || n.kind === 'ServiceAccount'))
        results.add(sid);
    });
    return [...results];
  },

  // NEW: Workload/Pod nodes that have plaintext credentials hardcoded in
  // environment variables (matched against sensitive name patterns).
  plaintextenv: () => {
    if (!graphData) return [];
    const results = new Set();
    const wls = rawGraphData?.cluster_objects?.workloads || [];
    wls.forEach(wl => {
      if ((wl.plaintext_env_vars || []).length > 0)
        results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    const pods = rawGraphData?.cluster_objects?.pods || [];
    pods.forEach(pod => {
      if ((pod.plaintext_env_vars || []).length > 0)
        results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  // NEW: principals with can_create or can_patch edges whose target is a
  // role/clusterrole resource node — these can write new privilege grants.
  rolewriters: () => {
    if (!graphData) return [];
    const results = new Set();
    graphData.edges.forEach(e => {
      if (e.kind !== 'can_create' && e.kind !== 'can_patch') return;
      const tid = edgeNodeId(e.target || e.to);
      const tgt = nodeById[tid];
      if (!tgt) return;
      if (tgt.kind !== 'ClusterRole' && tgt.kind !== 'Role' &&
          !(tgt.id || '').match(/resource:.*:(cluster)?roles/)) return;
      const sid = edgeNodeId(e.source || e.from);
      const n = nodeById[sid];
      if (n && (n.kind === 'Identity' || n.kind === 'ServiceAccount'))
        results.add(sid);
    });
    return [...results];
  },

  // NEW: Secret nodes with type "helm.sh/release.v1" — these store rendered
  // Helm release manifests which typically contain all values including credentials.
  helmsecrets: () => {
    if (!graphData) return [];
    const fromGraph = graphData.nodes
      .filter(n => n.kind === 'Secret' && n.metadata?.type === 'helm.sh/release.v1')
      .map(n => n.id);
    const fromRaw = (rawGraphData?.cluster_objects?.secrets_meta || [])
      .filter(s => s.type === 'helm.sh/release.v1')
      .map(s => `secret:${s.namespace}:${s.name}`);
    return [...new Set([...fromGraph, ...fromRaw])].filter(id => nodeById[id]);
  },

  // ── Pod Security Queries ──────────────────────────────────────────────────
  // All six queries scan raw workload + pod data and map to graph node IDs.

  // Workloads/Pods with at least one container running with privileged: true.
  privilegedpods: () => {
    if (!graphData) return [];
    const results = new Set();
    (rawGraphData?.cluster_objects?.workloads || []).forEach(wl => {
      if ((wl.privileged_containers || []).length > 0)
        results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    (rawGraphData?.cluster_objects?.pods || []).forEach(pod => {
      if ((pod.privileged_containers || []).length > 0)
        results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  // Workloads/Pods with hostPID: true — shares the host PID namespace,
  // allowing containers to see and signal all host processes.
  hostpidpods: () => {
    if (!graphData) return [];
    const results = new Set();
    (rawGraphData?.cluster_objects?.workloads || []).forEach(wl => {
      if (wl.host_pid) results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    (rawGraphData?.cluster_objects?.pods || []).forEach(pod => {
      if (pod.host_pid) results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  // Workloads/Pods with hostIPC: true — shares the host IPC namespace,
  // enabling shared memory introspection of host processes.
  hostipcpods: () => {
    if (!graphData) return [];
    const results = new Set();
    (rawGraphData?.cluster_objects?.workloads || []).forEach(wl => {
      if (wl.host_ipc) results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    (rawGraphData?.cluster_objects?.pods || []).forEach(pod => {
      if (pod.host_ipc) results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  // Workloads/Pods with hostNetwork: true — shares the host network stack,
  // bypassing NetworkPolicies and exposing host-level network interfaces.
  hostnetpods: () => {
    if (!graphData) return [];
    const results = new Set();
    (rawGraphData?.cluster_objects?.workloads || []).forEach(wl => {
      if (wl.host_network) results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    (rawGraphData?.cluster_objects?.pods || []).forEach(pod => {
      if (pod.host_network) results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  // Workloads/Pods that mount host filesystem paths (hostPath volumes).
  hostpathpods: () => {
    if (!graphData) return [];
    const results = new Set();
    (rawGraphData?.cluster_objects?.workloads || []).forEach(wl => {
      if ((wl.host_path_mounts || []).length > 0)
        results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    (rawGraphData?.cluster_objects?.pods || []).forEach(pod => {
      if ((pod.host_path_mounts || []).length > 0)
        results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },

  // Workloads/Pods where the SA token is NOT explicitly disabled
  // (automount_sa_token !== false). These containers have the SA token
  // available at /var/run/secrets/kubernetes.io/serviceaccount/token.
  automountpods: () => {
    if (!graphData) return [];
    const results = new Set();
    (rawGraphData?.cluster_objects?.workloads || []).forEach(wl => {
      if (wl.automount_sa_token !== false)
        results.add(`workload:${wl.namespace}:${wl.name}`);
    });
    (rawGraphData?.cluster_objects?.pods || []).forEach(pod => {
      if (pod.automount_sa_token !== false)
        results.add(`pod:${pod.namespace}:${pod.name}`);
    });
    return [...results].filter(id => nodeById[id]);
  },
};

function runQuery(queryId) {
  if (!graphData) {
    alert('Load a JSON file first.');
    return;
  }
  // Mark button as running
  const btn = document.getElementById('qbtn-' + queryId);
  if (btn) btn.classList.add('running');

  setTimeout(() => {
    const { adj } = buildQueryAdj();
    const raw = QUERIES[queryId]({ adj });

    // Determine type: path queries return objects with .nodes, enum queries return string ids
    const isPathQuery = [
      'clusteradmin','anysecret','anynode','privpod',
      'impersonate','kubesystem','cloudiam_path','webhook',
      'crossns',
    ].includes(queryId);

    queryResults = raw || [];
    queryResultIdx = 0;
    queryResultType = isPathQuery ? 'path' : 'enum';

    // Reset button states, mark this one
    document.querySelectorAll('.query-btn').forEach(b => {
      b.classList.remove('running', 'has-results');
    });
    if (btn && queryResults.length > 0) btn.classList.add('has-results');

    renderQueryResults();
  }, 0);
}

function renderQueryResults() {
  const area = document.getElementById('query-results-area');
  const badge = document.getElementById('query-count-badge');
  const nav = document.getElementById('query-path-nav');
  const cards = document.getElementById('query-result-cards');

  area.style.display = '';
  const count = queryResults.length;

  if (count === 0) {
    badge.className = 'query-count-badge no-results';
    badge.textContent = 'No results';
    nav.style.display = 'none';
    cards.innerHTML = '<div class="query-empty">No matching nodes or paths found in the current graph.</div>';
    return;
  }

  badge.className = 'query-count-badge has-results';
  badge.textContent = count + ' result' + (count > 1 ? 's' : '');

  if (queryResultType === 'path') {
    nav.style.display = 'flex';
    updateQueryNav();
    renderQueryPathCard(queryResults[queryResultIdx], queryResultIdx);
  } else {
    // Enum: show all nodes as chips, with a single Highlight All + Clear
    nav.style.display = 'none';
    renderQueryEnumCards(queryResults);
  }
}

function updateQueryNav() {
  const total = queryResults.length;
  document.getElementById('qnav-label').textContent = `Path ${queryResultIdx + 1} of ${total}`;
  document.getElementById('qnav-prev').disabled = queryResultIdx <= 0;
  document.getElementById('qnav-next').disabled = queryResultIdx >= total - 1;
}

function queryNavStep(delta) {
  queryResultIdx = Math.max(0, Math.min(queryResults.length - 1, queryResultIdx + delta));
  updateQueryNav();
  renderQueryPathCard(queryResults[queryResultIdx], queryResultIdx);
}

function nodeChipHtml(nodeId) {
  const n = nodeById[nodeId];
  if (!n) return `<span class="path-node-chip" style="background:var(--surface3)">${escHtml(nodeId)}</span>`;
  const color = queryNodeColor(n);
  const label = n.name || n.id || nodeId;
  const ns = n.namespace || n.metadata?.namespace || '';
  const display = ns ? `${escHtml(ns)}/${escHtml(label)}` : escHtml(label);
  return `<span class="path-node-chip" style="background:${color}22;border:1px solid ${color};color:${color}" title="${escHtml(n.kind||'')}: ${escHtml(n.id||'')}">
    ${escHtml(n.kind || '')} ${display}
  </span>`;
}

function queryNodeColor(n) {
  if (!n) return '#8b909a';
  return nodeColor(n) || '#8b909a';
}

function renderQueryPathCard(path, idx) {
  if (!path) return;
  const cards = document.getElementById('query-result-cards');
  let chain = '';
  for (let i = 0; i < path.nodes.length; i++) {
    chain += nodeChipHtml(path.nodes[i]);
    if (i < path.nodes.length - 1) {
      const edgeKind = (path.edges[i] && (path.edges[i].kind || '')) || '';
      chain += `<span class="path-arrow">&rarr;</span>`;
      if (edgeKind) chain += `<span class="path-edge-badge">${escHtml(edgeKind)}</span><span class="path-arrow">&rarr;</span>`;
    }
  }
  const cardId = 'qrc-' + idx;
  cards.innerHTML = `
    <div class="query-result-card" id="${cardId}">
      <div class="query-result-chain path-chain">${chain}</div>
      <div class="query-result-actions">
        <button class="query-action-btn" onclick="highlightQueryPath(${idx})">Highlight in Graph</button>
        <button class="query-action-btn clear-btn" onclick="clearQueryResults()">Clear</button>
      </div>
    </div>`;
}

function renderQueryEnumCards(nodeIds) {
  const cards = document.getElementById('query-result-cards');
  if (!nodeIds.length) { cards.innerHTML = ''; return; }

  let html = `<div class="query-result-card">
    <div class="query-result-chain path-chain">`;
  for (const nid of nodeIds) {
    html += nodeChipHtml(nid) + ' ';
  }
  html += `</div>
    <div class="query-result-actions">
      <button class="query-action-btn" onclick="highlightQueryEnum()">Highlight in Graph</button>
      <button class="query-action-btn clear-btn" onclick="clearQueryResults()">Clear</button>
    </div>
  </div>`;
  cards.innerHTML = html;
}

function highlightQueryPath(idx) {
  const path = queryResults[idx];
  if (!path) return;
  highlightPath(path);
  // Switch to attack paths tab so user can see the graph highlight
  document.querySelector('.tab[data-tab="paths"]').click();
}

function highlightQueryEnum() {
  if (!queryResults.length) return;
  const nodeIds = queryResults;
  const pathNodeSet = new Set(nodeIds);
  nodesLayer.selectAll('circle.node-circle')
    .classed('dimmed',      d => !pathNodeSet.has(d.id))
    .classed('highlighted', false)
    .classed('path-active', d => pathNodeSet.has(d.id));
  linksLayer.selectAll('path.edge-path')
    .classed('dimmed', true)
    .classed('highlighted', false)
    .classed('path-active', false);
  fitNodesToView(nodeIds);
}

function clearQueryResults() {
  clearPathHighlight();
  queryResults = [];
  queryResultIdx = 0;
  const area = document.getElementById('query-results-area');
  area.style.display = 'none';
  document.querySelectorAll('.query-btn').forEach(b => b.classList.remove('has-results','running'));
}
</script>
