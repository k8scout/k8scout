// briefing.js
// SA usage index, data layer indices, briefing view, path view, foothold header

/* ================================================================
   SA USAGE INDEX
   Tracks which ServiceAccounts are actually used by running pods/workloads.
   Populated from runs_as edges after data load; used by securityCategory()
   to distinguish "privilege with a foothold" from "privilege in isolation".
   ================================================================ */
function buildSAUsageIndex() {
  saWithWorkload.clear();
  saWithPrivilegedWorkload.clear();
  if (!graphData) return;
  graphData.edges.forEach(e => {
    if (e.kind !== 'runs_as') return;
    const src = edgeNodeId(e.source || e.from);
    const tgt = edgeNodeId(e.target || e.to);
    if (!src || !tgt) return;
    saWithWorkload.add(tgt);
    const wl = nodeById[src];
    if (wl && nodeHasSpecialConfig(wl)) {
      saWithPrivilegedWorkload.add(tgt);
    }
  });
  dataLayer.saUsage = {
    withWorkload: new Set(saWithWorkload),
    withPrivilegedWorkload: new Set(saWithPrivilegedWorkload),
  };
}

function resetTransientState() {
  selectedNodeId = null;
  activeFindingId = null;
  activePathIdx = null;
  activePathNodeIds = new Set();
  computedPaths = [];
  nodePosMap = {};
}

function buildDataLayerIndices(raw, nodes, edges, findings) {
  const index = createEmptyDataLayer();
  index.nodes = nodes;
  index.edges = edges;
  index.findings = findings;
  index.fullGraph = { nodes, edges, findings };
  index.nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
  index.adjacency.out = createAdjacencyBuckets(nodes);
  index.adjacency.in = createAdjacencyBuckets(nodes);
  index.adjacency.attackOut = createAdjacencyBuckets(nodes);
  index.adjacency.attackIn = createAdjacencyBuckets(nodes);

  edges.forEach((edge, edgeIdx) => {
    const from = edgeNodeId(edge.source || edge.from);
    const to = edgeNodeId(edge.target || edge.to);
    if (!from || !to) return;
    const entry = { edge, edgeIdx, from, to, kind: edge.kind };
    (index.adjacency.out[from] ||= []).push(entry);
    (index.adjacency.in[to] ||= []).push(entry);
    if (ATTACK_EDGE_KINDS.has(edge.kind)) {
      (index.adjacency.attackOut[from] ||= []).push(entry);
      (index.adjacency.attackIn[to] ||= []).push(entry);
    }
  });

  findings.forEach(finding => {
    (finding.affected_nodes || []).forEach(nodeId => {
      (index.findingsByNode[nodeId] ||= []).push(finding);
    });
  });

  index.foothold = extractFoothold(raw, { nodes, edges }, index.nodeById);
  return index;
}

function hashText(input) {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

function ensurePathId(path, idx) {
  if (path._pathId) return path._pathId;
  const signature = path.nodes.join('→');
  path._pathId = `path-${idx}-${hashText(signature)}`;
  path._pathSignature = signature;
  return path._pathId;
}

function buildActionsByNode() {
  const actionsByNode = {};

  computedPaths.forEach((path, idx) => {
    if (!path?.nodes?.length || !path?.edges?.length) return;
    const sourceId = path.nodes[0];
    const targetId = path.nodes[path.nodes.length - 1];
    const firstHopId = path.nodes[1];
    const edgeKind = path.edges[0];
    if (!sourceId || !firstHopId || !edgeKind) return;

    const target = nodeById[targetId];
    const firstHop = nodeById[firstHopId];
    const impact = pathImpactType(path);
    const edgeWeight = EDGE_WEIGHT[edgeKind] || 5;
    const pathWeight = (path.edges || []).reduce((sum, kind) => sum + (EDGE_WEIGHT[kind] || 5), 0);
    const ranking = impact.score / Math.max(edgeWeight, 0.1);
    const dedupeKey = `${edgeKind}:${firstHopId}`;

    const current = (actionsByNode[sourceId] ||= {});
    const nextCandidate = {
      dedupeKey,
      sourceId,
      targetId: firstHopId,
      terminalTargetId: targetId,
      edgeKind,
      impact,
      edgeWeight,
      pathWeight,
      ranking,
      narrative: getPathNarrative(path),
      pathId: ensurePathId(path, idx),
      path,
      target: firstHop,
      terminalTarget: target,
    };

    if (!current[dedupeKey] || nextCandidate.ranking > current[dedupeKey].ranking) {
      current[dedupeKey] = nextCandidate;
    }
  });

  return Object.fromEntries(
    Object.entries(actionsByNode).map(([nodeId, actionMap]) => [
      nodeId,
      Object.values(actionMap).sort((a, b) => {
        if (b.ranking !== a.ranking) return b.ranking - a.ranking;
        if (b.impact.score !== a.impact.score) return b.impact.score - a.impact.score;
        return a.edgeWeight - b.edgeWeight;
      }),
    ])
  );
}

function rebuildPathIndices() {
  const pathsById = {};
  const pathsByImpact = {};
  const pathRows = [];

  computedPaths.forEach((path, idx) => {
    const pathId = ensurePathId(path, idx);
    const impact = pathImpactType(path);
    const source = nodeById[path.nodes[0]];
    const target = nodeById[path.nodes[path.nodes.length - 1]];
    // When the path carries a backend finding ID, use ONLY that finding's
    // metadata (accurate). Otherwise fall back to affected-node intersection
    // for frontend-DFS-only paths.
    const relatedFindings = path._findingId
      ? (graphData?.findings || []).filter(f => f.id === path._findingId)
      : (graphData?.findings || []).filter(f =>
          path.nodes.some(nodeId => (f.affected_nodes || []).includes(nodeId))
        );
    const mitreIds = path._mitreIds && path._mitreIds.length
      ? [...new Set(path._mitreIds)]
      : [...new Set(relatedFindings.flatMap(f => f.mitre_ids || []))];
    const namespaces = [...new Set(path.nodes.map(nodeId => nodeById[nodeId]?.namespace).filter(Boolean))];
    const edgeKinds = [...new Set(path.edges || [])];
    const searchText = [
      source?.name,
      target?.name,
      impact.label,
      impact.type,
      getPathNarrative(path),
      edgeKinds.join(' '),
      namespaces.join(' '),
      path.nodes.map(nodeId => nodeById[nodeId]?.name || nodeId).join(' '),
    ].filter(Boolean).join(' ').toLowerCase();
    const entry = {
      id: pathId,
      path,
      idx,
      impact,
      source,
      target,
      severity: pathSeverity(path),
      hopCount: Math.max(path.nodes.length - 1, 0),
      narrative: getPathNarrative(path),
      namespaces,
      edgeKinds,
      targetKind: target?.kind || '',
      mitreIds,
      relatedFindings,
      searchText,
    };
    pathsById[pathId] = entry;
    (pathsByImpact[impact.type] ||= []).push(entry);
    pathRows.push(entry);
  });

  const footholdIds = new Set(getFootholdSourceIds());
  const hasFoothold = footholdIds.size > 0;
  pathRows.forEach(row => {
    row.footholdRooted = hasFoothold && footholdIds.has(row.path.nodes[0]);
  });

  const sortPaths = hasFoothold
    ? (a, b) => {
        if (a.footholdRooted !== b.footholdRooted) return a.footholdRooted ? -1 : 1;
        if (b.impact.score !== a.impact.score) return b.impact.score - a.impact.score;
        return a.path.nodes.length - b.path.nodes.length;
      }
    : (a, b) => {
        if (b.impact.score !== a.impact.score) return b.impact.score - a.impact.score;
        return a.path.nodes.length - b.path.nodes.length;
      };

  Object.values(pathsByImpact).forEach(items => items.sort(sortPaths));
  pathRows.sort(sortPaths);

  dataLayer.pathsById = pathsById;
  dataLayer.pathsByImpact = pathsByImpact;
  dataLayer.pathRows = pathRows;
  dataLayer.actionsByNode = buildActionsByNode();
}

function getFootholdSourceIds() {
  const foothold = dataLayer.foothold || {};
  return [foothold.podId, foothold.workloadId, foothold.serviceAccountId, foothold.identityId].filter(Boolean);
}

function getBriefingFilterState() {
  const query = getCurrentRouteQuery();
  return {
    q: query.q || '',
    impact: query.impact || '',
    ns: query.ns || '',
    target: query.target || '',
    pathTab: query.pathTab || '',
  };
}

function getBriefingFilterOptions() {
  const rows = dataLayer.pathRows || [];
  const namespaces = [...new Set(rows.flatMap(row => row.namespaces))].sort();
  const targetKinds = [...new Set(rows.map(row => row.targetKind).filter(Boolean))].sort();
  return { namespaces, targetKinds };
}

function getFilteredBriefingRows(filterState) {
  return (dataLayer.pathRows || []).filter(row => {
    if (filterState.impact && row.impact.type !== filterState.impact) return false;
    if (filterState.ns && !row.namespaces.includes(filterState.ns)) return false;
    if (filterState.target && row.targetKind !== filterState.target) return false;
    if (filterState.q && !row.searchText.includes(filterState.q.toLowerCase())) return false;
    return true;
  });
}

function getBriefingImpactBuckets(filteredRows) {
  const defs = [
    { type: 'CLUSTER_ADMIN', label: 'Cluster-admin', desc: 'Paths to cluster-wide control.' },
    { type: 'NODE_BREAKOUT', label: 'Node escape', desc: 'Host compromise and kubelet pivots.' },
    { type: 'SECRET_EXFIL', label: 'Secret theft', desc: 'Direct credential and token access.' },
    { type: 'CLOUD_ESCALATION', label: 'Cloud IAM', desc: 'Projected identity and role takeover.' },
    { type: 'LATERAL_MOVE', label: 'Lateral movement', desc: 'Pivot into neighboring workloads.' },
    { type: 'PRIVESC', label: 'Workload mutation', desc: 'Patch, bind, or mutate toward impact.' },
  ];
  return defs.map(def => ({
    ...def,
    count: filteredRows.filter(row => row.impact.type === def.type).length,
  }));
}

function chainStampHtml(path) {
  const maxNodes = 5;
  const nodeIds = path.nodes || [];
  const visible = nodeIds.slice(0, maxNodes);
  const hidden = Math.max(nodeIds.length - visible.length, 0);
  const parts = [];
  visible.forEach((nodeId, idx) => {
    const node = nodeById[nodeId];
    const color = NODE_COLORS[node?.kind] || DEFAULT_NODE_COLOR;
    const label = node?.name || nodeId;
    parts.push(
      `<span class="chain-stamp-node" style="border-color:${color}45;color:${color}" title="${escHtml(`${node?.kind || 'Node'} ${label}`)}">
        <span>${escHtml(NODE_ICONS[node?.kind] || '•')}</span>
        <span>${escHtml(label.split(':').pop())}</span>
      </span>`
    );
    if (idx < visible.length - 1) parts.push('<span class="chain-stamp-arrow">›</span>');
  });
  if (hidden > 0) parts.push(`<span class="chain-stamp-node">+${hidden} more</span>`);
  return parts.join('');
}

function mountVirtualList(containerEl, items, options) {
  const {
    rowHeight = 116,
    overscan = 6,
    renderRow,
    emptyHtml = '<div class="brief-list-empty">No paths match the current filters.</div>',
  } = options || {};

  containerEl.innerHTML = '';
  if (!items.length) {
    containerEl.innerHTML = emptyHtml;
    return;
  }

  const viewport = document.createElement('div');
  viewport.className = 'brief-virtual-wrap';
  const inner = document.createElement('div');
  inner.className = 'brief-virtual-inner';
  inner.style.height = `${items.length * rowHeight}px`;
  viewport.appendChild(inner);
  containerEl.appendChild(viewport);

  function renderWindow() {
    const height = viewport.clientHeight || 500;
    const start = Math.max(Math.floor(viewport.scrollTop / rowHeight) - overscan, 0);
    const end = Math.min(items.length, Math.ceil((viewport.scrollTop + height) / rowHeight) + overscan);
    inner.innerHTML = '';
    for (let i = start; i < end; i++) {
      const row = document.createElement('div');
      row.className = 'brief-path-row';
      row.style.top = `${i * rowHeight}px`;
      row.style.height = `${rowHeight}px`;
      row.innerHTML = renderRow(items[i], i);
      inner.appendChild(row);
    }
  }

  viewport.addEventListener('scroll', renderWindow);
  renderWindow();
}

function renderBriefing() {
  const routeEl = document.getElementById('briefing-route');
  if (!routeEl) return;
  parkIdentityAnalyzer();

  if (!graphData) {
    routeEl.innerHTML = `
      <div id="briefing-view">
        <div class="brief-card brief-empty-card">
          <div class="brief-empty-icon">📂</div>
          <div class="brief-empty-title">Drop a k8scout JSON report</div>
          <div class="brief-empty-sub">The new default landing route is path-first. Load a report to get next-best actions, impact buckets, and a ranked attack path list without starting the full graph simulation.</div>
          <div class="brief-actions">
            <button class="brief-btn primary" id="brief-open-btn">Open JSON</button>
            <button class="brief-btn" id="brief-explore-btn">Open Explore</button>
          </div>
        </div>
      </div>
    `;
    document.getElementById('brief-open-btn')?.addEventListener('click', () => fileInput.click());
    document.getElementById('brief-explore-btn')?.addEventListener('click', () => route('/explore'));
    return;
  }

  const filters = getBriefingFilterState();
  const allRows = dataLayer.pathRows || [];
  const filteredRows = getFilteredBriefingRows(filters);
  const options = getBriefingFilterOptions();
  const buckets = getBriefingImpactBuckets(allRows);
  const foothold = dataLayer.foothold;
  const hasFoothold = foothold && foothold.serviceAccountId;

  const footholdRows = [];
  const otherRows = [];
  if (hasFoothold) {
    filteredRows.forEach(row => (row.footholdRooted ? footholdRows : otherRows).push(row));
  } else {
    otherRows.push(...filteredRows);
  }
  const hasOtherTab = hasFoothold && otherRows.length > 0;
  const activePathTab = hasFoothold
    ? ((filters.pathTab === 'other' && hasOtherTab) ? 'other' : 'foothold')
    : 'all';
  const activeTabRows = activePathTab === 'other' ? otherRows : footholdRows;
  const activeTabLabel = activePathTab === 'other' ? 'Other Cluster Paths' : 'Paths From This Foothold';
  const activeTabCount = activeTabRows.length;

  const summaryHtml = `
    <div id="brief-impact-grid" class="impact-grid${hasFoothold ? ' impact-grid-inline' : ''}"></div>
  `;

  const filterBarHtml = `
    <div class="brief-filter-bar">
      <input id="brief-search" class="brief-input" type="text" value="${escHtml(filters.q)}" placeholder="Search paths...">
      <select id="brief-namespace-filter" class="brief-select">
        <option value="">All namespaces</option>
        ${options.namespaces.map(ns => `<option value="${escHtml(ns)}"${filters.ns === ns ? ' selected' : ''}>${escHtml(ns)}</option>`).join('')}
      </select>
      <select id="brief-target-filter" class="brief-select">
        <option value="">Target type</option>
        ${options.targetKinds.map(kind => `<option value="${escHtml(kind)}"${filters.target === kind ? ' selected' : ''}>${escHtml(kind)}</option>`).join('')}
      </select>
    </div>
  `;

  routeEl.innerHTML = hasFoothold ? `
    <div id="briefing-view" class="fh-mode">
      <div class="fh-layout">
        <div class="fh-sidebar">
          <div class="brief-card fh-summary-card">
            <div class="brief-card-head">
              <div class="brief-card-title">Summary</div>
              <button class="brief-inline-btn" id="brief-clear-impact">Clear filter</button>
            </div>
            <div class="brief-card-body">${summaryHtml}</div>
          </div>
          <details class="brief-analyzer-collapse fh-analyzer-card">
            <summary>
              <span>Analyze From A Different Identity</span>
            </summary>
            <div class="brief-analyzer-collapse-body">
              <div class="brief-analyzer-sub">Pivot off the initial foothold using the cluster-wide chain analyzer.</div>
              <div id="brief-analyzer-slot" class="brief-analyzer-slot"></div>
            </div>
          </details>
        </div>
        <div class="fh-main">
          <div class="brief-card scroll-card" style="flex:1;">
            <div class="brief-card-head">
              <div>
                <div class="brief-card-title">${activeTabLabel} <span class="brief-meta" style="display:inline;margin-left:8px;">${activeTabCount} paths</span></div>
              </div>
              <div class="brief-path-actions">
                <button class="brief-btn" id="brief-open-json-inline">Open JSON</button>
                <button class="brief-btn primary" id="brief-explore-inline">Explore</button>
              </div>
            </div>
            ${hasOtherTab ? `
              <div class="brief-path-tabs">
                <button class="brief-path-tab${activePathTab === 'foothold' ? ' active' : ''}" data-path-tab="foothold">
                  From Foothold
                  <span class="brief-path-tab-count">${footholdRows.length}</span>
                </button>
                <button class="brief-path-tab${activePathTab === 'other' ? ' active' : ''}" data-path-tab="other">
                  Other Cluster Paths
                  <span class="brief-path-tab-count">${otherRows.length}</span>
                </button>
              </div>
            ` : ''}
            ${filterBarHtml}
            <div class="brief-list-meta">
              <span>${activePathTab === 'other' ? `${activeTabCount} other-cluster paths` : `${activeTabCount} foothold-rooted paths`}</span>
            </div>
            <div id="brief-path-list" class="brief-path-list-host"></div>
          </div>
        </div>
      </div>
    </div>
  ` : `
    <div id="briefing-view">
      <div class="briefing-grid">
        <div class="briefing-left">
          <div class="brief-card">
            <div class="brief-card-head">
              <div class="brief-card-title">Summary</div>
              <button class="brief-inline-btn" id="brief-clear-impact">Clear filter</button>
            </div>
            <div class="brief-card-body">${summaryHtml}</div>
          </div>
          <details class="brief-analyzer-collapse">
            <summary>
              <span>Analyze From A Different Identity</span>
            </summary>
            <div class="brief-analyzer-collapse-body">
              <div class="brief-analyzer-sub">Pivot off the initial foothold using the cluster-wide chain analyzer.</div>
              <div id="brief-analyzer-slot" class="brief-analyzer-slot"></div>
            </div>
          </details>
        </div>
        <div class="briefing-main">
          <div class="brief-card scroll-card" style="flex:1;">
            <div class="brief-card-head">
              <div>
                <div class="brief-card-title">Top Attack Paths</div>
              </div>
              <div class="brief-path-actions">
                <button class="brief-btn" id="brief-open-json-inline">Open JSON</button>
                <button class="brief-btn primary" id="brief-explore-inline">Explore</button>
              </div>
            </div>
            ${filterBarHtml}
            <div class="brief-list-meta">
              <span>${filteredRows.length} of ${allRows.length} paths</span>
            </div>
            <div id="brief-path-list" class="brief-path-list-host"></div>
          </div>
        </div>
      </div>
    </div>
  `;

  const impactGrid = routeEl.querySelector('#brief-impact-grid');
  if (impactGrid) {
    impactGrid.innerHTML = buckets.map(bucket => `
      <div class="impact-tile${filters.impact === bucket.type ? ' active' : ''}" data-impact="${bucket.type}">
        <div class="impact-tile-head">
          <div class="impact-tile-label">${escHtml(bucket.label)}</div>
          <div class="impact-tile-count">${bucket.count}</div>
        </div>
        <div class="impact-tile-sub">${escHtml(bucket.desc)}</div>
      </div>
    `).join('');
    impactGrid.querySelectorAll('[data-impact]').forEach(tile => {
      tile.addEventListener('click', () => {
        const impact = tile.dataset.impact;
        updateRouteQuery({ impact: filters.impact === impact ? '' : impact }, '/briefing');
      });
    });
  }
  routeEl.querySelector('#brief-clear-impact')?.addEventListener('click', () => updateRouteQuery({ impact: '' }, '/briefing'));
  routeEl.querySelectorAll('[data-path-tab]').forEach(btn => {
    btn.addEventListener('click', () => updateRouteQuery({ pathTab: btn.dataset.pathTab }, '/briefing'));
  });

  routeEl.querySelector('#brief-open-json-inline')?.addEventListener('click', () => fileInput.click());
  routeEl.querySelector('#brief-explore-inline')?.addEventListener('click', () => route('/explore'));

  const wireInput = (id, key) => {
    const el = routeEl.querySelector(id);
    if (!el) return;
    const handler = () => updateRouteQuery({ [key]: el.value.trim() }, '/briefing');
    el.addEventListener(el.tagName === 'INPUT' ? 'input' : 'change', handler);
  };
  wireInput('#brief-search', 'q');
  wireInput('#brief-namespace-filter', 'ns');
  wireInput('#brief-target-filter', 'target');
  mountIdentityAnalyzer(routeEl.querySelector('#brief-analyzer-slot'));

  const renderPathRow = row => `
    <div class="brief-path-card" data-path-id="${row.id}">
      <div class="brief-path-top">
        <div>
          <div class="brief-path-title">
            <span class="sev-badge ${row.severity}">${row.severity}</span>
            <span>${escHtml(row.impact.label)}</span>
            <span class="mini-chip"><strong>Hops</strong> ${row.hopCount}</span>
          </div>
        </div>
        <button class="brief-inline-btn" data-open-path="${row.id}">Open</button>
      </div>
      <div class="chain-stamp">${chainStampHtml(row.path)}</div>
    </div>
  `;

  const rowHeight = window.innerWidth < 760 ? 116 : 106;
  const primaryRows = hasFoothold ? activeTabRows : filteredRows;

  const pathListHost = routeEl.querySelector('#brief-path-list');
  mountVirtualList(pathListHost, primaryRows, {
    rowHeight,
    overscan: 8,
    renderRow: renderPathRow,
    emptyHtml: hasFoothold
      ? (activePathTab === 'other'
          ? '<div class="brief-list-empty">No other cluster paths match the current filters.</div>'
          : '<div class="brief-list-empty">No paths start from this foothold identity. Switch tabs or use a different identity.</div>')
      : '<div class="brief-list-empty">No paths match the current filters.</div>',
  });

  const wirePathClicks = host => {
    host?.addEventListener('click', e => {
      const openBtn = e.target.closest('[data-open-path]');
      if (openBtn) {
        e.stopPropagation();
        route(`/path/${encodeURIComponent(openBtn.dataset.openPath)}`);
        return;
      }
      const card = e.target.closest('.brief-path-card[data-path-id]');
      if (card) route(`/path/${encodeURIComponent(card.dataset.pathId)}`);
    });
  };
  wirePathClicks(pathListHost);
}

function getPathRouteState() {
  const query = getCurrentRouteQuery();
  const hop = Math.max(0, parseInt(query.hop || '0', 10) || 0);
  return { hop, focus: query.focus || '' };
}

function summarizeWhyItWorks(src, tgt, edgeKind) {
  const inbound = (dataLayer.adjacency.in[src?.id] || []).filter(entry =>
    ['grants', 'bound_to', 'granted_by', 'member_of', 'runs_as', 'mounts', 'authenticates_as'].includes(entry.kind)
  );

  if (edgeKind === 'runs_as') {
    return `${src?.kind || 'Workload'} ${src?.name || '?'} runs as service account ${tgt?.name || '?'}, so compromising the workload yields that identity automatically.`;
  }
  if (edgeKind === 'mounts') {
    return `${src?.kind || 'Workload'} ${src?.name || '?'} mounts ${tgt?.kind || 'resource'} ${tgt?.name || '?'}, exposing it from inside the workload context.`;
  }
  if (edgeKind === 'authenticates_as') {
    return `${src?.kind || 'Secret'} ${src?.name || '?'} contains credentials that authenticate as ${tgt?.kind || 'identity'} ${tgt?.name || '?'}.`;
  }
  if (edgeKind === 'assumes_cloud_role') {
    return `${src?.name || '?'} is mapped to cloud identity ${tgt?.name || '?'}, allowing the workload identity to inherit cloud permissions.`;
  }
  if (edgeKind === 'runs_on') {
    return `${src?.name || '?'} is already positioned on node ${tgt?.name || '?'}, so a container escape or privileged host access lands on the host.`;
  }
  if (!inbound.length) {
    return `${src?.kind || 'Node'} ${src?.name || '?'} has the ${edgeKind} relationship to ${tgt?.kind || 'target'} ${tgt?.name || '?'}, as confirmed in the attack graph.`;
  }

  const reasons = inbound.slice(0, 3).map(entry => {
    const fromNode = nodeById[entry.from];
    return `${fromNode?.kind || 'Upstream object'} ${fromNode?.name || entry.from} ${entry.kind.replace(/_/g, ' ')} ${src?.name || '?'}`;
  });
  return `${reasons.join('; ')}. That chain enables ${src?.name || '?'} to ${edgeKind.replace(/_/g, ' ')} ${tgt?.name || '?'}.`;
}

function getHopEvidence(srcId, tgtId) {
  const srcFindings = dataLayer.findingsByNode[srcId] || [];
  const tgtFindings = dataLayer.findingsByNode[tgtId] || [];
  const seen = new Set();
  return [...srcFindings, ...tgtFindings].filter(f => {
    const key = f.id || f.title;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 4);
}

function getHopAlternatives(srcId, currentTargetId) {
  return (dataLayer.actionsByNode[srcId] || [])
    .filter(action => action.targetId !== currentTargetId)
    .slice(0, 4);
}

function buildHopModels(pathEntry) {
  const path = pathEntry.path;
  return (path.edges || []).map((edgeKind, idx) => {
    const src = nodeById[path.nodes[idx]];
    const tgt = nodeById[path.nodes[idx + 1]];
    const evidence = getHopEvidence(src?.id, tgt?.id);
    const alternatives = getHopAlternatives(src?.id, tgt?.id);
    const mitreIds = [...new Set(evidence.flatMap(f => f.mitre_ids || []))];
    return {
      idx,
      src,
      tgt,
      edgeKind,
      tier: EDGE_TIER[edgeKind] || 2,
      weight: EDGE_WEIGHT[edgeKind] || 5,
      whyItWorks: summarizeWhyItWorks(src, tgt, edgeKind),
      evidence,
      alternatives,
      mitreIds,
      info: ATTACK_CMD[edgeKind] ? ATTACK_CMD[edgeKind](src || {}, tgt || {}) : null,
    };
  });
}

function renderPhaseStrip(pathEntry) {
  const phases = classifyPathPhases(pathEntry.path);
  const defs = [
    { key: 'initialAccess', label: 'Foothold', data: phases.initialAccess },
    { key: 'credTheft', label: 'Credential Access', data: phases.credTheft },
    { key: 'privEsc', label: 'Privilege Escalation', data: phases.privEsc },
    { key: 'lateralMovement', label: 'Lateral Movement', data: phases.lateralMovement },
    { key: 'impact', label: 'Impact', data: phases.impact },
  ];
  return defs.map(def => {
    const node = nodeById[def.data.nodeId];
    return `
      <div class="phase-step${def.data.present ? ' active' : ''}">
        <div class="phase-step-label">${escHtml(def.label)}</div>
        <div class="phase-step-node">${node ? escHtml((node.name || node.id).split(':').pop()) : 'Not present'}</div>
        <div class="phase-step-meta">${def.data.edgeKind ? escHtml(def.data.edgeKind) : (def.data.present ? 'Present in path' : 'No dedicated step')}</div>
      </div>
    `;
  }).join('');
}

function buildScopedSubgraph(nodeIds, focusId) {
  const focus = new Set(nodeIds.filter(Boolean));
  const queue = [...focus];
  const visited = new Set(focus);
  const overflow = [];

  while (queue.length && visited.size < 40) {
    const cur = queue.shift();
    const neighbors = [
      ...(dataLayer.adjacency.out[cur] || []),
      ...(dataLayer.adjacency.in[cur] || []),
    ];
    for (const entry of neighbors) {
      const otherId = entry.from === cur ? entry.to : entry.from;
      if (visited.has(otherId)) continue;
      if (visited.size < 40) {
        visited.add(otherId);
        queue.push(otherId);
      } else {
        overflow.push(otherId);
      }
    }
  }

  if (focusId && !visited.has(focusId)) visited.add(focusId);
  return {
    nodeIds: [...visited],
    overflowCount: Math.max(0, [...new Set(overflow)].length),
  };
}

function renderSubgraphCard(containerEl, nodeIds, focusId, onNodeClick) {
  if (!containerEl) return;
  if (subgraphSimulation) {
    subgraphSimulation.stop();
    subgraphSimulation = null;
  }

  const scoped = buildScopedSubgraph(nodeIds, focusId);
  const scopedNodes = scoped.nodeIds.map(id => ({ ...nodeById[id] })).filter(Boolean);
  const nodeSet = new Set(scopedNodes.map(n => n.id));
  const scopedEdges = (graphData?.edges || [])
    .filter(edge => {
      const from = edgeNodeId(edge.source || edge.from);
      const to = edgeNodeId(edge.target || edge.to);
      return nodeSet.has(from) && nodeSet.has(to);
    })
    .slice(0, 80)
    .map(edge => ({
      ...edge,
      source: edgeNodeId(edge.source || edge.from),
      target: edgeNodeId(edge.target || edge.to),
    }));

  containerEl.innerHTML = `
    <div class="subgraph-svg-wrap"></div>
    <div class="subgraph-overflow">${scoped.overflowCount > 0 ? `<span class="mini-chip">+${scoped.overflowCount} more hidden</span>` : ''}</div>
  `;

  const wrap = containerEl.querySelector('.subgraph-svg-wrap');
  if (!scopedNodes.length || !scopedEdges.length) {
    wrap.innerHTML = '<div class="subgraph-empty">No local subgraph available for this hop.</div>';
    return;
  }

  const width = wrap.clientWidth || 320;
  const height = wrap.clientHeight || 230;
  const svg = d3.select(wrap).append('svg').attr('width', width).attr('height', height);
  const nodes = scopedNodes.map(node => ({ ...node }));
  const links = scopedEdges.map(edge => ({ ...edge }));
  const nodeIndex = Object.fromEntries(nodes.map((node, idx) => [node.id, idx]));
  links.forEach(link => {
    link.source = nodeIndex[link.source];
    link.target = nodeIndex[link.target];
  });

  svg.append('rect').attr('width', width).attr('height', height).attr('fill', 'transparent');
  const linkSel = svg.append('g').selectAll('line')
    .data(links)
    .join('line')
    .attr('stroke', edgeColor)
    .attr('stroke-opacity', 0.55)
    .attr('stroke-width', d => (EDGE_TIER[d.kind] || 2) === 1 ? 2.2 : 1.4);

  const nodeSelLocal = svg.append('g').selectAll('g')
    .data(nodes)
    .join('g')
    .style('cursor', 'pointer')
    .on('click', (_, d) => onNodeClick?.(d.id));

  nodeSelLocal.append('circle')
    .attr('r', d => d.id === focusId ? 18 : 14)
    .attr('fill', d => nodeColor(d))
    .attr('fill-opacity', 0.88)
    .attr('stroke', d => d.id === focusId ? '#fff' : 'rgba(255,255,255,.16)')
    .attr('stroke-width', d => d.id === focusId ? 2.6 : 1.4);

  nodeSelLocal.append('text')
    .attr('text-anchor', 'middle')
    .attr('dominant-baseline', 'middle')
    .attr('font-size', '9px')
    .attr('fill', '#fff')
    .text(d => NODE_ICONS[d.kind] || '?');

  nodeSelLocal.append('text')
    .attr('class', 'subgraph-node-label')
    .attr('text-anchor', 'middle')
    .attr('dy', 24)
    .text(d => {
      const label = (d.name || d.id || '').split(':').pop();
      return label.length > 14 ? `${label.slice(0, 12)}…` : label;
    });

  subgraphSimulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id((_, i) => i).distance(62).strength(0.45))
    .force('charge', d3.forceManyBody().strength(-210))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collide', d3.forceCollide().radius(d => (d.id === focusId ? 28 : 24)))
    .stop();

  for (let i = 0; i < 90; i++) subgraphSimulation.tick();

  linkSel
    .attr('x1', d => nodes[d.source.index ?? d.source].x)
    .attr('y1', d => nodes[d.source.index ?? d.source].y)
    .attr('x2', d => nodes[d.target.index ?? d.target].x)
    .attr('y2', d => nodes[d.target.index ?? d.target].y);

  nodeSelLocal.attr('transform', d => `translate(${d.x},${d.y})`);
  subgraphSimulation.stop();
  subgraphSimulation = null;
}

function renderPathView() {
  const routeEl = document.getElementById('path-route');
  if (!routeEl) return;
  if (!graphData) {
    routeEl.innerHTML = '';
    return;
  }

  const pathEntry = dataLayer.pathsById[currentRoute?.params?.id];
  if (!pathEntry) {
    routeEl.innerHTML = `
      <div id="path-view">
        <div class="brief-card brief-empty-card">
          <div class="brief-empty-icon">🧭</div>
          <div class="brief-empty-title">Path not found</div>
          <div class="brief-empty-sub">The requested path ID is missing from the current report. Return to Briefing and select a path again.</div>
          <div class="brief-actions"><button class="brief-btn primary" id="path-missing-back">Back to Briefing</button></div>
        </div>
      </div>
    `;
    routeEl.querySelector('#path-missing-back')?.addEventListener('click', () => route('/briefing'));
    return;
  }

  const pathState = getPathRouteState();
  const hopModels = buildHopModels(pathEntry);
  const selectedHop = hopModels[Math.min(pathState.hop, Math.max(hopModels.length - 1, 0))] || hopModels[0];
  const focusId = pathState.focus || selectedHop?.src?.id || selectedHop?.tgt?.id || '';
  const impact = pathEntry.impact;
  const phasesHtml = renderPhaseStrip(pathEntry);
  const pathWeight = (pathEntry.path.edges || []).reduce((sum, kind) => sum + (EDGE_WEIGHT[kind] || 5), 0);

  routeEl.innerHTML = `
    <div id="path-view">
      <div class="path-back-row">
        <button class="brief-btn" id="path-back-btn">Back to Briefing</button>
        <button class="brief-btn primary" id="path-explore-btn">Open in Explore</button>
      </div>
      <div class="phase-strip">${phasesHtml}</div>
      <div class="path-layout">
        <div class="path-main">
          <div class="brief-card" style="display:flex;flex-direction:column;min-height:0;flex:1;">
            <div class="path-toolbar">
              <div>
                <div class="path-toolbar-title">${escHtml(pathEntry.narrative)}</div>
                <div class="path-toolbar-sub">${escHtml(impact.label)} · ${pathEntry.hopCount} hops · ${pathEntry.severity} severity · total weight ${pathWeight.toFixed(1)}</div>
              </div>
              <div class="path-toolbar-actions">
                <span class="sev-badge ${pathEntry.severity}">${pathEntry.severity}</span>
                <span class="mini-chip"><strong>Target</strong> ${escHtml(pathEntry.target?.kind || '?')}</span>
                <span class="mini-chip"><strong>MITRE</strong> ${pathEntry.mitreIds.length || 0}</span>
              </div>
            </div>
            <div class="path-scroll">
              <div id="path-storyboard" class="path-storyboard"></div>
            </div>
          </div>
        </div>
        <div class="path-rail">
          <div class="path-rail-card">
            <div class="subgraph-card-head">
              <div class="path-rail-title" style="margin:0">Inline Subgraph</div>
              <span class="mini-chip"><strong>Focus</strong> ${escHtml((nodeById[focusId]?.name || focusId || '').split(':').pop())}</span>
            </div>
            <div class="path-rail-body">
              <div id="path-subgraph-card"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  routeEl.querySelector('#path-back-btn')?.addEventListener('click', () => route('/briefing'));
  routeEl.querySelector('#path-explore-btn')?.addEventListener('click', () => route(`/explore?scope=${encodeURIComponent(`path:${pathEntry.id}`)}&path=${encodeURIComponent(pathEntry.id)}`));

  const storyboard = routeEl.querySelector('#path-storyboard');
  if (storyboard) {
    storyboard.innerHTML = hopModels.map(hop => {
      const actionInfo = hop.info || { action: hop.edgeKind, cmds: [`# ${hop.edgeKind}`] };
      return `
        <div class="hop-card${selectedHop?.idx === hop.idx ? ' active' : ''}" data-hop-idx="${hop.idx}" data-focus-id="${escHtml(hop.src?.id || hop.tgt?.id || '')}">
          <div class="hop-head">
            <div class="hop-head-top">
              <div class="hop-title">
                <span class="mini-chip" style="border-color:${NODE_COLORS[hop.src?.kind] || DEFAULT_NODE_COLOR}55;color:${NODE_COLORS[hop.src?.kind] || DEFAULT_NODE_COLOR}">${escHtml(NODE_ICONS[hop.src?.kind] || '•')} ${escHtml(hop.src?.kind || '?')}</span>
                <span>${escHtml(hop.src?.name || hop.src?.id || '?')}</span>
                <span class="mini-chip" style="border-color:${EDGE_COLORS[hop.edgeKind] || DEFAULT_EDGE_COLOR}55;color:${EDGE_COLORS[hop.edgeKind] || DEFAULT_EDGE_COLOR}">${escHtml(hop.edgeKind)}</span>
                <span class="mini-chip" style="border-color:${NODE_COLORS[hop.tgt?.kind] || DEFAULT_NODE_COLOR}55;color:${NODE_COLORS[hop.tgt?.kind] || DEFAULT_NODE_COLOR}">${escHtml(NODE_ICONS[hop.tgt?.kind] || '•')} ${escHtml(hop.tgt?.kind || '?')}</span>
                <span>${escHtml(hop.tgt?.name || hop.tgt?.id || '?')}</span>
              </div>
              <div class="hop-inline-row">
                <span class="mini-chip"><strong>Weight</strong> ${hop.weight.toFixed(1)}</span>
                <span class="mini-chip"><strong>Tier</strong> ${hop.tier}</span>
              </div>
            </div>
          </div>
          <div class="hop-body">
            <div class="hop-primary-stack">
              <div class="hop-section">
                <div class="hop-section-title">Why It Works</div>
                <div style="font-size:12px;color:var(--text);line-height:1.65;">${escHtml(hop.whyItWorks)}</div>
              </div>
              <div class="hop-section hop-copy-wrap">
                <div class="hop-section-title">Attack Command</div>
                <button class="hop-copy-btn" data-copy-cmd="${encodeURIComponent(actionInfo.cmds.join('\n'))}">Copy</button>
                <div class="modal-cmd" style="margin:0;padding-right:54px;">${escHtml(actionInfo.cmds.join('\n'))}</div>
              </div>
            </div>
            <details class="hop-extra-details">
              <summary>
                <span>Supporting Detail</span>
                <span class="hop-extra-summary">
                  <span class="mini-chip"><strong>Evidence</strong> ${hop.evidence.length}</span>
                  <span class="mini-chip"><strong>Alternatives</strong> ${hop.alternatives.length}</span>
                  <span class="mini-chip"><strong>MITRE</strong> ${hop.mitreIds.length}</span>
                </span>
              </summary>
              <div class="hop-extra-body">
                <div class="hop-section">
                  <div class="hop-section-title">Evidence</div>
                  <div class="hop-evidence-list">
                    ${hop.evidence.length ? hop.evidence.map(f => `
                      <div class="hop-evidence-item">
                        <strong>${escHtml(f.severity || '?')} · ${escHtml(f.title || f.rule_id || 'Finding')}</strong><br>
                        ${escHtml((f.description || '').slice(0, 180))}
                      </div>
                    `).join('') : '<div class="hop-evidence-item">No directly overlapping findings for this hop.</div>'}
                  </div>
                </div>
                <div class="hop-section">
                  <div class="hop-section-title">Alternative Pivots</div>
                  <details class="hop-alt-toggle">
                    <summary style="cursor:pointer;color:var(--accent);font-size:11px;">${hop.alternatives.length} other moves from ${escHtml(hop.src?.name || '?')}</summary>
                    <div class="hop-alt-list" style="margin-top:10px;">
                      ${hop.alternatives.length ? hop.alternatives.map(alt => `
                        <div class="hop-alt-item">
                          <strong>${escHtml(alt.edgeKind)}</strong> → ${escHtml(alt.target?.kind || '?')} ${escHtml(alt.target?.name || alt.targetId)}
                          <div style="margin-top:6px;"><button class="brief-inline-btn" data-alt-path="${alt.pathId}">Focus this path</button></div>
                        </div>
                      `).join('') : '<div class="hop-alt-item">No alternative pivots cached for this actor.</div>'}
                    </div>
                  </details>
                </div>
                <div class="hop-section">
                  <div class="hop-section-title">MITRE / Tags</div>
                  <div class="hop-inline-row">
                    <span class="mini-chip"><strong>Edge</strong> ${escHtml(hop.edgeKind)}</span>
                    ${(hop.mitreIds.length ? hop.mitreIds : ['No MITRE tags']).map(id => `<span class="mitre-chip">${escHtml(id)}</span>`).join('')}
                  </div>
                </div>
              </div>
            </details>
          </div>
        </div>
      `;
    }).join('');

    storyboard.querySelectorAll('[data-hop-idx]').forEach(card => {
      card.addEventListener('click', e => {
        if (e.target.closest('[data-copy-cmd]') || e.target.closest('[data-alt-path]') || e.target.closest('summary')) return;
        updateRouteQuery({ hop: card.dataset.hopIdx, focus: card.dataset.focusId || '' }, currentRoute.path);
      });
    });
    storyboard.querySelectorAll('[data-copy-cmd]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        navigator.clipboard.writeText(decodeURIComponent(btn.dataset.copyCmd));
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1200);
      });
    });
    storyboard.querySelectorAll('[data-alt-path]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        route(`/path/${encodeURIComponent(btn.dataset.altPath)}`);
      });
    });
  }

  renderSubgraphCard(routeEl.querySelector('#path-subgraph-card'), [selectedHop?.src?.id, selectedHop?.tgt?.id], focusId, nodeId => {
    updateRouteQuery({ focus: nodeId }, currentRoute.path);
  });
}

const FULL_GRAPH_WARNING_THRESHOLD = 500;

function useFullGraphData() {
  if (dataLayer.fullGraph) graphData = dataLayer.fullGraph;
}

function getExploreRouteState() {
  const query = getCurrentRouteQuery();
  return {
    scope: query.scope || '',
    confirm: query.confirm === '1',
    pathId: query.path || '',
  };
}

function isPathFocusedExploreMode() {
  const state = getExploreRouteState();
  return currentRoute?.name === 'explore' && state.scope.startsWith('path:') && !!state.pathId;
}

function getScopedExplorePathIndex() {
  if (!isPathFocusedExploreMode()) return -1;
  const entry = dataLayer.pathsById[currentRoute?.query?.path];
  if (!entry) return -1;
  const pathSig = entry.path.nodes.join('→');
  return computedPaths.findIndex(path => path.nodes.join('→') === pathSig);
}

function updateExploreScopedChrome() {
  const pathFocused = isPathFocusedExploreMode();
  const state = getExploreRouteState();
  const fullGraph = currentRoute?.name === 'explore' && state.scope === 'full';
  document.body.dataset.exploreMode = pathFocused ? 'path-focus' : (fullGraph ? 'full-graph' : '');
  if (!pathFocused) return;
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tab === 'paths'));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.toggle('active', panel.id === 'tab-paths'));
}

function buildScopedGraph(nodeIds) {
  const set = new Set(nodeIds.filter(Boolean));
  const nodes = dataLayer.nodes.filter(node => set.has(node.id)).map(node => ({ ...node }));
  const edges = dataLayer.edges
    .filter(edge => {
      const from = edgeNodeId(edge.source || edge.from);
      const to = edgeNodeId(edge.target || edge.to);
      return set.has(from) && set.has(to);
    })
    .map(edge => ({ ...edge }));
  const findings = (dataLayer.findings || []).filter(finding =>
    (finding.affected_nodes || []).some(nodeId => set.has(nodeId)) || finding.id === dataLayer.pathsById[getExploreRouteState().pathId]?.path?._findingId
  );
  return { nodes, edges, findings };
}

function buildPathNeighborhoodGraph(pathId) {
  const entry = dataLayer.pathsById[pathId];
  if (!entry) return null;
  const visited = new Set(entry.path.nodes);
  let frontier = new Set(entry.path.nodes);

  for (let depth = 0; depth < 2; depth++) {
    const next = new Set();
    frontier.forEach(nodeId => {
      const steps = [
        ...(dataLayer.adjacency.out[nodeId] || []),
        ...(dataLayer.adjacency.in[nodeId] || []),
      ];
      steps.forEach(step => {
        const neighborId = step.from === nodeId ? step.to : step.from;
        if (!visited.has(neighborId)) {
          visited.add(neighborId);
          next.add(neighborId);
        }
      });
    });
    frontier = next;
  }

  return buildScopedGraph([...visited]);
}

function buildNamespaceGraph(namespace) {
  const baseIds = new Set(
    dataLayer.nodes.filter(node => node.namespace === namespace).map(node => node.id)
  );
  const expanded = new Set(baseIds);
  dataLayer.edges.forEach(edge => {
    const from = edgeNodeId(edge.source || edge.from);
    const to = edgeNodeId(edge.target || edge.to);
    const fromNode = nodeById[from];
    const toNode = nodeById[to];
    if (baseIds.has(from) || baseIds.has(to)) {
      if (!fromNode?.namespace || fromNode.namespace === namespace) expanded.add(from);
      if (!toNode?.namespace || toNode.namespace === namespace) expanded.add(to);
    }
  });
  return buildScopedGraph([...expanded]);
}

function renderExploreGate(title, subtitle, contentHtml, actionsHtml = '') {
  const gate = document.getElementById('explore-gate');
  const toolbar = document.getElementById('toolbar');
  const main = document.getElementById('main');
  if (!gate || !toolbar || !main) return;
  gate.classList.add('visible');
  toolbar.style.display = 'none';
  main.style.display = 'none';
  gate.innerHTML = `
    <div class="explore-gate-card">
      <div class="explore-gate-title">${escHtml(title)}</div>
      <div class="explore-gate-sub">${escHtml(subtitle)}</div>
      ${contentHtml}
      ${actionsHtml ? `<div class="explore-gate-actions">${actionsHtml}</div>` : ''}
    </div>
  `;
}

function hideExploreGate() {
  const gate = document.getElementById('explore-gate');
  const toolbar = document.getElementById('toolbar');
  const main = document.getElementById('main');
  if (!gate || !toolbar || !main) return;
  gate.classList.remove('visible');
  gate.innerHTML = '';
  toolbar.style.display = '';
  main.style.display = '';
}

function updateExploreToolbar() {
  if (!exploreScopeBtn || !exploreFullToggleBtn || !crossnsBtn || !focusBtn || !briefingBtn) return;
  const inExplore = currentRoute?.name === 'explore' && !!graphData;
  const scope = getExploreRouteState().scope || '';
  const isFullGraph = inExplore && scope === 'full';

  briefingBtn.style.display = inExplore ? '' : 'none';
  exploreScopeBtn.style.display = inExplore && !isFullGraph ? '' : 'none';
  exploreFullToggleBtn.style.display = inExplore && !isFullGraph ? '' : 'none';
  crossnsBtn.style.display = inExplore && !isFullGraph ? '' : 'none';
  focusBtn.style.display = inExplore && !isFullGraph ? '' : 'none';
  if (!inExplore) return;

  if (scope.startsWith('ns:')) {
    exploreScopeBtn.textContent = `🧭 ${scope.slice(3)}`;
  } else if (scope.startsWith('path:')) {
    exploreScopeBtn.textContent = '🧭 Path Scope';
  } else if (scope === 'full') {
    exploreScopeBtn.textContent = '🧭 Full Scope';
  } else {
    exploreScopeBtn.textContent = '🧭 Scope';
  }
  exploreFullToggleBtn.textContent = dataLayer.nodes.length > FULL_GRAPH_WARNING_THRESHOLD ? '⚠ Full Graph' : '⬡ Full Graph';
}

function destroyExplore() {
  if (simulation) {
    simulation.stop();
    simulation = null;
  }
  if (zoomBehavior) {
    svg.on('.zoom', null);
    zoomBehavior = null;
  }
  clearPathHighlight();
  clearSelection();
  hideExploreGate();
  hullLayer.selectAll('*').remove();
  linksLayer.selectAll('*').remove();
  nodesLayer.selectAll('*').remove();
  d3.select('#minimap-svg').selectAll('circle.mm-node').remove();
  d3.select('#minimap-vp').attr('x', 0).attr('y', 0).attr('width', 0).attr('height', 0);
  nodePosMap = {};
  linkSel = null;
  nodeSel = null;
  document.body.dataset.exploreMode = '';
}

function renderExploreScopePicker() {
  hideLoading();
  const state = getExploreRouteState();
  const hasPathReturn = !!state.pathId && !!dataLayer.pathsById[state.pathId];
  const namespaces = [...new Set(dataLayer.nodes.map(node => node.namespace).filter(Boolean))].sort();
  updateExploreToolbar();
  renderExploreGate(
    'Choose Explore Scope',
    'Explore is now opt-in. Start with a namespace-scoped graph, or explicitly load the full cluster graph if you need the entire topology.',
    `<div class="explore-gate-grid">
      ${namespaces.map(ns => {
        const nodeCount = dataLayer.nodes.filter(node => node.namespace === ns).length;
        return `<button class="explore-ns-btn" data-explore-ns="${escHtml(ns)}"><span class="label">${escHtml(ns)}</span><span class="meta">${nodeCount} namespaced nodes</span></button>`;
      }).join('')}
    </div>`,
    `
      ${hasPathReturn ? '<button class="brief-btn" id="explore-back-path">Back to Path Graph</button>' : ''}
      <button class="brief-btn" id="explore-back-briefing">Back to Briefing</button>
      <button class="brief-btn primary" id="explore-full-btn">Load full cluster graph${dataLayer.nodes.length > FULL_GRAPH_WARNING_THRESHOLD ? ' (warning)' : ''}</button>
    `
  );

  document.querySelectorAll('[data-explore-ns]').forEach(btn => {
    btn.addEventListener('click', () => updateRouteQuery({ scope: `ns:${btn.dataset.exploreNs}`, confirm: '' }, '/explore'));
  });
  document.getElementById('explore-back-path')?.addEventListener('click', () => {
    updateRouteQuery({ scope: `path:${state.pathId}`, path: state.pathId, confirm: '' }, '/explore');
  });
  document.getElementById('explore-back-briefing')?.addEventListener('click', () => route('/briefing'));
  document.getElementById('explore-full-btn')?.addEventListener('click', () => updateRouteQuery({ scope: 'full', confirm: '' }, '/explore'));
}

function renderFullGraphWarning() {
  hideLoading();
  const state = getExploreRouteState();
  updateExploreToolbar();
  renderExploreGate(
    'Full Cluster Graph Warning',
    `This report contains ${dataLayer.nodes.length} nodes. Loading the full graph can be noisy and slower than a scoped Explore session.`,
    '<div class="brief-list-empty" style="padding:0;text-align:left;">Use namespace scope for day-to-day work, or continue if you explicitly need the full cluster topology.</div>',
    `
      <button class="brief-btn" id="explore-warning-back">Choose namespace instead</button>
      <button class="brief-btn primary" id="explore-warning-continue">Load full graph</button>
    `
  );
  document.getElementById('explore-warning-back')?.addEventListener('click', () => updateRouteQuery({ scope: '', confirm: '' }, '/explore'));
  document.getElementById('explore-warning-continue')?.addEventListener('click', () => updateRouteQuery({ confirm: '1' }, '/explore'));
}

function applyExploreRouteState() {
  if (!graphData || currentRoute?.name !== 'explore') return;
  const pathId = currentRoute?.query?.path;
  if (!pathId || !dataLayer.pathsById[pathId]) return;
  const entry = dataLayer.pathsById[pathId];
  activePathIdx = null;
  const pathSig = entry.path.nodes.join('→');
  const scopedIdx = computedPaths.findIndex(path => path.nodes.join('→') === pathSig);
  if (scopedIdx >= 0) {
    activePathIdx = scopedIdx;
    clearSelection();
    highlightPath(computedPaths[scopedIdx]);
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
    const card = document.querySelector(`.path-card[data-path-idx="${scopedIdx}"]`);
    if (card) card.classList.add('active');
  }
}

function ensureExploreGraph() {
  if (!dataLayer.fullGraph) {
    hideLoading();
    return;
  }
  if (subgraphSimulation) {
    subgraphSimulation.stop();
    subgraphSimulation = null;
  }

  const state = getExploreRouteState();
  if (!state.scope) {
    renderExploreScopePicker();
    return;
  }

  if (state.scope === 'full' && dataLayer.nodes.length > FULL_GRAPH_WARNING_THRESHOLD && !state.confirm) {
    renderFullGraphWarning();
    return;
  }

  let scopedGraph = null;
  if (state.scope.startsWith('path:')) {
    const pathId = state.scope.slice(5);
    scopedGraph = buildPathNeighborhoodGraph(pathId);
  } else if (state.scope.startsWith('ns:')) {
    scopedGraph = buildNamespaceGraph(state.scope.slice(3));
  } else if (state.scope === 'full') {
    scopedGraph = buildScopedGraph(dataLayer.nodes.map(node => node.id));
  }

  if (!scopedGraph || !scopedGraph.nodes.length) {
    renderExploreScopePicker();
    return;
  }

  hideExploreGate();
  graphData = scopedGraph;
  goalNodeSet = buildGoalNodeSetFromFindings(scopedGraph.findings);
  updateExploreScopedChrome();
  renderSidebar();
  computeAttackPaths();
  importFindingPaths();
  renderGraph();
  applyRbacVisibility();
  renderAttackPaths();
  updateStats();
  updateExploreToolbar();
  applyExploreRouteState();
}

function renderCurrentRoute() {
  renderFootholdHeader();
  if (currentRoute?.name === 'explore') {
    parkIdentityAnalyzer();
    ensureExploreGraph();
    return;
  }
  parkIdentityAnalyzer();
  destroyExplore();
  if (subgraphSimulation) {
    subgraphSimulation.stop();
    subgraphSimulation = null;
  }
  useFullGraphData();
  updateExploreToolbar();
  if (currentRoute?.name === 'path') {
    renderPathView();
    return;
  }
  renderBriefing();
}

onRouteChange(renderCurrentRoute);
renderCurrentRoute();
