// state.js
// Global application state, routing, data layer creation, foothold extraction

/* ================================================================
   STATE
   ================================================================ */
let graphData      = null;   // { nodes, edges, findings }
let rawGraphData   = null;   // before filtering (for large files)
let simulation     = null;
let nodeById       = {};
let zoomBehavior   = null;
// SA usage index: populated from runs_as edges after data load.
// saWithWorkload — SA IDs that have at least one pod/workload running as them.
// saWithPrivilegedWorkload — SA IDs used by a privileged/host-namespace workload.
let saWithWorkload           = new Set();
let saWithPrivilegedWorkload = new Set();
let currentTransform = d3.zoomIdentity;
window._findings   = {};
let activeFilters  = new Set(['CRITICAL','HIGH','MEDIUM','LOW']);
let selectedNodeId = null;
let activeFindingId = null;
let activePathIdx   = null;
let computedPaths   = [];
let showClusters    = true;
let showCrossNS     = false;
let showRbac        = true;  // RBAC node visibility toggle
let playbackTimer   = null; // attack playback timer
let blueTeamMode    = false; // blue team detection mode
let nodePosMap      = {}; // id -> {x,y} for minimap
let dataLayer       = createEmptyDataLayer();
let currentRoute    = null;
const routeListeners = new Set();
let dataVersion = 0;
let subgraphSimulation = null;
const svg        = d3.select('#graph');
const svgDefs    = svg.select('#svg-defs');
const zoomLayer  = svg.select('#zoom-layer');
const hullLayer  = svg.select('#hull-layer');
const linksLayer = svg.select('#links-layer');
const nodesLayer = svg.select('#nodes-layer');
let linkSel      = null;
let nodeSel      = null;

function createEmptyDataLayer() {
  return {
    nodes: [],
    edges: [],
    findings: [],
    nodeById: {},
    adjacency: { out: {}, in: {}, attackOut: {}, attackIn: {} },
    findingsByNode: {},
    pathsById: {},
    pathsByImpact: {},
    pathRows: [],
    actionsByNode: {},
    saUsage: { withWorkload: new Set(), withPrivilegedWorkload: new Set() },
    foothold: null,
    fullGraph: null,
  };
}

function createAdjacencyBuckets(nodes) {
  const buckets = {};
  nodes.forEach(n => { buckets[n.id] = []; });
  return buckets;
}

function parseServiceAccountRef(username) {
  const m = String(username || '').match(/^system:serviceaccount:([^:]+):([^:]+)$/);
  return m ? { namespace: m[1], name: m[2] } : null;
}

function extractFoothold(raw, graph, byId) {
  const identity = raw?.identity || {};
  const saRef = {
    namespace: identity.namespace || parseServiceAccountRef(identity.username)?.namespace || '',
    name: identity.sa_name || parseServiceAccountRef(identity.username)?.name || '',
  };

  const saNode = graph.nodes.find(n =>
    n.kind === 'ServiceAccount' &&
    n.name === saRef.name &&
    (n.namespace || '') === (saRef.namespace || '')
  ) || null;

  const workloadCandidates = graph.edges
    .filter(e => e.kind === 'runs_as' && edgeNodeId(e.target || e.to) === saNode?.id)
    .map(e => byId[edgeNodeId(e.source || e.from)])
    .filter(Boolean)
    .sort((a, b) => {
      const aPod = a.kind === 'Pod' ? 1 : 0;
      const bPod = b.kind === 'Pod' ? 1 : 0;
      if (aPod !== bPod) return bPod - aPod;
      const aRunning = a.metadata?.phase === 'Running' ? 1 : 0;
      const bRunning = b.metadata?.phase === 'Running' ? 1 : 0;
      if (aRunning !== bRunning) return bRunning - aRunning;
      return (b.risk_score || 0) - (a.risk_score || 0);
    });

  const primaryWorkload = workloadCandidates[0] || null;
  const podNode = workloadCandidates.find(n => n.kind === 'Pod') || null;
  const nodeName = podNode?.metadata?.node || primaryWorkload?.metadata?.node || '';
  const cloudEdge = graph.edges.find(e => {
    const sid = edgeNodeId(e.source || e.from);
    const tid = edgeNodeId(e.target || e.to);
    return sid === saNode?.id && byId[tid]?.kind === 'CloudIdentity';
  });
  const cloudIdentity = cloudEdge ? byId[edgeNodeId(cloudEdge.target || cloudEdge.to)] : null;
  const auditEntries = raw?.audit_footprint || [];
  const auditSkipped = auditEntries.filter(e => e.skipped).length;

  return {
    username: identity.username || '',
    identityId: byId[`identity:${identity.username || ''}`]?.id || '',
    namespace: saRef.namespace || '',
    serviceAccount: saNode?.name || saRef.name || '',
    serviceAccountId: saNode?.id || '',
    workloadId: primaryWorkload?.kind === 'Workload' ? primaryWorkload.id : '',
    workload: primaryWorkload?.kind === 'Workload' ? primaryWorkload.name : '',
    podId: podNode?.id || (primaryWorkload?.kind === 'Pod' ? primaryWorkload.id : ''),
    pod: podNode?.name || (primaryWorkload?.kind === 'Pod' ? primaryWorkload.name : ''),
    node: nodeName,
    cloudIdentity: cloudIdentity?.name || cloudIdentity?.id || '',
    stealth: !!raw?.meta?.stealth,
    auditSkipped,
    auditTotal: auditEntries.length,
  };
}

function renderFootholdHeader() {
  const header = document.getElementById('foothold-header');
  if (!header) return;

  const foothold = dataLayer.foothold;
  const routeName = currentRoute?.name || 'briefing';
  if (!foothold || !graphData || routeName === 'explore') {
    header.classList.remove('visible');
    header.innerHTML = '';
    return;
  }

  const chips = [
    foothold.pod        ? ['Pod', foothold.pod] : null,
    foothold.workload   ? ['Wkld', foothold.workload] : null,
    foothold.serviceAccount ? ['SA', foothold.serviceAccount] : null,
    foothold.namespace  ? ['NS', foothold.namespace] : null,
    foothold.node       ? ['Node', foothold.node] : null,
    foothold.cloudIdentity ? ['Cloud', foothold.cloudIdentity] : null,
  ].filter(Boolean);

  const chipsHtml = chips.map(([label, value]) =>
    `<span class="fh-chip" title="${escHtml(label)}: ${escHtml(value)}"><span class="fh-chip-label">${escHtml(label)}</span> ${escHtml(value)}</span>`
  ).join('');

  header.innerHTML = `
    <div class="fh-compact-row">
      <div class="fh-identity">
        <div class="fh-brand app-brand">
          <img class="app-brand-logo" src="img/k8scout_logo.png?v=1776347433" alt="k8scout logo">
          <span class="app-brand-wordmark">k8scout</span>
        </div>
        <span class="fh-sep fh-sep-inline"></span>
        <span class="fh-kicker">Foothold</span>
        <span class="fh-username" title="${escHtml(foothold.username || 'Current identity')}">${escHtml(foothold.username || 'Current identity')}</span>
        ${chipsHtml}
      </div>
      <div class="fh-toolbar">
        <button class="fh-action-btn" id="fh-scan-details">Scan</button>
        <button class="fh-action-btn" id="fh-open-json">JSON</button>
        <button class="fh-action-btn" id="fh-export-report"${rawGraphData ? '' : ' disabled'}>Export</button>
        <span class="fh-sep"></span>
        <button class="fh-action-btn${routeName === 'briefing' ? ' primary' : ''}" id="fh-briefing-btn"${routeName === 'briefing' ? ' disabled' : ''}>Briefing</button>
        <button class="fh-action-btn" id="fh-explore-btn">Explore</button>
      </div>
    </div>
  `;
  header.classList.add('visible');
  header.querySelector('#fh-scan-details')?.addEventListener('click', showScanDetailsModal);
  header.querySelector('#fh-open-json')?.addEventListener('click', () => fileInput.click());
  header.querySelector('#fh-export-report')?.addEventListener('click', exportReport);
  header.querySelector('#fh-briefing-btn')?.addEventListener('click', () => route('/briefing'));
  header.querySelector('#fh-explore-btn')?.addEventListener('click', () => route('/explore'));
}

function showScanDetailsModal() {
  if (!rawGraphData) return;
  const fp = rawGraphData.audit_footprint || [];
  const scanMode = rawGraphData?.meta?.stealth ? 'Stealth' : 'Standard';
  const skipped = fp.filter(entry => entry.skipped).length;
  const summaryHtml = `
    <div class="modal-section">
      <h4>Scan Mode</h4>
      <div style="color:var(--text);line-height:1.7;font-size:13px;">
        ${rawGraphData?.meta?.stealth
          ? 'Stealth mode was enabled. The scan avoided noisier SSRR/SSAR checks where possible.'
          : 'Standard mode was used. Full audit-relevant checks were not intentionally suppressed.'}
      </div>
    </div>
    <div class="modal-section">
      <h4>API Noise Summary</h4>
      <div style="color:var(--muted);line-height:1.7;font-size:12px;">
        ${fp.length
          ? `${skipped} of ${fp.length} audit-relevant checks were skipped.`
          : 'No audit footprint details were reported in this file.'}
      </div>
    </div>
  `;

  if (!fp.length) {
    openModal('Scan Details', summaryHtml);
    return;
  }

  const rows = fp.map(entry => `
    <tr>
      <td style="padding:4px 10px;color:#ccc">${escHtml(entry.action)}</td>
      <td style="padding:4px 10px;text-align:right;color:#aaa">${entry.count}</td>
      <td style="padding:4px 10px;color:${entry.skipped ? '#e74c3c' : '#2ecc71'}">${entry.skipped ? 'Skipped' : 'Called'}</td>
      <td style="padding:4px 10px;color:${entry.noise_level==='high' ? '#e74c3c' : entry.noise_level==='medium' ? '#f39c12' : '#2ecc71'}">${escHtml(entry.noise_level || 'unknown')}</td>
    </tr>
  `).join('');

  openModal(
    'Scan Details',
    `${summaryHtml}
    <div class="modal-section">
      <h4>Audit-Relevant Calls</h4>
      <table style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr style="color:#888;border-bottom:1px solid #333">
          <th style="text-align:left;padding:4px 10px">Action</th>
          <th style="text-align:right;padding:4px 10px">Count</th>
          <th style="text-align:left;padding:4px 10px">Status</th>
          <th style="text-align:left;padding:4px 10px">Noise</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`
  );
}

function parseRouteQuery(queryString) {
  const query = {};
  const params = new URLSearchParams(queryString || '');
  for (const [key, value] of params.entries()) query[key] = value;
  return query;
}

function parseHashRoute(hash) {
  const raw = (hash || '').replace(/^#/, '');
  const normalized = raw || '/briefing';
  const [pathname, queryString = ''] = normalized.split('?');
  if (pathname === '/briefing') {
    return { name: 'briefing', path: pathname, query: parseRouteQuery(queryString), params: {} };
  }
  const pathMatch = pathname.match(/^\/path\/([^/?]+)$/);
  if (pathMatch) {
    return { name: 'path', path: pathname, query: parseRouteQuery(queryString), params: { id: decodeURIComponent(pathMatch[1]) } };
  }
  if (pathname === '/explore' || pathname === '/legacy') {
    return { name: 'explore', path: '/explore', query: parseRouteQuery(queryString), params: {} };
  }
  return null;
}

function buildHash(path, query) {
  const params = new URLSearchParams();
  Object.entries(query || {}).forEach(([key, value]) => {
    if (value == null || value === '') return;
    params.set(key, value);
  });
  const qs = params.toString();
  return `#${path}${qs ? `?${qs}` : ''}`;
}

function applyRoute(routeInfo) {
  currentRoute = routeInfo;
  const briefingRoute = document.getElementById('briefing-route');
  const pathRoute = document.getElementById('path-route');
  const exploreRoute = document.getElementById('explore-route');
  if (briefingRoute) briefingRoute.classList.toggle('visible', routeInfo?.name === 'briefing');
  if (pathRoute) pathRoute.classList.toggle('visible', routeInfo?.name === 'path');
  if (exploreRoute) exploreRoute.style.display = routeInfo?.name === 'explore' ? 'flex' : 'none';
  document.body.dataset.route = routeInfo?.name || 'briefing';
  routeListeners.forEach(listener => listener(routeInfo));
}

function handleRouteChange() {
  const next = parseHashRoute(location.hash);
  if (!next) {
    if (location.hash !== '#/briefing') {
      location.hash = '/briefing';
      return;
    }
    applyRoute({ name: 'briefing', path: '/briefing', query: {}, params: {} });
    return;
  }
  applyRoute(next);
}

function route(path) {
  const target = path.startsWith('#') ? path : `#${path.startsWith('/') ? path : `/${path}`}`;
  if (location.hash === target) {
    handleRouteChange();
    return;
  }
  location.hash = target;
}

function onRouteChange(listener) {
  routeListeners.add(listener);
  return () => routeListeners.delete(listener);
}

function getCurrentRouteQuery() {
  return { ...(currentRoute?.query || {}) };
}

function updateRouteQuery(patch, pathOverride) {
  const nextPath = pathOverride || currentRoute?.path || '/briefing';
  const nextQuery = { ...(currentRoute?.query || {}) };
  Object.entries(patch || {}).forEach(([key, value]) => {
    if (value == null || value === '') delete nextQuery[key];
    else nextQuery[key] = value;
  });
  location.hash = buildHash(nextPath, nextQuery);
}
