// loading.js
// File loading, drag & drop, large file dialog, data ingestion

/* ================================================================
   FILE LOADING
   ================================================================ */
const dropOverlay  = document.getElementById('drop-overlay');
const appRoot      = document.getElementById('app');
const canvasWrap   = document.getElementById('canvas-wrap');
const fileInput    = document.getElementById('file-input');
const loadingOverlay = document.getElementById('loading-overlay');
const loadingText  = document.getElementById('loading-text');
const progressFill = document.getElementById('progress-fill');
const exploreScopeBtn = document.getElementById('explore-scope-btn');
const exploreFullToggleBtn = document.getElementById('explore-full-toggle-btn');

document.getElementById('open-file-btn').addEventListener('click', () => fileInput.click());
document.getElementById('drop-open-file-btn')?.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', e => { if (e.target.files[0]) handleFile(e.target.files[0]); });
window.addEventListener('hashchange', handleRouteChange);
handleRouteChange();
exploreScopeBtn?.addEventListener('click', () => route('/explore'));
exploreFullToggleBtn?.addEventListener('click', () => updateRouteQuery({ scope: 'full', confirm: '' }, '/explore'));

const RBAC_KINDS = new Set(['ClusterRole','Role','ClusterRoleBinding','RoleBinding']);
let activePathNodeIds = new Set(); // RBAC nodes to keep visible during path highlight
let focusMode = false;

const rbacBtn = document.getElementById('rbac-btn');
rbacBtn.classList.add('active');
rbacBtn.addEventListener('click', () => {
  showRbac = !showRbac;
  rbacBtn.classList.toggle('active', showRbac);
  applyRbacVisibility();
});

const focusBtn = document.getElementById('focus-btn');
focusBtn.addEventListener('click', () => {
  focusMode = !focusMode;
  focusBtn.classList.toggle('active', focusMode);
  applyFocusMode();
});

// applyRbacVisibility hides RBAC nodes UNLESS they are in the active attack path
function applyRbacVisibility() {
  if (!nodeSel || !linkSel) return;
  const hide = !showRbac;
  const hiddenIds = new Set();

  nodeSel.each(function(d) {
    const isRbac = RBAC_KINDS.has(d.kind);
    // Keep RBAC nodes visible if they're part of the active attack path
    const exempt = activePathNodeIds.has(d.id);
    const shouldHide = hide && isRbac && !exempt;
    d3.select(this).style('display', shouldHide ? 'none' : null);
    if (shouldHide) hiddenIds.add(d.id);
  });

  linkSel.style('display', d => {
    const sid = (typeof d.source === 'object' ? d.source : {}).id || d.source;
    const tid = (typeof d.target === 'object' ? d.target : {}).id || d.target;
    return (hiddenIds.has(sid) || hiddenIds.has(tid)) ? 'none' : null;
  });

  if (simulation) {
    nodeSel.each(function(d) {
      const isRbac = RBAC_KINDS.has(d.kind);
      const exempt = activePathNodeIds.has(d.id);
      if (hide && isRbac && !exempt) {
        d.fx = d.x; d.fy = d.y;
      } else if (!d._userPinned) {
        d.fx = null; d.fy = null;
      }
    });
    simulation.alpha(0.3).restart();
  }
}

// Focus mode: dim nodes/edges that aren't attack-relevant
// Attack-relevant = targets, actors with workloads, workloads, secrets, and their connecting edges
function applyFocusMode() {
  if (!nodeSel || !linkSel) return;

  if (!focusMode) {
    // Remove focus dimming
    nodeSel.classed('focus-dim', false);
    linkSel.classed('focus-dim', false);
    return;
  }

  // Nodes that matter: targets, actors, workloads, secrets, hooks, cloud identities
  // Nodes to dim: context category nodes, orphan RBAC with no attack edges
  const relevantNodes = new Set();
  const attackEdgeNodes = new Set(); // nodes that have at least one tier 1-2 edge

  linkSel.each(function(d) {
    const tier = EDGE_TIER[d.kind] || 3;
    if (tier <= 2) {
      const sid = (typeof d.source === 'object' ? d.source : {}).id || d.source;
      const tid = (typeof d.target === 'object' ? d.target : {}).id || d.target;
      attackEdgeNodes.add(sid);
      attackEdgeNodes.add(tid);
    }
  });

  nodeSel.each(function(d) {
    const cat = securityCategory(d);
    // Always show targets, workloads, secrets, actors, hooks, cloud identities
    if (cat === 'target' || cat === 'workload' || cat === 'secret' ||
        cat === 'actor' || cat === 'hook') {
      relevantNodes.add(d.id);
    }
    // Show RBAC/context nodes only if they have attack edges
    else if (attackEdgeNodes.has(d.id)) {
      relevantNodes.add(d.id);
    }
  });

  nodeSel.classed('focus-dim', d => !relevantNodes.has(d.id));

  linkSel.classed('focus-dim', d => {
    const sid = (typeof d.source === 'object' ? d.source : {}).id || d.source;
    const tid = (typeof d.target === 'object' ? d.target : {}).id || d.target;
    // Dim edges where BOTH endpoints are irrelevant, or tier 3 structural edges to irrelevant nodes
    const tier = EDGE_TIER[d.kind] || 3;
    if (tier === 3 && (!relevantNodes.has(sid) || !relevantNodes.has(tid))) return true;
    return !relevantNodes.has(sid) && !relevantNodes.has(tid);
  });
}

document.getElementById('export-btn')?.addEventListener('click', exportReport);

function exportReport() {
  if (!rawGraphData) { alert('Load a scan file first.'); return; }
  const findings = rawGraphData.findings || [];
  const graph    = rawGraphData.graph || rawGraphData;
  const identity = rawGraphData.identity || rawGraphData.enumeration?.identity || {};
  const scanTime = rawGraphData.scan_time || rawGraphData.enumeration?.scan_time || new Date().toISOString();

  const critFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const sevCounts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  findings.forEach(f => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

  function escHtmlReport(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  const rows = critFindings.map(f => `
    <tr>
      <td><span class="sev-${f.severity}">${f.severity}</span></td>
      <td>${f.score?.toFixed(1)||'?'}</td>
      <td><strong>${escHtmlReport(f.title||f.rule_id)}</strong><br><small>${escHtmlReport((f.description||'').slice(0,200))}</small></td>
      <td><small>${escHtmlReport(f.mitigation||'').replace(/\n/g,'<br>')}</small></td>
    </tr>`).join('');

  const svgEl = document.getElementById('graph');
  const svgBlob = svgEl ? `<div style="margin:24px 0;border:1px solid #ddd;border-radius:6px;overflow:hidden">${svgEl.outerHTML}</div>` : '';

  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>k8scout Security Report</title>
<style>
  body{font-family:system-ui,sans-serif;color:#1a1a2e;background:#fff;margin:0;padding:40px}
  h1{color:#e84c5a;font-size:28px;margin-bottom:4px}
  h2{color:#1a1a2e;font-size:18px;border-bottom:2px solid #e84c5a;padding-bottom:6px;margin-top:32px}
  table{border-collapse:collapse;width:100%;margin-top:12px}
  th{background:#1a1a2e;color:#fff;padding:8px 12px;text-align:left;font-size:13px}
  td{padding:8px 12px;border-bottom:1px solid #eee;vertical-align:top;font-size:12px}
  tr:nth-child(even){background:#f9f9f9}
  .sev-CRITICAL{background:#fee;color:#c00;padding:2px 8px;border-radius:4px;font-weight:700;font-size:11px}
  .sev-HIGH{background:#fff3e0;color:#e65c00;padding:2px 8px;border-radius:4px;font-weight:700;font-size:11px}
  .summary-box{display:flex;gap:16px;margin:16px 0}
  .sev-card{padding:16px 24px;border-radius:8px;text-align:center;border:1px solid}
  .sev-card.c{background:#fee;border-color:#c00;color:#c00}
  .sev-card.h{background:#fff3e0;border-color:#e65c00;color:#e65c00}
  .sev-card.m{background:#fffde0;border-color:#c8a000;color:#c8a000}
  .sev-card.l{background:#e8f5e9;border-color:#2e7d32;color:#2e7d32}
  .sev-card span{font-size:28px;font-weight:700;display:block}
  .sev-card small{font-size:11px}
  @media print{body{padding:20px}svg{max-width:100%;height:auto}}
</style></head><body>
<h1>k8scout Security Report</h1>
<p style="color:#666;font-size:13px">Identity: <strong>${escHtmlReport(identity.username||'N/A')}</strong> &nbsp;|&nbsp; Scan: <strong>${escHtmlReport(String(scanTime).slice(0,19))}</strong> &nbsp;|&nbsp; Nodes: <strong>${(graph.nodes||[]).length}</strong> &nbsp;|&nbsp; Findings: <strong>${findings.length}</strong></p>

<h2>Executive Summary</h2>
<div class="summary-box">
  <div class="sev-card c"><span>${sevCounts.CRITICAL}</span><small>CRITICAL</small></div>
  <div class="sev-card h"><span>${sevCounts.HIGH}</span><small>HIGH</small></div>
  <div class="sev-card m"><span>${sevCounts.MEDIUM}</span><small>MEDIUM</small></div>
  <div class="sev-card l"><span>${sevCounts.LOW}</span><small>LOW</small></div>
</div>

<h2>Critical &amp; High Findings</h2>
<table><thead><tr><th>Severity</th><th>Score</th><th>Finding</th><th>Mitigation</th></tr></thead>
<tbody>${rows}</tbody></table>

${svgBlob}

<p style="font-size:11px;color:#999;margin-top:40px;text-align:center">Generated by k8scout &mdash; ${new Date().toISOString()}</p>
</body></html>`;

  const blob = new Blob([html], {type: 'text/html'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'k8scout-report.html';
  a.click(); URL.revokeObjectURL(url);
}

async function generateMultiSAComparison(apiKey) {
  if (!apiKey) { alert('Enter an OpenAI API key first.'); return; }
  if (!rawGraphData) { alert('Load a scan file first.'); return; }
  const saNodes = graphData.nodes.filter(n => n.kind === 'ServiceAccount' && n.risk_score > 0);
  if (!saNodes.length) { alert('No ServiceAccount nodes found.'); return; }
  const top5 = saNodes.sort((a,b) => (b.risk_score||0) - (a.risk_score||0)).slice(0,5);
  const model = document.getElementById('god-ai-model').value || 'gpt-4o';

  setAIStatus('<span class="ai-spinner"></span>Thinking…', '#a29bfe', true);

  const saDescriptions = top5.map(sa => {
    const rules = typeof getSARules === 'function' ? getSARules(sa.id) : [];
    return `SA: ${sa.namespace||''}/${sa.name} (risk_score=${(sa.risk_score||0).toFixed(1)})\nRBAC Rules:\n${rules.slice(0,6).join('\n')||'(none found)'}`;
  }).join('\n\n---\n\n');

  const prompt = `You are a Kubernetes security expert.
Given these ${top5.length} service accounts and their RBAC permissions, rank them from most to least dangerous entry point for an attacker. For the top 2, explain the attack chain in 3 sentences each.

${saDescriptions}

Respond with valid JSON only:
{
  "ranked": [
    {"rank":1,"sa":"namespace/name","risk_score":0.0,"reason":"...","attack_chain":"..."}
  ],
  "summary": "..."
}`;

  try {
    const provider = getActiveProvider();
    const { endpoint, headers, body } = buildAIFetchOptions(apiKey, model, [{role:'user',content:prompt}]);
    body.temperature = 0.3; body.max_tokens = 1200;
    const resp = await fetch(endpoint, { method:'POST', headers, body: JSON.stringify(body) });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error?.message || resp.status);
    const raw = data.choices[0].message.content;
    const result = JSON.parse(raw.replace(/^```(?:json)?\s*/i,'').replace(/\s*```$/i,'').trim());
    renderMultiSABlock(result, model);
    setAIStatus('done','');
  } catch(err) {
    setAIStatus('error', 'Compare failed: ' + err.message);
  }
}

function renderMultiSABlock(result, model) {
  const body = document.getElementById('god-body');
  const block = document.createElement('div');
  block.className = 'god-ai-block expanded';
  const rankColors = ['#ff4757','#ff9f43','#ffd166','#74b9ff','#a9e34b'];
  const rows = (result.ranked||[]).map((item,i) => {
    const col = rankColors[i] || '#888';
    return `<div style="margin:6px 12px;padding:8px 10px;background:var(--surface2);border:1px solid ${col}30;border-left:3px solid ${col};border-radius:6px;font-size:11px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span style="font-size:16px;font-weight:900;color:${col}">#${item.rank}</span>
        <span style="color:var(--text);font-weight:600">${escHtml(item.sa||'')}</span>
        <span style="color:var(--muted);font-size:10px">score ${(item.risk_score||0).toFixed(1)}</span>
      </div>
      <div style="color:var(--muted)">${escHtml(item.reason||'')}</div>
      ${item.attack_chain ? `<div style="margin-top:5px;color:${col};font-style:italic;font-size:10px">${escHtml(item.attack_chain)}</div>` : ''}
    </div>`;
  }).join('');
  block.innerHTML = `
    <div class="god-ai-block-header" onclick="this.closest('.god-ai-block').classList.toggle('expanded')">
      <span class="god-ai-badge">🤖 AI · ${escHtml(model)}</span>
      <div class="god-ai-title">Multi-SA Risk Ranking (Top ${(result.ranked||[]).length})</div>
      <span class="god-chain-toggle">▾</span>
    </div>
    <div class="god-ai-block-body">
      ${result.summary ? `<div class="god-ai-summary">${escHtml(result.summary)}</div>` : ''}
      ${rows}
    </div>`;
  body.insertBefore(block, body.firstChild);
}

async function generateRemediation(fid) {
  const apiKey = document.getElementById('god-ai-key')?.value?.trim();
  if (!apiKey) { alert('Open Attack Chain Analyzer and enter an OpenAI API key first.'); return; }
  const f = window._findings?.[fid];
  if (!f) return;
  const outEl = document.getElementById('remediation-' + fid);
  if (!outEl) return;
  outEl.innerHTML = '<span style="color:var(--muted);font-size:11px">Generating fix...</span>';
  const model = document.getElementById('god-ai-model')?.value || 'gpt-4o';
  const prompt = `You are a Kubernetes RBAC security expert. Generate a minimal fix for this finding.

Finding: ${f.title}
Rule: ${f.rule_id}
Description: ${f.description}
Evidence: ${(f.evidence||[]).join('\n')}
Mitigation hint: ${f.mitigation||''}

Respond with valid JSON only:
{
  "kubectl_fix": "kubectl ...",
  "rbac_yaml": "apiVersion: rbac.authorization.k8s.io/v1\\n...",
  "side_effects": "What breaks if you apply this fix",
  "alternative": "Alternative approach if hard removal is not possible"
}`;
  try {
    const resp = await fetch('https://api.openai.com/v1/chat/completions', {
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+apiKey},
      body: JSON.stringify({model, messages:[{role:'user',content:prompt}], temperature:0.2, max_tokens:900, response_format:{type:'json_object'}})
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error?.message||resp.status);
    const fix = JSON.parse(data.choices[0].message.content);
    outEl.innerHTML = `
      <div style="margin-top:8px;padding:8px;background:var(--surface2);border-radius:6px;font-size:11px">
        ${fix.kubectl_fix ? `<div style="margin-bottom:6px"><div style="color:var(--muted);font-size:10px;margin-bottom:2px">kubectl command:</div><div class="modal-cmd">${escHtml(fix.kubectl_fix)}<button class="god-copy" onclick="navigator.clipboard.writeText(${JSON.stringify(fix.kubectl_fix)})">⧉</button></div></div>` : ''}
        ${fix.rbac_yaml ? `<div style="margin-bottom:6px"><div style="color:var(--muted);font-size:10px;margin-bottom:2px">RBAC YAML patch:</div><div class="modal-cmd" style="white-space:pre">${escHtml(fix.rbac_yaml)}<button class="god-copy" onclick="navigator.clipboard.writeText(${JSON.stringify(fix.rbac_yaml)})">⧉</button></div></div>` : ''}
        ${fix.side_effects ? `<div style="color:#ffd166;font-size:10px">⚠ Side effects: ${escHtml(fix.side_effects)}</div>` : ''}
        ${fix.alternative ? `<div style="color:var(--muted);font-size:10px;margin-top:4px">Alternative: ${escHtml(fix.alternative)}</div>` : ''}
      </div>`;
  } catch(err) {
    outEl.innerHTML = `<span style="color:var(--crit);font-size:11px">Error: ${escHtml(err.message)}</span>`;
  }
}

function revealDropOverlay(isDragging) {
  if (!dropOverlay) return;
  dropOverlay.classList.remove('hidden');
  dropOverlay.classList.toggle('drag-active', !!isDragging);
}

function restoreDropOverlay() {
  if (!dropOverlay) return;
  dropOverlay.classList.remove('drag-active');
  if (graphData) dropOverlay.classList.add('hidden');
}

appRoot?.addEventListener('dragenter', e => {
  e.preventDefault();
  revealDropOverlay(true);
});
appRoot?.addEventListener('dragover', e => {
  e.preventDefault();
  revealDropOverlay(true);
});
appRoot?.addEventListener('dragleave', e => {
  if (e.relatedTarget && appRoot.contains(e.relatedTarget)) return;
  restoreDropOverlay();
});
appRoot?.addEventListener('drop', e => {
  e.preventDefault();
  e.stopPropagation();
  restoreDropOverlay();
  if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});
document.body.addEventListener('dragover', e => e.preventDefault());
document.body.addEventListener('drop', e => {
  e.preventDefault();
  restoreDropOverlay();
  if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});

async function handleFile(file) {
  showLoading('Reading file…', 0);
  await nextFrame();

  let text;
  try { text = await file.text(); }
  catch(e) { hideLoading(); alert('Failed to read file: ' + e.message); return; }

  showLoading('Parsing JSON…', 10);
  await nextFrame();

  let raw;
  try { raw = JSON.parse(text); }
  catch(e) { hideLoading(); alert('Failed to parse JSON: ' + e.message); return; }

  const g = raw.graph || raw;
  const allNodes = (g.nodes || []);
  const allEdges = (g.edges || []);

  if (allNodes.length > 300) {
    hideLoading();
    await showLargeFileDialog(raw, allNodes, allEdges);
  } else {
    showLoading('Building graph…', 30);
    await nextFrame();
    try {
      ingestData(raw, allNodes, allEdges);
    } catch(e) {
      hideLoading();
      console.error('k8scout ingest failed', e);
      alert('Failed to build graph: ' + e.message);
    }
  }
}

/* ================================================================
   LARGE FILE DIALOG
   ================================================================ */
let largeFileResolve = null;

function showLargeFileDialog(raw, nodes, edges) {
  return new Promise(resolve => {
    largeFileResolve = resolve;
    const sub = document.getElementById('largefile-sub');
    sub.textContent = `${nodes.length} nodes · ${edges.length} edges. Filter to improve performance.`;

    // Collect namespaces
    const nsSet = new Set(nodes.filter(n => n.namespace).map(n => n.namespace));
    const nsChips = document.getElementById('ns-chips');
    nsChips.innerHTML = '';
    nsSet.forEach(ns => {
      const chip = document.createElement('div');
      chip.className = 'filter-chip on';
      chip.textContent = ns;
      chip.dataset.ns = ns;
      chip.addEventListener('click', () => { chip.classList.toggle('on'); updateLargeFilePreview(raw, nodes, edges); });
      nsChips.appendChild(chip);
    });

    // Collect kinds
    const kindSet = new Set(nodes.map(n => n.kind).filter(Boolean));
    const kindChips = document.getElementById('kind-chips');
    kindChips.innerHTML = '';
    kindSet.forEach(k => {
      const chip = document.createElement('div');
      chip.className = 'filter-chip on';
      chip.textContent = k;
      chip.dataset.kind = k;
      chip.addEventListener('click', () => { chip.classList.toggle('on'); updateLargeFilePreview(raw, nodes, edges); });
      kindChips.appendChild(chip);
    });

    const slider = document.getElementById('min-risk-slider');
    const label  = document.getElementById('min-risk-label');
    slider.value = 0;
    label.textContent = '0';
    slider.oninput = () => { label.textContent = slider.value; updateLargeFilePreview(raw, nodes, edges); };

    updateLargeFilePreview(raw, nodes, edges);

    document.getElementById('largefile-ok').onclick = () => {
      const filtered = applyLargeFileFilters(nodes, edges);
      document.getElementById('largefile-bg').classList.remove('visible');
      showLoading('Building graph…', 30);
      setTimeout(() => {
        try {
          ingestData(raw, filtered.nodes, filtered.edges);
        } catch(e) {
          hideLoading();
          console.error('k8scout filtered ingest failed', e);
          alert('Failed to build filtered graph: ' + e.message);
        }
        largeFileResolve && largeFileResolve();
      }, 30);
    };
    document.getElementById('largefile-cancel').onclick = () => {
      document.getElementById('largefile-bg').classList.remove('visible');
      largeFileResolve && largeFileResolve();
    };

    document.getElementById('largefile-bg').classList.add('visible');
  });
}

function applyLargeFileFilters(nodes, edges) {
  const selNS   = new Set([...document.querySelectorAll('#ns-chips .filter-chip.on')].map(c => c.dataset.ns));
  const selKind = new Set([...document.querySelectorAll('#kind-chips .filter-chip.on')].map(c => c.dataset.kind));
  const minRisk = parseFloat(document.getElementById('min-risk-slider').value) || 0;

  const filteredNodes = nodes.filter(n => {
    if (n.namespace && !selNS.has(n.namespace)) return false;
    if (n.kind && !selKind.has(n.kind)) return false;
    if ((n.risk_score || 0) < minRisk) return false;
    return true;
  });
  const nodeSet = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = edges.filter(e => {
    const s = e.from || e.source;
    const t = e.to || e.target;
    return nodeSet.has(typeof s === 'object' ? s.id : s) &&
           nodeSet.has(typeof t === 'object' ? t.id : t);
  });
  return { nodes: filteredNodes, edges: filteredEdges };
}

function updateLargeFilePreview(raw, nodes, edges) {
  const f = applyLargeFileFilters(nodes, edges);
  document.getElementById('largefile-preview').textContent =
    `After filter: ${f.nodes.length} nodes · ${f.edges.length} edges`;
}


/* ================================================================
   DATA INGESTION
   ================================================================ */
function ingestData(raw, nodes, edges) {
  resetTransientState();
  dataVersion += 1;
  rawGraphData = raw;   // store for AI prompt access to cluster_objects
  const g = raw.graph || raw;
  const simNodes = nodes.map(n => ({...n}));
  const simEdges = edges.map(e => ({...e}));
  const findings = raw.risk_findings || g.risk_findings || raw.findings || g.findings || [];
  dataLayer = buildDataLayerIndices(raw, simNodes, simEdges, findings);
  nodeById = dataLayer.nodeById;

  window._findings = {};
  findings.forEach(f => { window._findings[f.id || f.title] = f; });

  // Propagate max finding score to each affected node so risk badges show real values
  findings.forEach(f => {
    (f.affected_nodes || []).forEach(nid => {
      const n = nodeById[nid];
      if (n && (f.score || 0) > (n.risk_score || 0)) n.risk_score = f.score;
    });
  });

  graphData = { nodes: simNodes, edges: simEdges, findings };

  // Build SA usage index so securityCategory() can differentiate used vs unused SAs.
  buildSAUsageIndex();

  // Build goal node set BEFORE renderGraph so securityCategory() works correctly
  goalNodeSet = buildGoalNodeSetFromFindings(findings);

  // Clear any stale path highlight from a previous data load.
  if (nodeSel) clearPathHighlight();
  if (simulation) simulation.stop();

  dropOverlay.classList.add('hidden');
  computeAttackPaths();
  importFindingPaths();
  rebuildPathIndices();
  // Refresh after path computation adds more goal info
  goalNodeSet = buildGoalNodeSetFromFindings(findings);
  renderFootholdHeader();
  renderCurrentRoute();
  if (currentRoute?.name !== 'explore') hideLoading();
  // Refresh GOD panel if open
  if (document.getElementById('god-panel').classList.contains('visible') || document.getElementById('god-panel').classList.contains('embedded')) {
    populateGodSASelector();
    renderGodPanel();
  }
}

