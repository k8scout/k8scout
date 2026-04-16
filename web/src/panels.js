// panels.js
// Node selection, path highlighting, chain strip, blast radius, detail panel, finding modal, tooltip

/* ================================================================
   NODE SELECTION + HIGHLIGHT
   ================================================================ */
function selectNode(id) {
  selectedNodeId = id;
  activePathIdx  = null;
  document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));

  const node = graphData.nodes.find(n => n.id === id);
  if (!node) return;

  const neighborIds = new Set([id]);
  graphData.edges.forEach(e => {
    const sid = edgeNodeId(e.source || e.from);
    const tid = edgeNodeId(e.target || e.to);
    if (sid === id) neighborIds.add(tid);
    if (tid === id) neighborIds.add(sid);
  });

  nodesLayer.selectAll('circle.node-circle')
    .classed('dimmed',      d => !neighborIds.has(d.id))
    .classed('highlighted', d => d.id === id)
    .classed('path-active', false);
  nodesLayer.selectAll('polygon.host-shape')
    .classed('dimmed',      d => !neighborIds.has(d.id))
    .classed('path-active', false);
  nodesLayer.selectAll('circle.target-ring')
    .style('display', d => neighborIds.has(d.id) ? null : 'none')
    .style('opacity', d => neighborIds.has(d.id) ? null : 0);
  nodesLayer.selectAll('circle.score-ring')
    .style('display', d => neighborIds.has(d.id) ? null : 'none')
    .style('opacity', d => neighborIds.has(d.id) ? null : 0);
  nodesLayer.selectAll('text.score-badge-text')
    .style('display', d => neighborIds.has(d.id) ? null : 'none')
    .style('opacity', d => neighborIds.has(d.id) ? null : 0);
  linksLayer.selectAll('path.edge-path')
    .classed('dimmed', d => {
      const sid = edgeNodeId(d.source), tid = edgeNodeId(d.target);
      return !(sid === id || tid === id);
    })
    .classed('highlighted', d => {
      const sid = edgeNodeId(d.source), tid = edgeNodeId(d.target);
      return sid === id || tid === id;
    })
    .classed('path-active', false);

  showDetailPanel(node);
}

function clearSelection() {
  selectedNodeId = null;
  nodesLayer.selectAll('circle.node-circle').classed('dimmed',false).classed('highlighted',false).classed('path-active',false).classed('path-start',false).classed('path-end',false);
  nodesLayer.selectAll('polygon.host-shape').classed('dimmed',false).classed('path-active',false).classed('path-start',false).classed('path-end',false);
  nodesLayer.selectAll('circle.target-ring').style('display', null).style('opacity', null);
  nodesLayer.selectAll('circle.score-ring').style('display', null).style('opacity', null);
  nodesLayer.selectAll('text.score-badge-text').style('display', null).style('opacity', null);
  linksLayer.selectAll('path.edge-path').classed('dimmed',false).classed('highlighted',false).classed('path-active',false);
  nodesLayer.selectAll('text.path-step-num').remove();
  nodesLayer.selectAll('g.path-edge-label').remove();
  hideDetailPanel();
  document.querySelectorAll('.finding-card').forEach(c => c.classList.remove('active'));
}

function highlightPath(path) {
  if (!path) return;
  const pathNodeSet = new Set(path.nodes);
  const pathEdgeSet = new Set();
  path.nodes.forEach((nid, i) => {
    if (i < path.nodes.length - 1) pathEdgeSet.add(`${nid}→${path.nodes[i+1]}`);
  });
  const startId = path.nodes[0];
  const endId   = path.nodes[path.nodes.length - 1];

  // Force-show RBAC nodes in this path even if RBAC is hidden
  activePathNodeIds = pathNodeSet;
  if (!showRbac) applyRbacVisibility();

  // Remove focus-dim during path highlight (path highlighting does its own dimming)
  if (focusMode) {
    nodeSel.classed('focus-dim', false);
    linkSel.classed('focus-dim', false);
  }

  // Dim/highlight circles
  nodesLayer.selectAll('circle.node-circle')
    .classed('dimmed',      d => !pathNodeSet.has(d.id))
    .classed('highlighted', false)
    .classed('path-active', d => pathNodeSet.has(d.id))
    .classed('path-start',  d => d.id === startId)
    .classed('path-end',    d => d.id === endId);

  // Host diamond polygons
  nodesLayer.selectAll('polygon.host-shape')
    .classed('dimmed',      d => !pathNodeSet.has(d.id))
    .classed('path-active', d => pathNodeSet.has(d.id))
    .classed('path-start',  d => d.id === startId)
    .classed('path-end',    d => d.id === endId);

  nodesLayer.selectAll('circle.target-ring')
    .style('display', d => pathNodeSet.has(d.id) ? null : 'none')
    .style('opacity', d => pathNodeSet.has(d.id) ? null : 0);
  nodesLayer.selectAll('circle.score-ring')
    .style('display', 'none')
    .style('opacity', 0);
  nodesLayer.selectAll('text.score-badge-text')
    .style('display', 'none')
    .style('opacity', 0);

  // Dim/highlight edges
  linksLayer.selectAll('path.edge-path')
    .classed('dimmed', d => {
      const sid = edgeNodeId(d.source), tid = edgeNodeId(d.target);
      return !pathEdgeSet.has(`${sid}→${tid}`);
    })
    .classed('highlighted', false)
    .classed('path-active', d => {
      const sid = edgeNodeId(d.source), tid = edgeNodeId(d.target);
      return pathEdgeSet.has(`${sid}→${tid}`);
    });

  // Step number overlays: numbered badges on each path node
  nodesLayer.selectAll('text.path-step-num').remove();
  path.nodes.forEach((nid, i) => {
    const nodeG = nodesLayer.selectAll('g.node-g').filter(d => d.id === nid);
    if (nodeG.empty()) return;
    const d = nodeG.datum();
    const r = nodeRadius(d);
    nodeG.append('text')
      .attr('class', 'path-step-num')
      .attr('x', 0).attr('y', 0)
      .attr('dy', -r - 8)
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('font-weight', '800')
      .attr('fill', i === 0 ? '#4cc9f0' : (i === path.nodes.length-1 ? '#ff4757' : '#a9e34b'))
      .attr('stroke', '#0d0f13')
      .attr('stroke-width', '2.5')
      .text(i === 0 ? '▶' : (i === path.nodes.length-1 ? '⬛' : String(i)));
  });

  hideDetailPanel();
  showChainStrip(path);
  fitNodesToView(path.nodes);
}

function clearPathHighlight() {
  activePathIdx = null;
  nodesLayer.selectAll('circle.node-circle')
    .classed('dimmed',false).classed('highlighted',false).classed('path-active',false)
    .classed('path-start',false).classed('path-end',false);
  nodesLayer.selectAll('polygon.host-shape')
    .classed('dimmed',false).classed('path-active',false)
    .classed('path-start',false).classed('path-end',false);
  nodesLayer.selectAll('circle.target-ring')
    .style('display', null)
    .style('opacity', null);
  nodesLayer.selectAll('circle.score-ring')
    .style('display', null)
    .style('opacity', null);
  nodesLayer.selectAll('text.score-badge-text')
    .style('display', null)
    .style('opacity', null);
  linksLayer.selectAll('path.edge-path').classed('dimmed',false).classed('highlighted',false).classed('path-active',false);
  nodesLayer.selectAll('text.path-step-num').remove();
  nodesLayer.selectAll('g.path-edge-label').remove();
  hideChainStrip();
  document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));

  // Re-hide RBAC nodes that were temporarily shown for the path
  activePathNodeIds = new Set();
  if (!showRbac) applyRbacVisibility();

  // Re-apply focus mode if active
  if (focusMode) applyFocusMode();
}

/* ================================================================
   CHAIN STRIP — narrative bar showing path steps at canvas bottom
   ================================================================ */
function showChainStrip(path) {
  const strip = document.getElementById('chain-strip');
  const inner = document.getElementById('chain-strip-inner');
  if (!strip || !inner) return;

  inner.innerHTML = '';
  path.nodes.forEach((nid, i) => {
    const node = nodeById[nid];
    const cat  = node ? securityCategory(node) : 'context';
    const col  = CATEGORY_COLORS[cat] || '#555';
    const label = node ? (node.name || nid).split(':').pop() : nid;
    const isStart = i === 0;
    const isEnd   = i === path.nodes.length - 1;

    const step = document.createElement('div');
    step.className = 'cs-step';

    // Node chip
    const chip = document.createElement('div');
    chip.className = `cs-node${isStart?' cs-start':''}${isEnd?' cs-end':''}`;
    chip.style.cssText = `background:${col}18;color:${col};border-color:${col}50`;
    const nodeIcon = escHtml(NODE_ICONS[node?.kind] || '•');
    chip.innerHTML = `<span class="cs-node-num" style="background:${col}30">${nodeIcon}</span><span class="cs-node-label">${escHtml(label)}</span>`;
    if (isStart) chip.innerHTML += `<span class="cs-start-badge">START</span>`;
    if (isEnd)   chip.innerHTML += `<span class="cs-end-badge">TARGET</span>`;
    chip.title = nid;
    chip.addEventListener('click', () => { selectNode(nid); });
    step.appendChild(chip);

    // Arrow + edge label (between steps)
    if (i < path.nodes.length - 1) {
      const edgeKind = (path.edges && path.edges[i]) ? path.edges[i] : '→';
      const arrow = document.createElement('div');
      arrow.className = 'cs-arrow';
      const edgeLabel = edgeKind.replace('can_','').replace(/_/g,' ');
      arrow.innerHTML = `<span class="cs-edge-label">${escHtml(edgeLabel)}</span><span class="cs-edge-icon">›</span>`;
      step.appendChild(arrow);
    }

    inner.appendChild(step);
  });

  strip.classList.add('visible');
}

function hideChainStrip() {
  const strip = document.getElementById('chain-strip');
  if (strip) strip.classList.remove('visible');
}

// Close button
document.getElementById('chain-strip-close').addEventListener('click', () => {
  clearPathHighlight();
});

function fitNodesToView(nodeIds) {
  if (!graphData || !zoomBehavior) return;
  const pts = nodeIds.map(id => nodePosMap[id]).filter(Boolean);
  if (!pts.length) return;
  const xs = pts.map(p => p.x), ys = pts.map(p => p.y);
  const x0 = Math.min(...xs)-40, x1 = Math.max(...xs)+40;
  const y0 = Math.min(...ys)-40, y1 = Math.max(...ys)+40;
  const W = canvasWrap.clientWidth, H = canvasWrap.clientHeight;
  const k = 0.9 * Math.min(W/(x1-x0), H/(y1-y0));
  const tx = (W - k*(x0+x1)) / 2, ty = (H - k*(y0+y1)) / 2;
  svg.transition().duration(600)
    .call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(k));
}


/* ================================================================
   BLAST RADIUS
   ================================================================ */
function computeBlastRadius(nodeId) {
  const visited = new Set([nodeId]);
  const queue = [nodeId];
  const attackEdges = new Set(['can_exec','can_create','can_patch','can_delete','can_get','can_list','can_impersonate','inferred']);
  while (queue.length) {
    const cur = queue.shift();
    for (const e of graphData.edges) {
      const sid = e.source?.id || e.from || (typeof e.source === 'string' ? e.source : null);
      const tid = e.target?.id || e.to   || (typeof e.target === 'string' ? e.target : null);
      if (sid === cur && attackEdges.has(e.kind) && !visited.has(tid)) {
        visited.add(tid);
        queue.push(tid);
      }
    }
  }
  visited.delete(nodeId);
  const reachableNodes = [...visited].map(id => nodeById[id]).filter(Boolean);
  const namespaces = new Set(reachableNodes.map(n => n.namespace).filter(Boolean));
  const secrets    = reachableNodes.filter(n => n.kind === 'Secret').length;
  const workloads  = reachableNodes.filter(n => n.kind === 'Workload' || n.kind === 'Pod').length;
  const nodes      = reachableNodes.filter(n => n.kind === 'Node').length;
  return { namespaces: namespaces.size, secrets, workloads, nodes, totalReachable: visited.size };
}

/* ================================================================
   DETAIL PANEL
   ================================================================ */
function showDetailPanel(node) {
  document.getElementById('detail-panel').classList.add('visible');
  const badge = document.getElementById('detail-kind-badge');
  badge.textContent = node.kind || 'Unknown';
  badge.style.background = nodeColor(node);
  document.getElementById('detail-name').textContent = node.name || node.id;
  document.getElementById('detail-ns').textContent = node.namespace ? `ns: ${node.namespace}` : '';

  const incoming = [], outgoing = [];
  graphData.edges.forEach(e => {
    const sid = edgeNodeId(e.source || e.from);
    const tid = edgeNodeId(e.target || e.to);
    if (sid === node.id) { const tn = nodeById[tid]; if (tn) outgoing.push({rel:e.kind,node:tn}); }
    if (tid === node.id) { const sn = nodeById[sid]; if (sn) incoming.push({rel:e.kind,node:sn}); }
  });

  const related = graphData.findings.filter(f => (f.affected_nodes||[]).includes(node.id));
  const score   = node.risk_score || 0;

  // Find attack paths involving this node
  const relPaths = computedPaths.filter(p => p.nodes.includes(node.id));

  let html = `
    <div class="detail-section">
      <h3>Risk Score</h3>
      <div class="detail-row"><span>Score</span><span>${score.toFixed(1)} / 10</span></div>
      <div class="risk-bar-wrap"><div class="risk-bar-fill" style="width:${Math.min(100,score*10)}%"></div></div>
    </div>
    <div class="detail-section">
      <h3>Properties</h3>
      <div class="detail-row"><span>Kind</span><span>${node.kind||'?'}</span></div>
      ${node.namespace ? `<div class="detail-row"><span>Namespace</span><span>${escHtml(node.namespace)}</span></div>` : ''}
      <div class="detail-row"><span>ID</span><span style="font-size:10px">${escHtml(node.id)}</span></div>
    </div>`;

  // Blast radius
  if (node.kind === 'ServiceAccount' || node.kind === 'Identity') {
    const br = computeBlastRadius(node.id);
    const total = graphData.nodes.length;
    const pct = total > 0 ? Math.round((br.totalReachable / total) * 100) : 0;
    const clusterWide = pct > 50;
    html += `<div class="detail-section">
      <h3>Blast Radius</h3>
      <div class="detail-row"><span>Reachable nodes</span><span>${br.totalReachable} / ${total} (${pct}%)</span></div>
      <div class="risk-bar-wrap"><div class="risk-bar-fill" style="width:${Math.min(100,pct)}%;background:${clusterWide?'var(--crit)':'var(--accent)'}"></div></div>
      <div class="detail-row"><span>Namespaces</span><span>${br.namespaces}</span></div>
      <div class="detail-row"><span>Secrets</span><span>${br.secrets}</span></div>
      <div class="detail-row"><span>Workloads/Pods</span><span>${br.workloads}</span></div>
      ${clusterWide ? `<div style="margin-top:6px;padding:5px 8px;background:#2e0000;border-radius:4px;font-size:11px;color:var(--crit);font-weight:700">⚠ Cluster-wide compromise risk</div>` : ''}
    </div>`;
  }

  const CONN_PREVIEW = 8;
  if (outgoing.length) {
    html += `<div class="detail-section"><h3>Can reach (${outgoing.length})</h3>`;
    outgoing.forEach((c, i) => {
      const col = NODE_COLORS[c.node.kind] || DEFAULT_NODE_COLOR;
      const hidden = i >= CONN_PREVIEW ? ' class="conn-item conn-extra" style="display:none"' : ' class="conn-item"';
      html += `<div${hidden}><span class="rel-badge">${escHtml(c.rel)}</span><span class="conn-name" style="color:${col}">${escHtml(c.node.name||c.node.id)}</span></div>`;
    });
    if (outgoing.length > CONN_PREVIEW) html += `<button class="show-more-btn" onclick="expandSection(this)">Show ${outgoing.length - CONN_PREVIEW} more</button>`;
    html += `</div>`;
  }
  if (incoming.length) {
    html += `<div class="detail-section"><h3>Reachable from (${incoming.length})</h3>`;
    incoming.forEach((c, i) => {
      const col = NODE_COLORS[c.node.kind] || DEFAULT_NODE_COLOR;
      const hidden = i >= CONN_PREVIEW ? ' class="conn-item conn-extra" style="display:none"' : ' class="conn-item"';
      html += `<div${hidden}><span class="rel-badge">${escHtml(c.rel)}</span><span class="conn-name" style="color:${col}">${escHtml(c.node.name||c.node.id)}</span></div>`;
    });
    if (incoming.length > CONN_PREVIEW) html += `<button class="show-more-btn" onclick="expandSection(this)">Show ${incoming.length - CONN_PREVIEW} more</button>`;
    html += `</div>`;
  }

  if (relPaths.length) {
    html += `<div class="detail-section"><h3>In Attack Paths (${relPaths.length})</h3>`;
    relPaths.forEach((p, pi) => {
      const idx = computedPaths.indexOf(p);
      const target = nodeById[p.nodes[p.nodes.length-1]];
      const sev = pathSeverity(p);
      const col = pathColor(sev);
      html += `<div class="mini-finding" data-sev="${sev}" onclick="selectPathFromDetail(${idx})"><div class="mini-finding-title" style="color:${col}">${escHtml(target?.name||'?')} · ${p.nodes.length-1} steps</div><div class="mini-finding-sev">${sev}</div></div>`;
    });
    html += `</div>`;
  }

  if (related.length) {
    html += `<div class="detail-section"><h3>Findings (${related.length})</h3>`;
    related.forEach(f => {
      const fid = f.id || f.title;
      html += `<div class="mini-finding" data-sev="${f.severity}" data-fid="${encodeURIComponent(fid)}" onclick="openFindingModalSafe(this)"><div class="mini-finding-title">${escHtml(f.title||fid)}</div><div class="mini-finding-sev">${f.severity} · score ${f.score||0}</div></div>`;
    });
    html += `</div>`;
  }

  document.getElementById('detail-body').innerHTML = html;
}

window.selectPathFromDetail = function(idx) {
  const path = computedPaths[idx];
  if (!path) return;
  activePathIdx = idx;
  highlightPath(path);
  // Switch to paths tab and activate card
  document.querySelector('.tab[data-tab="paths"]').click();
  const card = document.querySelector(`.path-card[data-path-idx="${idx}"]`);
  if (card) {
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    card.scrollIntoView({behavior:'smooth',block:'nearest'});
  }
};

function hideDetailPanel() { document.getElementById('detail-panel').classList.remove('visible'); }
document.getElementById('detail-close').addEventListener('click', () => { clearSelection(); clearPathHighlight(); });

function showEdgeDetailPanel(src, tgt, edge) {
  selectedNodeId = null;
  document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));

  const eColor = edgeColor(edge);
  const panel = document.getElementById('detail-panel');
  panel.classList.add('visible');

  const badge = document.getElementById('detail-kind-badge');
  badge.textContent = edge.kind || 'edge';
  badge.style.background = eColor;

  document.getElementById('detail-name').textContent =
    `${src?.name || src?.id || '?'}  →  ${tgt?.name || tgt?.id || '?'}`;
  document.getElementById('detail-ns').textContent =
    edge.inferred ? 'inferred edge' : '';

  const cmdFn = ATTACK_CMD[edge.kind];
  const info = cmdFn ? cmdFn(src || {}, tgt || {}) : null;

  let html = `
    <div class="detail-section">
      <h3>Edge Properties</h3>
      <div class="detail-row"><span>Type</span><span>${escHtml(edge.kind || '?')}</span></div>
      <div class="detail-row"><span>Source</span><span style="color:${NODE_COLORS[src?.kind]||DEFAULT_NODE_COLOR}">${escHtml(src?.name || src?.id || '?')}</span></div>
      <div class="detail-row"><span>Target</span><span style="color:${NODE_COLORS[tgt?.kind]||DEFAULT_NODE_COLOR}">${escHtml(tgt?.name || tgt?.id || '?')}</span></div>
      ${src?.namespace ? `<div class="detail-row"><span>Src NS</span><span>${escHtml(src.namespace)}</span></div>` : ''}
      ${tgt?.namespace ? `<div class="detail-row"><span>Tgt NS</span><span>${escHtml(tgt.namespace)}</span></div>` : ''}
      ${edge.inferred ? `<div class="detail-row"><span>Inferred</span><span style="color:var(--med)">Yes (rule-based)</span></div>` : ''}
    </div>`;

  if (info) {
    const cmdEncoded = encodeURIComponent(info.cmds.join('\n'));
    html += `
      <div class="detail-section">
        <h3>Attack Step</h3>
        <div style="font-size:11px;color:var(--text);margin-bottom:6px;line-height:1.5">${escHtml(info.action)}</div>
        <div class="step-cmd">${escHtml(info.cmds.join('\n'))}<button class="copy-btn" onclick="copyCmd(this)" data-cmd="${cmdEncoded}">⧉</button></div>
      </div>`;
  }

  document.getElementById('detail-body').innerHTML = html;

  // Highlight this edge and its two endpoints
  const srcId = edgeNodeId(edge.source), tgtId = edgeNodeId(edge.target);
  const edgeNodes = new Set([srcId, tgtId].filter(Boolean));

  linksLayer.selectAll('path.edge-path')
    .classed('dimmed',      dd => dd !== edge)
    .classed('highlighted', dd => dd === edge)
    .classed('path-active', false);

  nodesLayer.selectAll('circle.node-circle')
    .classed('dimmed',      d => !edgeNodes.has(d.id))
    .classed('highlighted', d => edgeNodes.has(d.id))
    .classed('path-active', false);
}

window.openFindingModalSafe = function(el) { openFindingModal(decodeURIComponent(el.dataset.fid)); };

/* ================================================================
   FINDING MODAL
   ================================================================ */
function openFindingModal(fid) {
  const f = window._findings[fid];
  if (!f) return;
  activeFindingId = fid;

  const affected = new Set(f.affected_nodes || []);
  nodesLayer.selectAll('circle.node-circle')
    .classed('dimmed',      d => !affected.has(d.id))
    .classed('highlighted', d => affected.has(d.id))
    .classed('path-active', false);
  linksLayer.selectAll('path.edge-path').classed('dimmed',true).classed('highlighted',false).classed('path-active',false);

  document.querySelectorAll('.finding-card').forEach(c =>
    c.classList.toggle('active', c.dataset.fid === fid)
  );

  document.getElementById('modal-title').innerHTML =
    `<span class="sev-badge ${f.severity}">${f.severity}</span> ${escHtml(f.title||fid)}`;

  // MITRE badges
  const mitreContainer = document.getElementById('modal-mitre');
  if (f.mitre_ids?.length) {
    mitreContainer.innerHTML = f.mitre_ids.map(id =>
      `<a href="https://attack.mitre.org/techniques/${id.replace('.','/')}/" target="_blank" style="display:inline-block;padding:2px 8px;border-radius:4px;background:#0a1628;border:1px solid #4cc9f040;color:#4cc9f0;font-size:10px;font-weight:700;text-decoration:none;margin:2px">${id}</a>`
    ).join('');
    mitreContainer.style.display = 'flex';
  } else {
    mitreContainer.innerHTML = '';
    mitreContainer.style.display = 'none';
  }

  // Look up enriched content per rule_id
  const ruleEnrich = RULE_ENRICHMENT[f.rule_id] || {};

  let body = '';

  // Description
  const desc = f.description || ruleEnrich.description || '';
  if (desc) body += `<div class="modal-section"><h4>Description</h4><p>${escHtml(desc)}</p></div>`;

  // Real-world impact
  const impact = f.impact || ruleEnrich.impact || '';
  if (impact) {
    body += `<div class="modal-section"><h4>Real-World Impact</h4><div class="modal-impact"><p>${escHtml(impact)}</p></div></div>`;
  }

  // Evidence
  if (f.evidence?.length) {
    body += `<div class="modal-section"><h4>Evidence</h4><ul>`;
    f.evidence.forEach(ev => { body += `<li><code>${escHtml(ev)}</code></li>`; });
    body += `</ul></div>`;
  }

  // Exploitation path — prefer the finding's own backend attack_path. Only
  // fall back to a node-intersection match in computedPaths for findings
  // that don't carry a backend path (single-step rule findings).
  let exploitPath = null;
  if (f.attack_path && f.attack_path.length >= 2) {
    const apNodes = f.attack_path.map(s => s.node && s.node.id).filter(Boolean);
    const apEdges = f.attack_path.slice(1).map(s => (s.edge && s.edge.kind) || 'inferred');
    if (apNodes.length >= 2) {
      exploitPath = { nodes: apNodes, edges: apEdges };
    }
  }
  if (!exploitPath) {
    const relPaths = computedPaths.filter(p =>
      (f.affected_nodes||[]).some(nid => p.nodes.includes(nid))
    );
    if (relPaths.length) exploitPath = relPaths[0];
  }
  if (exploitPath) {
    const impact2 = pathImpactType(exploitPath);
    body += `<div class="modal-section"><h4>Exploitation Path <span class="impact-badge ${impact2.type}" style="vertical-align:middle">${escHtml(impact2.label)}</span></h4>`;
    exploitPath.edges.forEach((ek, i) => {
      const srcN = nodeById[exploitPath.nodes[i]];
      const tgtN = nodeById[exploitPath.nodes[i+1]];
      const cmdFn = ATTACK_CMD[ek];
      const info = cmdFn
        ? cmdFn(srcN||{}, tgtN||{})
        : { action: `${ek}: ${srcN?.name || exploitPath.nodes[i]} → ${tgtN?.name || exploitPath.nodes[i+1]}`, cmds: [`# ${ek}`] };
      body += `<p style="margin-bottom:4px;color:var(--muted);font-size:11px">Step ${i+1}: ${escHtml(info.action)}</p>`;
      body += `<div class="modal-cmd">${escHtml(info.cmds.join('\n'))}</div>`;
    });
    body += `</div>`;
  }

  // Attacker command from rule enrichment
  const attackerCmd = ruleEnrich.attacker_cmd || '';
  if (attackerCmd && !relPaths.length) {
    body += `<div class="modal-section"><h4>Attacker Command Example</h4><div class="modal-attacker-cmd"><div class="step-cmd">${escHtml(attackerCmd)}</div></div></div>`;
  }

  // Detection opportunities
  const detect = f.detection || ruleEnrich.detection || '';
  if (detect) {
    body += `<div class="modal-section"><h4>Detection Opportunities</h4><div class="modal-detect"><p>${escHtml(detect)}</p></div></div>`;
  }

  // Mitigation
  const mitItems = [];
  if (f.mitigation) mitItems.push(f.mitigation);
  if (ruleEnrich.mitigation?.length) mitItems.push(...ruleEnrich.mitigation);
  if (mitItems.length) {
    body += `<div class="modal-section"><h4>Mitigation</h4><div class="modal-mitigate"><ul>`;
    mitItems.forEach(m => { body += `<li>${escHtml(m)}</li>`; });
    body += `</ul></div></div>`;
  }

  // Affected nodes
  if (f.affected_nodes?.length) {
    body += `<div class="modal-section"><h4>Affected Nodes (${f.affected_nodes.length})</h4><ul>`;
    f.affected_nodes.slice(0,25).forEach(nid => {
      const n = nodeById[nid];
      const col = NODE_COLORS[n?.kind] || DEFAULT_NODE_COLOR;
      body += `<li><span style="color:${col}">${escHtml(n ? (n.name||nid) : nid)}</span></li>`;
    });
    if (f.affected_nodes.length>25) body += `<li>…and ${f.affected_nodes.length-25} more</li>`;
    body += `</ul></div>`;
  }
  // AI Remediation button
  body += `<div class="modal-section"><h4>AI Remediation</h4><button class="tb-btn" style="font-size:11px" onclick="generateRemediation('${escHtml(fid)}')">⚡ Get Fix</button><div id="remediation-${escHtml(fid)}" style="margin-top:8px"></div></div>`;

  if (!body) body = '<p style="color:var(--muted)">No additional details available.</p>';

  document.getElementById('modal-body').innerHTML = body;
  document.getElementById('modal-bg').classList.add('visible');
}

function closeModal() {
  document.getElementById('modal-bg').classList.remove('visible');
  activeFindingId = null;
  if (selectedNodeId) selectNode(selectedNodeId);
  else clearSelection();
}

// Generic modal opener — used for audit footprint and other non-finding modals.
function openModal(title, bodyHtml) {
  document.getElementById('modal-title').innerHTML = escHtml(title);
  const mitreContainer = document.getElementById('modal-mitre');
  if (mitreContainer) { mitreContainer.innerHTML = ''; mitreContainer.style.display = 'none'; }
  document.getElementById('modal-body').innerHTML = bodyHtml;
  document.getElementById('modal-bg').classList.add('visible');
}

document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-bg').addEventListener('click', e => {
  if (e.target === document.getElementById('modal-bg')) closeModal();
});

/* ================================================================
   TOOLTIP
   ================================================================ */
const tooltip = document.getElementById('tooltip');
function showTooltip(event, title, body) {
  document.getElementById('tooltip-title').textContent = title;
  document.getElementById('tooltip-body').textContent = body || '';
  tooltip.classList.add('visible');
  moveTooltip(event);
}
function moveTooltip(event) {
  const x = event.clientX + 14, y = event.clientY + 14;
  tooltip.style.left = Math.min(x, window.innerWidth - 240) + 'px';
  tooltip.style.top  = Math.min(y, window.innerHeight - 80) + 'px';
}
function hideTooltip() { tooltip.classList.remove('visible'); }
