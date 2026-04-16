// sidebar.js
// Stats display, sidebar tab switching, findings list, attack paths list

/* ================================================================
   STATS
   ================================================================ */
function updateStats() {
  if (!graphData) return;
  const { nodes, edges, findings } = graphData;
  const stealthChip = rawGraphData?.meta?.stealth
    ? ' <span style="background:#e67e22;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;margin-left:6px" title="Stealth mode: SSRR/SSAR skipped">[STEALTH]</span>'
    : '';
  const footprintHtml = buildAuditFootprintSummary();
  document.getElementById('stats').innerHTML =
    `${nodes.length} nodes · ${edges.length} edges · ${findings.length} findings · ${computedPaths.length} paths${stealthChip}${footprintHtml}`;
}

function buildAuditFootprintSummary() {
  const fp = rawGraphData?.audit_footprint;
  if (!fp || fp.length === 0) return '';
  const skipped = fp.filter(e => e.skipped).length;
  if (skipped === 0) return '';
  const rows = fp.map(e =>
    `<tr style="opacity:${e.skipped?0.5:1}">
      <td style="padding:2px 8px;color:${e.skipped?'#888':'#ccc'}">${escHtml(e.action)}</td>
      <td style="padding:2px 8px;text-align:right">${e.count}</td>
      <td style="padding:2px 8px;color:${e.skipped?'#e74c3c':'#2ecc71'}">${e.skipped?'SKIPPED':'called'}</td>
      <td style="padding:2px 8px;color:${e.noise_level==='high'?'#e74c3c':e.noise_level==='medium'?'#f39c12':'#2ecc71'}">${e.noise_level}</td>
    </tr>`).join('');
  return ` <span style="cursor:pointer;background:#333;border:1px solid #555;padding:1px 6px;border-radius:3px;font-size:10px;color:#aaa"
    title="${escHtml('<table><thead><tr><th>Action</th><th>Count</th><th>Status</th><th>Noise</th></tr></thead><tbody>' + rows + '</tbody></table>')}"
    onclick="showAuditFootprintModal()">&#128065; Audit Footprint (${skipped} skipped)</span>`;
}

function showAuditFootprintModal() {
  const fp = rawGraphData?.audit_footprint;
  if (!fp) return;
  const rows = fp.map(e =>
    `<tr>
      <td style="padding:4px 10px;color:#ccc">${escHtml(e.action)}</td>
      <td style="padding:4px 10px;text-align:right;color:#aaa">${e.count}</td>
      <td style="padding:4px 10px;color:${e.skipped?'#e74c3c':'#2ecc71'}">${e.skipped?'SKIPPED':'called'}</td>
      <td style="padding:4px 10px;color:${e.noise_level==='high'?'#e74c3c':e.noise_level==='medium'?'#f39c12':'#2ecc71'}">${e.noise_level}</td>
    </tr>`).join('');
  const html = `<table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="color:#888;border-bottom:1px solid #333">
      <th style="text-align:left;padding:4px 10px">API Action</th>
      <th style="text-align:right;padding:4px 10px">Count</th>
      <th style="text-align:left;padding:4px 10px">Status</th>
      <th style="text-align:left;padding:4px 10px">Noise Level</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  openModal('Audit Footprint', html);
}

/* ================================================================
   SIDEBAR TABS
   ================================================================ */
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const name = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + name).classList.add('active');
  });
});

/* ================================================================
   SIDEBAR – FINDINGS
   ================================================================ */
function sevOrder(s) { return {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3}[s] ?? 4; }

function renderSidebar() {
  const { findings } = graphData;
  const sorted = [...findings].sort((a,b) => {
    const sd = sevOrder(a.severity) - sevOrder(b.severity);
    return sd !== 0 ? sd : (b.score||0) - (a.score||0);
  });

  const list = document.getElementById('findings-list');
  list.innerHTML = '';
  if (!sorted.length) {
    list.innerHTML = '<div style="padding:16px;color:var(--muted);font-size:12px;text-align:center;">No findings.</div>';
    return;
  }

  sorted.forEach(f => {
    const fid = f.id || f.title;
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.dataset.sev = f.severity || 'LOW';
    card.dataset.fid = fid;
    if (!activeFilters.has(f.severity)) card.classList.add('hidden');
    card.innerHTML = `
      <div class="finding-title"><span class="sev-badge ${f.severity||'LOW'}">${f.severity||'?'}</span> ${escHtml(f.title||fid)}</div>
      <div class="finding-meta"><span>${(f.affected_nodes||[]).length} node(s)</span><span>score ${f.score||0}</span><span>${f.rule_id||''}</span></div>
    `;
    card.addEventListener('click', () => {
      openFindingModal(fid);
      // If this finding has an attack_path, highlight it. Look up in
      // computedPaths by signature; if missing (e.g. a deeper backend path
      // that the frontend DFS didn't rediscover), synthesise it on demand
      // and re-render the paths list so the new card is reachable.
      const ap = f.attack_path;
      if (!ap || ap.length < 2) return;
      const nodes = ap.map(s => s.node && s.node.id).filter(Boolean);
      const sig = nodes.join('→');
      let pathIdx = computedPaths.findIndex(p => p.nodes.join('→') === sig);
      if (pathIdx < 0) {
        pathIdx = synthesisePathFromFinding(f);
        if (pathIdx < 0) return;
        // Re-render the paths sidebar so the synthesised card exists.
        renderAttackPaths();
      }
      clearPathHighlight();
      activePathIdx = pathIdx;
      highlightPath(computedPaths[pathIdx]);
      document.querySelector('.tab[data-tab="paths"]').click();
      const matchCard = document.querySelector(`.path-card[data-path-idx="${pathIdx}"]`);
      if (matchCard) {
        document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
        matchCard.classList.add('active');
        matchCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
    list.appendChild(card);
  });
}

function applyFilters() {
  document.querySelectorAll('.finding-card').forEach(card => {
    card.classList.toggle('hidden', !activeFilters.has(card.dataset.sev));
  });
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  const sev = btn.dataset.sev;
  btn.addEventListener('click', () => {
    if (activeFilters.has(sev)) { activeFilters.delete(sev); btn.classList.add('off'); }
    else { activeFilters.add(sev); btn.classList.remove('off'); }
    applyFilters();
  });
});

/* ================================================================
   SIDEBAR – ATTACK PATHS
   ================================================================ */
function pathSeverity(path) {
  const impact = pathImpactType(path);
  if (impact.score >= 9) return 'CRITICAL';
  if (impact.score >= 7) return 'HIGH';
  if (impact.score >= 5) return 'MEDIUM';
  return 'LOW';
}

function pathColor(sev) {
  return {CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)'}[sev] || 'var(--muted)';
}

function renderAttackPaths() {
  const container = document.getElementById('paths-container');
  if (!computedPaths.length) {
    container.innerHTML = '<div class="paths-empty">No privilege escalation paths found.<br><br>This may mean the current identity has limited permissions or the graph has no paths to high-value targets.</div>';
    return;
  }
  container.innerHTML = '';
  const pathFocused = isPathFocusedExploreMode();
  const focusedPathIdx = getScopedExplorePathIndex();

  // Annotate paths with impact info and sort by impact score desc
  const annotated = computedPaths.map((path, idx) => {
    const impact = pathImpactType(path);
    const sev    = pathSeverity(path);
    // Compute path weight from edge weights
    let weight = path._weight;
    if (weight == null) {
      weight = 0;
      (path.edges || []).forEach(ek => { weight += (EDGE_WEIGHT[ek] || 5.0); });
    }
    return { path, idx, impact, sev, weight };
  });
  annotated.sort((a, b) => {
    // Primary: impact score desc; Secondary: weight asc (easier paths first)
    if (b.impact.score !== a.impact.score) return b.impact.score - a.impact.score;
    return a.weight - b.weight;
  });
  const visibleAnnotated = pathFocused
    ? (focusedPathIdx >= 0 ? annotated.filter(item => item.idx === focusedPathIdx) : annotated.slice(0, 1))
    : annotated;

  // Group by severity
  const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW'];
  const groups = {};
  SEV_ORDER.forEach(s => { groups[s] = []; });
  visibleAnnotated.forEach(item => { (groups[item.sev] || groups['LOW']).push(item); });

  SEV_ORDER.forEach(sev => {
    const items = groups[sev];
    if (!items.length) return;

    const groupEl = document.createElement('div');
    groupEl.className = 'sev-group';

    const itemsEl = document.createElement('div');
    itemsEl.className = 'sev-group-items';

    if (!pathFocused) {
      const header = document.createElement('div');
      header.className = 'sev-group-header';
      header.dataset.sev = sev;
      const sevEmoji = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🟢' }[sev] || '';
      header.innerHTML = `${sevEmoji} ${sev}<span class="sev-count">${items.length} path${items.length!==1?'s':''}</span><span class="sev-chevron">▾</span>`;
      header.addEventListener('click', () => header.classList.toggle('collapsed'));
      groupEl.appendChild(header);
    }

    items.forEach(({ path, idx, impact, weight }) => {
      const target = nodeById[path.nodes[path.nodes.length-1]];
      const source = nodeById[path.nodes[0]];
      const col    = pathColor(sev);
      // Prefer backend-computed stages when available (accurate taxonomy).
      // Fall back to the frontend heuristic for frontend-DFS-only paths.
      const backendStages = path._stages && path._stages.length ? path._stages : null;
      const phases = classifyPathPhases(path);
      const steps  = path.nodes.length - 1;

      const card = document.createElement('div');
      card.className = 'path-card';
      if (pathFocused) card.classList.add('active');
      card.dataset.pathIdx = idx;
      card.dataset.impact  = impact.type;

      // Narrative label
      const narrative = getPathNarrative(path);

      // Phase row HTML — prefer backend stages, fall back to frontend heuristic.
      const phaseHtml = backendStages
        ? buildBackendStageRow(backendStages)
        : buildPhaseRow(phases);
      const shapeBadge = chainShapeBadge(path._chainShape);

      // Identity context banner — shows which SA/user to operate as
      let identityBannerHtml = '';
      if (source) {
        if (source.kind === 'ServiceAccount') {
          const saRef = `system:serviceaccount:${source.namespace||'default'}:${source.name}`;
          identityBannerHtml = `
            <div class="identity-ctx-banner">
              <div class="identity-ctx-label">Identity — operate as this service account</div>
              <div class="identity-ctx-row">
                <code>${escHtml(saRef)}</code>
                <button class="copy-btn" onclick="copyCmd(this)" data-cmd="${encodeURIComponent(saRef)}">⧉</button>
              </div>
              <div class="identity-ctx-hint">To impersonate: add <code>--as=${escHtml(saRef)}</code> to kubectl commands, or exec into a pod running as this SA and use its mounted token.</div>
            </div>`;
        } else if (source.kind === 'Identity') {
          identityBannerHtml = `
            <div class="identity-ctx-banner is-user">
              <div class="identity-ctx-label">Identity — current kubeconfig user</div>
              <div class="identity-ctx-row">
                <code>${escHtml(source.name||'current-identity')}</code>
              </div>
              <div class="identity-ctx-hint">Commands run as your current kubeconfig context (no impersonation needed).</div>
            </div>`;
        }
      }

      // Numbered step list — action label header, command below
      let stepsHtml = identityBannerHtml + '<div class="attack-steps-label">Attack Steps</div>';
      path.edges.forEach((edgeKind, i) => {
        const srcNode = nodeById[path.nodes[i]];
        const tgtNode = nodeById[path.nodes[i+1]];
        const cmdFn   = ATTACK_CMD[edgeKind];
        const info    = cmdFn ? cmdFn(srcNode||{}, tgtNode||{}) : {
          action: `${edgeKind}: ${srcNode?.name||'?'} → ${tgtNode?.name||'?'}`,
          cmds: [`# ${edgeKind}`]
        };
        let stepPhaseLabel = '';
        if (phases.initialAccess.nodeId === path.nodes[i]) stepPhaseLabel = 'Initial Access';
        else if (phases.credTheft.present && phases.credTheft.stepIdx === i) stepPhaseLabel = '🔑 Cred Theft';
        else if (phases.privEsc.present && phases.privEsc.stepIdx === i) stepPhaseLabel = '⬆ Priv Esc';
        else if (phases.lateralMovement.present && phases.lateralMovement.stepIdx === i) stepPhaseLabel = '↔ Lateral Move';
        if (i === path.edges.length - 1) stepPhaseLabel = (stepPhaseLabel || '') + (stepPhaseLabel ? ' + ' : '') + '💀 Impact';

        const cmdText = info.cmds.join('\n');
        stepsHtml += `
          <div class="attack-step">
            <div class="attack-step-header">
              <div class="step-num">${i+1}</div>
              <div class="step-action">${escHtml(info.action)}${stepPhaseLabel ? `<span style="font-size:9px;color:var(--muted);margin-left:5px;">[${stepPhaseLabel}]</span>` : ''}</div>
            </div>
            <div class="step-cmd">${escHtml(cmdText)}<button class="copy-btn" onclick="copyCmd(this)" data-cmd="${encodeURIComponent(cmdText)}">⧉</button></div>
          </div>
        `;
      });

      // Exploitability meter: lower weight = easier to exploit = higher bar
      const maxWeight = 15; // weight at which exploitability is near-zero
      const exploitPct = Math.max(5, Math.min(100, (1 - weight / maxWeight) * 100));
      const exploitColor = exploitPct > 70 ? 'var(--crit)' : exploitPct > 40 ? 'var(--high)' : exploitPct > 20 ? 'var(--med)' : 'var(--low)';
      const exploitLabel = weight < 1 ? 'Trivial' : weight < 3 ? 'Easy' : weight < 6 ? 'Moderate' : weight < 10 ? 'Hard' : 'Very Hard';

      // Use backend title if available, otherwise generate from source→target
      const displayTitle = path._title || `${escHtml(source?.name||'?')} → ${escHtml(target?.name||'?')}`;
      const riskScore = path._score || ((target?.risk_score||0) > 0 ? target.risk_score : impact.score);

      card.innerHTML = `
        <div class="path-header">
          <div class="path-sev-dot" style="background:${col}"></div>
          <div style="flex:1;min-width:0;">
            <div class="path-title">${path._title ? escHtml(displayTitle) : displayTitle}</div>
            <div class="path-meta">${steps} step${steps!==1?'s':''} · risk ${Number(riskScore).toFixed(1)} · exploitability: ${exploitLabel}</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:3px;align-items:flex-end;">
            <span class="impact-badge ${impact.type}">${escHtml(impact.label)}</span>
            ${shapeBadge}
          </div>
        </div>
        <div class="effort-meter" title="Exploitability: ${exploitLabel} (weight ${weight.toFixed(1)})"><div class="effort-bar" style="width:${exploitPct}%;background:${exploitColor}"></div></div>
        <div class="path-label">${escHtml(narrative)}</div>
        ${phaseHtml}
        <div class="path-steps">
          ${stepsHtml}
        </div>
      `;

      card.addEventListener('click', e => {
        if (e.target.closest('.copy-btn')) return;
        if (pathFocused) {
          document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
          card.classList.add('active');
          activePathIdx = idx;
          highlightPath(path);
          return;
        }
        const isActive = card.classList.contains('active');
        document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
        if (!isActive) {
          card.classList.add('active');
          activePathIdx = idx;
          highlightPath(path);
          document.querySelector('.tab[data-tab="paths"]').click();
        } else {
          activePathIdx = null;
          clearPathHighlight();
        }
      });

      itemsEl.appendChild(card);
    });

    groupEl.appendChild(itemsEl);
    container.appendChild(groupEl);
  });
}

// buildBackendStageRow renders the phase row using backend AttackStages.
// Each stage carries: stage (int), label (string), node_id (string), description (string).
// Called when a path was emitted by the backend; otherwise we fall back to the
// frontend heuristic classifyPathPhases.
function buildBackendStageRow(stages) {
  if (!stages || !stages.length) return '';
  const classFor = (label) => {
    const l = (label||'').toLowerCase();
    if (l.includes('foothold') || l.includes('entry')) return 'initial';
    if (l.includes('credential') || l.includes('theft') || l.includes('impersonat') || l.includes('identity pivot') || l.includes('node pivot')) return 'credtheft';
    if (l.includes('priv') || l.includes('admin') || l.includes('escalat') || l.includes('cloud')) return 'privesc';
    if (l.includes('lateral') || l.includes('takeover') || l.includes('escape') || l.includes('visibility') || l.includes('discovery')) return 'lateral';
    if (l.includes('target') || l.includes('data') || l.includes('reached')) return 'impact';
    return 'initial';
  };
  const chips = stages.map(s => {
    const node = nodeById[s.node_id];
    const short = node ? ((node.name||node.id||'?').split(':').pop()) : (s.node_id||'').split(':').pop();
    const trunc = short.length > 14 ? short.slice(0, 13) + '…' : short;
    const cls = classFor(s.label);
    return `<span class="phase-chip ${cls}" title="${escHtml(s.label)}: ${escHtml(s.description||'')}">${escHtml(s.label)} · ${escHtml(trunc)}</span>`;
  });
  return `<div class="phase-row">${chips.join('<span class="phase-arrow">→</span>')}</div>`;
}

// chainShapeBadge renders a small badge describing the backend PathShape.
function chainShapeBadge(shape) {
  if (!shape) return '';
  const labels = {
    full_chain:     { text: 'FULL CHAIN',     cls: 'impact-badge CLUSTER_ADMIN' },
    foothold_start: { text: 'FOOTHOLD CHAIN', cls: 'impact-badge NODE_BREAKOUT' },
    bridge_start:   { text: 'RBAC CHAIN',     cls: 'impact-badge PRIVESC' },
    abstract_start: { text: 'THEORETICAL',    cls: 'impact-badge UNKNOWN' },
  };
  const info = labels[shape];
  if (!info) return '';
  return `<span class="${info.cls}" title="Backend chain-shape classification">${escHtml(info.text)}</span>`;
}

function buildPhaseRow(phases) {
  const make = (phase, cls) => {
    const node = nodeById[phase.nodeId];
    const label = node ? (node.name||node.id||'?').split(':').pop() : '?';
    if (!phase.present) return `<span class="phase-chip ${cls} no-step">— ${escHtml(phase.label)}</span>`;
    return `<span class="phase-chip ${cls}" title="${escHtml(phase.label)}: ${escHtml(node?.name||phase.nodeId||'')}">${escHtml(phase.label.split(' ').map(w=>w[0]).join(''))} ${escHtml(label.length>14?label.slice(0,13)+'…':label)}</span>`;
  };
  return `
    <div class="phase-row">
      ${make(phases.initialAccess,   'initial')}
      <span class="phase-arrow">→</span>
      ${make(phases.credTheft,       'credtheft')}
      <span class="phase-arrow">→</span>
      ${make(phases.privEsc,         'privesc')}
      <span class="phase-arrow">→</span>
      ${make(phases.lateralMovement, 'lateral')}
      <span class="phase-arrow">→</span>
      ${make(phases.impact,          'impact')}
    </div>
  `;
}

window.copyCmd = function(btn) {
  const cmd = decodeURIComponent(btn.dataset.cmd);
  navigator.clipboard.writeText(cmd).then(() => {
    btn.textContent = '✓';
    setTimeout(() => { btn.textContent = '⧉'; }, 1500);
  });
};
