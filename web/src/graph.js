// graph.js
// D3 force-directed graph rendering, namespace zone hulls, minimap

/* ================================================================
   D3 FORCE GRAPH
   ================================================================ */
// Set up glow filters and gradients
function setupFilters() {
  svgDefs.selectAll('*').remove();

  // Glow filter for critical nodes (CRITICAL risk_score >= 8)
  const fCrit = svgDefs.append('filter').attr('id','glow-crit').attr('x','-60%').attr('y','-60%').attr('width','220%').attr('height','220%');
  fCrit.append('feGaussianBlur').attr('in','SourceGraphic').attr('stdDeviation','4').attr('result','blur');
  const mCrit = fCrit.append('feMerge');
  mCrit.append('feMergeNode').attr('in','blur');
  mCrit.append('feMergeNode').attr('in','SourceGraphic');

  // Glow filter for high nodes (HIGH risk_score 6-8)
  const fHigh = svgDefs.append('filter').attr('id','glow-high').attr('x','-45%').attr('y','-45%').attr('width','190%').attr('height','190%');
  fHigh.append('feGaussianBlur').attr('in','SourceGraphic').attr('stdDeviation','2.5').attr('result','blur');
  const mHigh = fHigh.append('feMerge');
  mHigh.append('feMergeNode').attr('in','blur');
  mHigh.append('feMergeNode').attr('in','SourceGraphic');

  // Subtle inner shadow for nodes (feComponentTransfer for depth)
  const fDepth = svgDefs.append('filter').attr('id','node-depth').attr('x','-20%').attr('y','-20%').attr('width','140%').attr('height','140%');
  fDepth.append('feGaussianBlur').attr('in','SourceAlpha').attr('stdDeviation','1.5').attr('result','shadow');
  fDepth.append('feOffset').attr('in','shadow').attr('dx','1').attr('dy','2').attr('result','offsetShadow');
  fDepth.append('feComposite').attr('in','SourceGraphic').attr('in2','offsetShadow').attr('operator','over');

  // Radial gradient defs for each security category (rich center → deep edge)
  const GRAD_DEFS = [
    { id:'g-actor',     c1:'#82e3f7', c2:'#2fb8e0', cx:'38%', cy:'32%' },
    { id:'g-target',    c1:'#ff9099', c2:'#d42030', cx:'38%', cy:'32%' },
    { id:'g-workload',  c1:'#6ef09a', c2:'#20a850', cx:'38%', cy:'32%' },
    { id:'g-secret',    c1:'#f8e050', c2:'#c8960a', cx:'38%', cy:'32%' },
    { id:'g-privilege', c1:'#cb96e6', c2:'#8030a8', cx:'38%', cy:'32%' },
    { id:'g-hook',      c1:'#ffcf80', c2:'#de8010', cx:'38%', cy:'32%' },
    { id:'g-cloud',     c1:'#f0a0ff', c2:'#b030d0', cx:'38%', cy:'32%' },
    { id:'g-context',   c1:'#606470', c2:'#303440', cx:'38%', cy:'32%' },
  ];
  GRAD_DEFS.forEach(({ id, c1, c2, cx, cy }) => {
    const g = svgDefs.append('radialGradient')
      .attr('id', id).attr('cx', cx).attr('cy', cy).attr('r','70%').attr('gradientUnits','objectBoundingBox');
    g.append('stop').attr('offset','0%').attr('stop-color', c1).attr('stop-opacity', 1);
    g.append('stop').attr('offset','100%').attr('stop-color', c2).attr('stop-opacity', 1);
  });

  // Gradient for active path edges
  const pathGrad = svgDefs.append('linearGradient').attr('id','path-edge-grad')
    .attr('gradientUnits','userSpaceOnUse');
  pathGrad.append('stop').attr('offset','0%').attr('stop-color','#a9e34b');
  pathGrad.append('stop').attr('offset','100%').attr('stop-color','#06d6a0');
}

// Arrow markers
function ensureMarker(color, dashed) {
  const safe = color.replace(/[^a-zA-Z0-9]/g, '_');
  const id = 'arr_' + safe + (dashed ? '_d' : '');
  if (svgDefs.select('#' + id).empty()) {
    svgDefs.append('marker')
      .attr('id', id)
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', 7)
      .attr('refY', 0)
      .attr('markerWidth', 5)
      .attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path')
        .attr('d', 'M0,-4L8,0L0,4')
        .attr('fill', color)
        .attr('opacity', dashed ? 0.5 : 0.85);
  }
  return id;
}

function nodeRadius(d) {
  const cat = securityCategory(d);
  if (cat === 'target') return Math.max(16, 14 + (d.risk_score||0) * 0.8);
  if (cat === 'context') return 7;
  // Workloads are primary footholds — slightly larger than SAs to emphasize their role.
  if (cat === 'workload') return Math.max(13, 11 + (d.risk_score||0) * 0.75);
  if (cat === 'actor') return Math.max(11, 10 + (d.risk_score||0) * 0.7);
  return 9 + (d.risk_score||0) * 0.75;
}
function nodeColor(d) {
  const cat = securityCategory(d);
  return CATEGORY_COLORS[cat] || DEFAULT_NODE_COLOR;
}
function edgeColor(d)  { return EDGE_COLORS[d.kind] || DEFAULT_EDGE_COLOR; }

function nodeHasSpecialConfig(d) {
  const m = d.metadata || {};
  return m.privileged_containers || m.host_pid === 'true' || m.host_network === 'true' ||
    m.host_path === 'true' || m.automount_service_account_token === 'true' ||
    d.privileged || d.host_path || d.host_pid || d.host_network ||
    d.host_path_mount || d.privileged_container || d.automount_sa_token ||
    (d.properties && (d.properties.privileged || d.properties.host_path));
}
function nodeSpecialIcon(d) {
  const m = d.metadata || {};
  if (m.privileged_containers || d.privileged || d.privileged_container || (d.properties?.privileged)) return '🛡';
  if (m.host_path === 'true' || d.host_path || d.host_path_mount || (d.properties?.host_path)) return '💾';
  if (m.host_pid === 'true' || m.host_network === 'true' || d.host_pid || d.host_network) return '🌐';
  if (m.automount_service_account_token === 'true' || d.automount_sa_token) return '🔑';
  return '⚠';
}

// Security category — semantic role of a node in the attack graph
function securityCategory(d) {
  if (!d) return 'context';
  // Explicit goal/target conditions
  if (d.kind === 'Node') return 'target';
  if (d.id === 'clusterrole:cluster-admin') return 'target';
  if (goalNodeSet.has(d.id)) return 'target';
  if ((d.risk_score||0) >= 8) return 'target';
  const meta = d.metadata || {};
  // Workloads/pods with dangerous config are targets
  if ((d.kind === 'Workload' || d.kind === 'Pod') &&
    (meta.privileged_containers || meta.host_pid === 'true' || meta.host_network === 'true')) return 'target';
  // SA with cloud IAM is a target
  if (d.kind === 'ServiceAccount' && meta.cloud_role) return 'target';
  // SA-token secrets or secrets with captured values are targets
  if (d.kind === 'Secret' && (meta.type === 'kubernetes.io/service-account-token' || meta.has_captured_values === 'true')) return 'target';
  // Actors — SA is only prominent if it actually has running workloads using it.
  // An SA with privilege but no execution foothold is de-emphasized as context.
  if (d.kind === 'Identity') return 'actor';
  if (d.kind === 'ServiceAccount') {
    if (saWithWorkload.has(d.id)) return 'actor';  // realistic foothold exists
    if (meta.cloud_role) return 'actor';            // cloud IAM — always relevant
    return 'context';                               // privilege without execution foothold
  }
  // Object categories
  if (d.kind === 'Pod' || d.kind === 'Workload') return 'workload';
  if (d.kind === 'Secret') return 'secret';
  if (['ClusterRole','Role','ClusterRoleBinding','RoleBinding'].includes(d.kind)) return 'privilege';
  if (d.kind === 'Webhook') return 'hook';
  if (d.kind === 'CloudIdentity') return 'target';
  return 'context';
}

// Build goalNodeSet from the backend's risk_findings attack_path data
function buildGoalNodeSetFromFindings(findings) {
  const set = new Set();
  if (!findings) return set;
  findings.forEach(f => {
    // Terminal node of backend attack paths
    const ap = f.attack_path;
    if (ap && ap.length >= 2) {
      const last = ap[ap.length - 1];
      if (last.node && last.node.id) set.add(last.node.id);
    }
    // Any affected node with critical score is also a goal
    if ((f.score || 0) >= 9) {
      (f.affected_nodes || []).forEach(nid => set.add(nid));
    }
  });
  // Always include cluster-admin role
  set.add('clusterrole:cluster-admin');
  return set;
}

// Re-apply category colors/classes after goalNodeSet is updated post-path-computation
function refreshGoalNodeVisuals() {
  if (!nodeSel) return;
  nodeSel.select('circle.node-circle')
    .attr('fill', d => {
      const cat = securityCategory(d);
      return CATEGORY_COLORS[cat] || DEFAULT_NODE_COLOR;
    })
    .attr('class', d => {
      const cat = securityCategory(d);
      return `node-circle cat-${cat}`;
    });
  // Add/remove target rings
  nodeSel.selectAll('circle.target-ring').remove();
  nodeSel.filter(d => securityCategory(d) === 'target').append('circle')
    .attr('class', 'target-ring')
    .attr('r', d => nodeRadius(d) + 5);
}

// Curved path for edge
function edgePath(d) {
  const s = d.source, t = d.target;
  if (!s || !t || s.x == null || t.x == null) return '';
  const dx = t.x - s.x, dy = t.y - s.y;
  const dist = Math.sqrt(dx*dx + dy*dy) || 1;
  const rs = nodeRadius(s), rt = nodeRadius(t);
  // start/end on circle circumferences
  const x1 = s.x + dx/dist * rs;
  const y1 = s.y + dy/dist * rs;
  const x2 = t.x - dx/dist * (rt + 6); // extra gap for arrowhead
  const y2 = t.y - dy/dist * (rt + 6);
  // Slight quadratic curve offset
  const curvature = (d._parallelOffset || 0) * 0.012;
  const mx = (x1+x2)/2 - dy * curvature;
  const my = (y1+y2)/2 + dx * curvature;
  return `M${x1.toFixed(1)},${y1.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`;
}

function renderGraph() {
  linksLayer.selectAll('*').remove();
  nodesLayer.selectAll('*').remove();
  hullLayer.selectAll('*').remove();
  if (simulation) simulation.stop();
  setupFilters();

  const { nodes, edges } = graphData;
  const allNodes = nodes.map(n => ({...n}));

  // ── Display projection: filter namespace-kind nodes out of graph.
  // Namespaces become visual zone regions (hulls), not graph nodes.
  // We keep their data for zone rendering via the namespace property on other nodes.
  const simNodes = allNodes.filter(n => n.kind !== 'Namespace');

  // Normalize edge source/target fields
  const idxMap = {};
  simNodes.forEach((n, i) => { idxMap[n.id] = i; });

  const simEdges = edges.map(e => ({
    ...e,
    source: e.source || e.from,
    target: e.target || e.to,
  })).filter(e => {
    const si = typeof e.source === 'string' ? idxMap[e.source] : null;
    const ti = typeof e.target === 'string' ? idxMap[e.target] : null;
    return si !== undefined && ti !== undefined && si !== null && ti !== null;
  });

  // Resolve string ids to indices for D3
  simEdges.forEach(e => {
    if (typeof e.source === 'string') e.source = idxMap[e.source] ?? e.source;
    if (typeof e.target === 'string') e.target = idxMap[e.target] ?? e.target;
  });

  // Assign parallel edge offsets so curved lines don't overlap
  const pairCount = {};
  simEdges.forEach(e => {
    const si = typeof e.source === 'number' ? e.source : (e.source?.id);
    const ti = typeof e.target === 'number' ? e.target : (e.target?.id);
    const key = `${Math.min(si,ti)}_${Math.max(si,ti)}`;
    if (!pairCount[key]) pairCount[key] = 0;
    e._parallelOffset = pairCount[key];
    pairCount[key] += 20;
  });

  // Classify edge visual style (3-tier: 1=exploitation, 2=privilege, 3=structural)
  function edgeVisualStyle(d) {
    const tier = EDGE_TIER[d.kind] || 2;
    const tgt = typeof d.target === 'object' ? d.target : simNodes[d.target];
    const tgtCat = tgt ? securityCategory(tgt) : 'context';
    const isNodeBreakout = tgt?.kind === 'Node' ||
      (d.kind === 'can_create' && (tgt?.kind === 'Pod' || tgt?.kind === 'Workload'));
    const isSecretExfil = (d.kind === 'can_get' || d.kind === 'can_list') && tgt?.kind === 'Secret';

    // Tier 1: exploitation — full opacity, thick, vivid color
    if (tier === 1) {
      if (isNodeBreakout) return { stroke: '#ff4757', width: '3.3', dash: null, opacity: 1 };
      if (d.inferred)     return { stroke: '#ff79c6', width: '2.8', dash: '5,3', opacity: 0.9 };
      const col = EDGE_COLORS[d.kind] || '#ff7f50';
      return { stroke: col, width: '3.0', dash: null, opacity: 1 };
    }
    // Tier 2: privilege chain — medium opacity, normal width
    if (tier === 2) {
      if (isSecretExfil) return { stroke: '#ffd166', width: '2.4', dash: '6,3', opacity: 0.8 };
      return { stroke: EDGE_COLORS[d.kind] || '#7b6fff', width: '2.3', dash: null, opacity: 0.7 };
    }
    // Tier 3: structural — very subtle, thin
    return { stroke: '#4a4e5a', width: '1.5', dash: null, opacity: 0.15 };
  }

  // Links (paths for curves)
  linkSel = linksLayer.selectAll('path.edge-path')
    .data(simEdges)
    .join('path')
      .attr('class', d => `edge-path${(EDGE_TIER[d.kind]||2) === 3 ? ' tier-3' : ''}`)
      .attr('stroke', d => edgeVisualStyle(d).stroke)
      .attr('stroke-width', d => edgeVisualStyle(d).width)
      .attr('stroke-dasharray', d => edgeVisualStyle(d).dash)
      .attr('opacity', d => edgeVisualStyle(d).opacity)
      .attr('marker-end', d => {
        const st = edgeVisualStyle(d);
        return `url(#${ensureMarker(st.stroke, !!st.dash)})`;
      });

  // Edge hover tooltip + click detail
  linkSel
    .on('mousemove', (event, d) => {
      // Suppress tooltip for edges dimmed out by an active path highlight.
      if (d3.select(event.currentTarget).classed('dimmed')) { hideTooltip(); return; }
      const src = typeof d.source === 'object' ? d.source : simNodes[d.source];
      const tgt = typeof d.target === 'object' ? d.target : simNodes[d.target];
      const sname = src?.name || src?.id || '?';
      const tname = tgt?.name || tgt?.id || '?';
      const tier = EDGE_TIER[d.kind] || 2;
      const tierLabel = tier === 1 ? '⚡ Direct Exploitation' : tier === 2 ? '🔗 Privilege Chain' : '• Structural';
      showTooltip(event, d.kind.replace(/_/g,' '), `${sname} → ${tname}${d.inferred ? ' (inferred)' : ''}\n${tierLabel}`);
    })
    .on('mouseleave', hideTooltip)
    .on('click', (event, d) => {
      event.stopPropagation();
      if (d3.select(event.currentTarget).classed('dimmed')) return;
      hideTooltip();
      const src = typeof d.source === 'object' ? d.source : simNodes[d.source];
      const tgt = typeof d.target === 'object' ? d.target : simNodes[d.target];
      showEdgeDetailPanel(src, tgt, d);
    });

  // Nodes
  nodeSel = nodesLayer.selectAll('g.node-g')
    .data(simNodes, d => d.id)
    .join('g')
      .attr('class', 'node-g')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
        .on('drag',  (e, d) => { d.fx=e.x; d.fy=e.y; })
        .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx=null; d.fy=null; }));

  // Circle (hidden for host nodes — they use diamond polygon instead)
  nodeSel.append('circle')
    .attr('class', d => `node-circle cat-${securityCategory(d)}`)
    .attr('r', d => nodeRadius(d))
    .attr('fill', d => {
      if (d.kind === 'Node') return 'none';  // host: use polygon
      const cat = securityCategory(d);
      const gradMap = {
        actor:     'url(#g-actor)',
        target:    'url(#g-target)',
        workload:  'url(#g-workload)',
        secret:    'url(#g-secret)',
        privilege: 'url(#g-privilege)',
        hook:      'url(#g-hook)',
        context:   'url(#g-context)',
      };
      return gradMap[cat] || DEFAULT_NODE_COLOR;
    })
    .attr('fill-opacity', d => {
      if (d.kind === 'Node') return 0;   // host: invisible circle, polygon renders shape
      return securityCategory(d) === 'context' ? 0.45 : 0.92;
    })
    .attr('stroke-opacity', d => d.kind === 'Node' ? 0 : 1)
    .attr('stroke', d => {
      const cat = securityCategory(d);
      if (cat === 'target')    return 'rgba(255,71,87,.9)';
      if (cat === 'actor')     return 'rgba(76,201,240,.8)';
      if (cat === 'workload')  return 'rgba(46,204,113,.7)';
      if (cat === 'secret')    return 'rgba(241,196,15,.7)';
      if (cat === 'privilege') return 'rgba(155,89,182,.6)';
      if (cat === 'hook')      return 'rgba(255,159,67,.7)';
      return 'rgba(255,255,255,.12)';
    })
    .attr('stroke-width', d => {
      const cat = securityCategory(d);
      if (cat === 'target') return 2.5;
      if (cat === 'actor')  return 2;
      return 1.5;
    })
    .attr('filter', d => {
      if (d.kind === 'Node') return null;  // filter applied to polygon
      if ((d.risk_score||0) >= 8) return 'url(#glow-crit)';
      if ((d.risk_score||0) >= 6) return 'url(#glow-high)';
      return null;
    })
    .on('click', (e, d) => { e.stopPropagation(); selectNode(d.id); })
    .on('mousemove', (e, d) => {
      // Suppress tooltip for nodes dimmed out by an active path highlight.
      if (d3.select(e.currentTarget).classed('dimmed')) { hideTooltip(); return; }
      const score = (d.risk_score||0).toFixed(1);
      const sev = score>=8?'CRITICAL':score>=6?'HIGH':score>=4?'MEDIUM':'LOW';
      let extra = '';
      if (d.kind === 'ServiceAccount') {
        if (saWithWorkload.has(d.id)) {
          const privFlag = saWithPrivilegedWorkload.has(d.id) ? ' (privileged workload)' : '';
          extra = `\nFoothold: used by running workload(s)${privFlag}`;
        } else {
          extra = '\nFoothold: no running workloads — privilege without execution context';
        }
      } else if (d.kind === 'Pod' || d.kind === 'Workload') {
        extra = '\nRole: attacker foothold';
      }
      showTooltip(e, `${d.kind}: ${d.name||d.id}`,
        `Namespace: ${d.namespace||'(cluster)'}\nRisk Score: ${score}/10 (${sev})${extra}`);
    })
    .on('mouseleave', hideTooltip);

  // Diamond polygon for Kubernetes Node (Linux host / machine layer)
  nodeSel.filter(d => d.kind === 'Node').append('polygon')
    .attr('class', 'host-shape')
    .attr('points', d => {
      const r = nodeRadius(d);
      const rw = r * 1.1, rh = r * 1.4;
      return `0,${-rh} ${rw},0 0,${rh} ${-rw},0`;
    })
    .attr('fill', 'url(#g-target)')
    .attr('fill-opacity', 0.95)
    .attr('stroke', '#ff6070')
    .attr('stroke-width', 2.5)
    .attr('filter', 'url(#glow-crit)')
    .on('click', (e, d) => { e.stopPropagation(); selectNode(d.id); })
    .on('mousemove', (e, d) => {
      const score = (d.risk_score||0).toFixed(1);
      showTooltip(e, `Host Node: ${d.name||d.id}`,
        `Linux machine — breakout target\nRisk Score: ${score}/10`);
    })
    .on('mouseleave', hideTooltip);

  // Risk score ring (arc around node proportional to score, for score >= 4)
  nodeSel.filter(d => (d.risk_score||0) >= 4).append('circle')
    .attr('class', 'score-ring')
    .attr('r', d => nodeRadius(d) + 3.5)
    .attr('fill', 'none')
    .attr('stroke-width', d => (d.risk_score||0) >= 8 ? 2.5 : 1.8)
    .attr('stroke', d => {
      const s = d.risk_score||0;
      return s >= 8 ? '#ff4757' : s >= 6 ? '#ff7f50' : '#ffd166';
    })
    .attr('stroke-dasharray', d => {
      const r = nodeRadius(d) + 3.5;
      const circ = 2 * Math.PI * r;
      const pct  = Math.min((d.risk_score||0) / 10, 1);
      return `${(pct * circ).toFixed(1)} ${circ.toFixed(1)}`;
    })
    .attr('transform', 'rotate(-90)')  // start arc from top
    .attr('stroke-linecap', 'round')
    .attr('opacity', 0.85);

  // Target halo — pulsing dashed ring for goal nodes
  nodeSel.filter(d => securityCategory(d) === 'target').append('circle')
    .attr('class', 'target-ring')
    .attr('r', d => nodeRadius(d) + 5);

  // Persistent score badge (floating text above node for score >= 7)
  nodeSel.filter(d => (d.risk_score||0) >= 7).append('text')
    .attr('class', 'score-badge-text')
    .attr('dy', d => -(nodeRadius(d) + 9))
    .attr('text-anchor', 'middle')
    .attr('font-size', '8.5px')
    .attr('font-weight', '800')
    .attr('letter-spacing', '-.3px')
    .attr('stroke', '#13141a')
    .attr('stroke-width', '3')
    .attr('paint-order', 'stroke fill')
    .attr('fill', d => (d.risk_score||0) >= 8 ? '#ff4757' : '#ff7f50')
    .attr('pointer-events', 'none')
    .text(d => (d.risk_score||0).toFixed(1));

  // Icon text
  nodeSel.append('text')
    .attr('class', 'node-icon')
    .attr('font-size', d => {
      const r = nodeRadius(d);
      return r > 16 ? '12px' : r > 12 ? '10px' : '8.5px';
    })
    .attr('fill', '#fff')
    .attr('opacity', 0.95)
    .attr('stroke', 'rgba(0,0,0,.3)')
    .attr('stroke-width', '0.5')
    .attr('paint-order', 'stroke fill')
    .text(d => NODE_ICONS[d.kind] || '?');

  // Special annotation badges for dangerous configs
  nodeSel.filter(d => nodeHasSpecialConfig(d)).append('text')
    .attr('class', 'node-annotation')
    .attr('dx', d => nodeRadius(d) - 1)
    .attr('dy', d => -(nodeRadius(d) - 1))
    .attr('font-size', '10px')
    .attr('fill', '#fff')
    .attr('filter', 'drop-shadow(0 0 3px rgba(255,100,0,.7))')
    .text(d => nodeSpecialIcon(d));

  // Label (shown based on security category; context nodes are silent)
  nodeSel.append('text')
    .attr('class', 'node-label')
    .attr('dy', d => nodeRadius(d) + 14)
    .attr('text-anchor', 'middle')
    .attr('fill', d => {
      const cat = securityCategory(d);
      if (cat === 'target')    return '#ff9aa5';
      if (cat === 'actor')     return '#5dd2f5';
      if (cat === 'workload')  return '#6ee898';
      if (cat === 'secret')    return '#f5de60';
      if (cat === 'privilege') return '#c0a0e0';
      if (cat === 'hook')      return '#ffbc60';
      return '#8892a0';
    })
    .attr('font-size', d => {
      const cat = securityCategory(d);
      return cat === 'target' ? '10.5px' : cat === 'actor' ? '10px' : '9px';
    })
    .attr('font-weight', d => {
      const cat = securityCategory(d);
      return cat === 'target' ? '700' : cat === 'actor' ? '600' : '500';
    })
    .attr('stroke', 'rgba(13,14,20,.85)')
    .attr('stroke-width', '3')
    .attr('paint-order', 'stroke fill')
    .text(d => {
      const cat = securityCategory(d);
      if (cat === 'context') return '';  // suppress namespace/configmap labels
      const nm = d.name || d.id || '';
      // Show "kind: name" for targets to make them immediately understandable
      if (cat === 'target' && d.kind && d.name) {
        const short = d.name.length > 18 ? d.name.slice(0,16)+'…' : d.name;
        return short;
      }
      return nm.length > 22 ? nm.slice(0,20)+'…' : nm;
    });

  // Simulation setup
  const W = canvasWrap.clientWidth;
  const H = canvasWrap.clientHeight;
  const nodeCount = simNodes.length;
  const alphaDecay = nodeCount > 500 ? 0.1 : nodeCount > 200 ? 0.045 : 0.024;
  // More negative charge = nodes spread out more, fewer overlaps, easier to read
  const chargeStr  = nodeCount > 500 ? -180 : nodeCount > 200 ? -280 : -380;

  // Y-layer targets: workloads/pods at top, hosts at bottom, RBAC in middle.
  // Using a weak forceY nudge so the layout is guided but not rigid.
  const yLayerTarget = d => {
    if (d.kind === 'Pod' || d.kind === 'Workload') return H * 0.15;
    if (d.kind === 'Node') return H * 0.85;
    if (d.kind === 'CloudIdentity') return H * 0.75;
    if (d.kind === 'ClusterRole' || d.kind === 'Role' ||
        d.kind === 'ClusterRoleBinding' || d.kind === 'RoleBinding') return H * 0.55;
    return H * 0.4;
  };

  simulation = d3.forceSimulation(simNodes)
    .force('link',    d3.forceLink(simEdges).id((_,i) => i)
      .distance(d => (EDGE_TIER[d.kind]||2) === 1 ? 150 : (EDGE_TIER[d.kind]||2) === 3 ? 70 : 110)
      .strength(d => (EDGE_TIER[d.kind]||2) === 3 ? 0.12 : 0.35))
    .force('charge',  d3.forceManyBody().strength(chargeStr).distanceMax(500))
    .force('center',  d3.forceCenter(W/2, H/2).strength(0.04))
    .force('y',       d3.forceY().y(yLayerTarget).strength(nodeCount > 200 ? 0.18 : 0.14))
    .force('collide', d3.forceCollide().radius(d => nodeRadius(d) + 12).iterations(3))
    .alphaDecay(alphaDecay)
    .on('tick', ticked);

  // Show loading until simulation settles
  showLoading('Simulating layout…', 50);

  // Zoom
  zoomBehavior = d3.zoom()
    .scaleExtent([0.03, 10])
    .on('zoom', e => {
      currentTransform = e.transform;
      zoomLayer.attr('transform', e.transform);
      updateMinimapViewport();
      // LOD: hide/show labels based on zoom level
      const k = e.transform.k;
      nodesLayer.selectAll('text.node-label').attr('display', k < 0.45 ? 'none' : null);
      // Edge mid-labels only shown for selected node — don't force-show them on zoom
    });
  svg.call(zoomBehavior);
  svg.on('click', () => { clearSelection(); clearPathHighlight(); });

  function ticked() {
    linkSel.attr('d', edgePath);
    nodeSel.attr('transform', d => `translate(${d.x?.toFixed(1)||0},${d.y?.toFixed(1)||0})`);

    // Update position map for minimap
    simNodes.forEach(n => { nodePosMap[n.id] = {x: n.x, y: n.y, kind: n.kind, risk: n.risk_score||0}; });
    updateMinimapViewport();
  }

  // Namespace zones — always render (namespace nodes filtered out of graph, shown as zones)
  const onSimEnd = () => {
    hideLoading();
    updateMinimap();
    renderNamespaceZones(simNodes);
  };
  simulation.on('end', onSimEnd);

  // Clusters (namespace hulls - legacy toggle support)
  if (showClusters) renderNamespaceZones(simNodes);

  // Store simNodes reference for path highlighting
  svg._simNodes = simNodes;
  svg._simEdges = simEdges;
}

/* ================================================================
   NAMESPACE ZONE RENDERING
   Namespace nodes are not rendered as graph nodes. Instead they are
   shown as visual zone regions (filled hulls) that enclose the
   namespaced resources (pods, SAs, workloads, secrets, etc.).
   ================================================================ */

// Stable hue per namespace name so colors are deterministic across reloads
function nsHue(ns) {
  let h = 5381;
  for (let i = 0; i < ns.length; i++) h = (h * 33 + ns.charCodeAt(i)) & 0xffff;
  return h % 360;
}

function renderNamespaceZones(simNodes) {
  if (!showClusters) { hullLayer.selectAll('*').remove(); return; }
  hullLayer.selectAll('*').remove();

  const nsByNs = d3.group(simNodes.filter(n => n.namespace && n.x != null), n => n.namespace);

  nsByNs.forEach((nodes, ns) => {
    if (nodes.length < 1) return;
    const pts = nodes.map(n => [n.x, n.y]);

    // Pad single nodes or collinear points to form a valid hull
    const padded = [];
    const extra = 28;
    pts.forEach(([px, py]) => {
      padded.push([px-extra, py-extra],[px+extra, py-extra],
                  [px+extra, py+extra],[px-extra, py+extra]);
    });
    const hull = d3.polygonHull(padded);
    if (!hull) return;

    const c = d3.polygonCentroid(hull);
    const margin = 22;
    const expanded = hull.map(([px, py]) => {
      const dx = px - c[0], dy = py - c[1];
      const len = Math.sqrt(dx*dx+dy*dy)||1;
      return [px + dx/len*margin, py + dy/len*margin];
    });

    const pathStr = 'M' + expanded.map(p => p.join(',')).join('L') + 'Z';
    const hue = nsHue(ns);
    const zoneColor = `hsl(${hue},55%,55%)`;

    hullLayer.append('path')
      .attr('class', 'ns-zone')
      .attr('d', pathStr)
      .attr('fill', zoneColor)
      .attr('stroke', zoneColor);

    // Label: find topmost point of expanded hull and place label above it
    const minY = Math.min(...expanded.map(p => p[1]));
    hullLayer.append('text')
      .attr('class', 'ns-label')
      .attr('x', c[0])
      .attr('y', minY - 6)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('fill', zoneColor)
      .text(ns);
  });
}

// Legacy renderHulls shim (kept for cluster-btn toggle handler)
function renderHulls(nodes) { renderNamespaceZones(nodes); }

/* ================================================================
   MINIMAP
   ================================================================ */
let minimapInitialized = false;

function updateMinimap() {
  const positions = Object.values(nodePosMap);
  if (!positions.length) return;

  const mmSvg = d3.select('#minimap-svg');
  const mmW = 140, mmH = 90, pad = 8;

  const xs = positions.map(p => p.x);
  const ys = positions.map(p => p.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const rangeX = (maxX - minX) || 1, rangeY = (maxY - minY) || 1;

  const scaleX = (mmW - pad*2) / rangeX;
  const scaleY = (mmH - pad*2) / rangeY;
  const sc = Math.min(scaleX, scaleY);

  mmSvg.selectAll('circle.mm-node').remove();
  mmSvg.selectAll('circle.mm-node')
    .data(positions)
    .join('circle')
      .attr('class', 'mm-node')
      .attr('cx', d => pad + (d.x - minX) * sc)
      .attr('cy', d => pad + (d.y - minY) * sc)
      .attr('r', d => d.risk > 7 ? 2.5 : 1.5)
      .attr('fill', d => NODE_COLORS[d.kind] || '#555')
      .attr('opacity', 0.7);

  updateMinimapViewport();
}

function updateMinimapViewport() {
  // stub - full minimap viewport tracking requires knowing graph bounding box
}

document.getElementById('minimap').addEventListener('click', () => {
  if (zoomBehavior) {
    svg.transition().duration(500).call(zoomBehavior.transform, d3.zoomIdentity);
    fitGraph();
  }
});
