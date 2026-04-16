// controls.js
// Fit/zoom controls, cross-namespace toggle, search, keyboard shortcuts

/* ================================================================
   FIT / ZOOM CONTROLS
   ================================================================ */
function fitGraph() {
  if (!graphData || !zoomBehavior) return;
  const pts = Object.values(nodePosMap);
  if (!pts.length) return;
  const xs = pts.map(p=>p.x), ys = pts.map(p=>p.y);
  const x0=Math.min(...xs)-30, x1=Math.max(...xs)+30;
  const y0=Math.min(...ys)-30, y1=Math.max(...ys)+30;
  const W=canvasWrap.clientWidth, H=canvasWrap.clientHeight;
  const k=0.9*Math.min(W/(x1-x0||1), H/(y1-y0||1), 2);
  const tx=(W-k*(x0+x1))/2, ty=(H-k*(y0+y1))/2;
  svg.transition().duration(500)
    .call(zoomBehavior.transform, d3.zoomIdentity.translate(tx,ty).scale(k));
}

document.getElementById('fit-btn').addEventListener('click', fitGraph);
document.getElementById('zoom-in-btn').addEventListener('click', () => {
  if (zoomBehavior) svg.transition().duration(200).call(zoomBehavior.scaleBy, 1.4);
});
document.getElementById('zoom-out-btn').addEventListener('click', () => {
  if (zoomBehavior) svg.transition().duration(200).call(zoomBehavior.scaleBy, 0.7);
});
document.getElementById('cluster-btn').addEventListener('click', () => {
  showClusters = !showClusters;
  document.getElementById('cluster-btn').classList.toggle('active', showClusters);
  if (graphData && svg._simNodes) renderNamespaceZones(svg._simNodes);
  else hullLayer.selectAll('*').remove();
});

document.getElementById('crossns-btn').addEventListener('click', () => {
  showCrossNS = !showCrossNS;
  document.getElementById('crossns-btn').classList.toggle('active', showCrossNS);
  if (linkSel) {
    linkSel.attr('stroke', d => {
      if (showCrossNS) {
        const src = typeof d.source === 'object' ? d.source : graphData.nodes[d.source];
        const tgt = typeof d.target === 'object' ? d.target : graphData.nodes[d.target];
        if (src && tgt && src.namespace && tgt.namespace && src.namespace !== tgt.namespace) {
          return '#ff6b35';
        }
      }
      return edgeVisualStyle(d).stroke;
    }).attr('stroke-dasharray', d => {
      if (showCrossNS) {
        const src = typeof d.source === 'object' ? d.source : graphData.nodes[d.source];
        const tgt = typeof d.target === 'object' ? d.target : graphData.nodes[d.target];
        if (src && tgt && src.namespace && tgt.namespace && src.namespace !== tgt.namespace) {
          return '8,4';
        }
      }
      return edgeVisualStyle(d).dash;
    });
  }
});


/* ================================================================
   SEARCH
   ================================================================ */
const searchInput = document.getElementById('search');
searchInput.addEventListener('input', () => {
  const q = searchInput.value.trim().toLowerCase();
  if (!graphData) return;
  if (!q) { clearSelection(); clearPathHighlight(); return; }
  const matches = new Set(
    graphData.nodes.filter(n => (n.name||'').toLowerCase().includes(q) || n.id.toLowerCase().includes(q)).map(n => n.id)
  );
  nodesLayer.selectAll('circle.node-circle')
    .classed('dimmed',      d => !matches.has(d.id))
    .classed('highlighted', d => matches.has(d.id))
    .classed('path-active', false);
  linksLayer.selectAll('path.edge-path').classed('dimmed',true).classed('highlighted',false).classed('path-active',false);
});

/* ================================================================
   KEYBOARD SHORTCUTS
   ================================================================ */
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement !== searchInput) {
    e.preventDefault(); searchInput.focus(); searchInput.select();
  }
  if (e.key === 'Escape') {
    if (document.getElementById('modal-bg').classList.contains('visible')) { closeModal(); return; }
    if (document.getElementById('largefile-bg').classList.contains('visible')) { return; }
    clearSelection(); clearPathHighlight(); searchInput.value = '';
  }
  if (e.key === 'f' || e.key === 'F') {
    if (document.activeElement !== searchInput) fitGraph();
  }
  if (e.key === '+' || e.key === '=') {
    if (zoomBehavior && document.activeElement !== searchInput)
      svg.transition().duration(200).call(zoomBehavior.scaleBy, 1.3);
  }
  if (e.key === '-') {
    if (zoomBehavior && document.activeElement !== searchInput)
      svg.transition().duration(200).call(zoomBehavior.scaleBy, 0.77);
  }
});

