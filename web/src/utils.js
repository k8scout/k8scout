// utils.js
// Shared utility functions used across all modules

function edgeNodeId(val) {
  if (!val) return null;
  if (typeof val === 'object') return val.id;
  return val;
}

/* ================================================================
   UTILITIES
   ================================================================ */
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

window.expandSection = function(btn) {
  const section = btn.closest('.detail-section');
  section.querySelectorAll('.conn-extra').forEach(el => {
    el.style.display = '';
    el.classList.remove('conn-extra');
  });
  btn.style.display = 'none';
};

/* ================================================================
   LOADING HELPERS
   ================================================================ */
function showLoading(text, pct) {
  loadingText.textContent = text;
  progressFill.style.width = (pct||0) + '%';
  loadingOverlay.classList.add('visible');
}
function hideLoading() { loadingOverlay.classList.remove('visible'); }
function nextFrame() { return new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); }

