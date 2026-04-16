package kube

import (
	"context"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// capabilityTiers maps dangerous Linux capabilities to their risk tier for granular scoring.
// CRITICAL: direct kernel or credential access; HIGH: strong introspection / raw I/O;
// MEDIUM: network manipulation.
var capabilityTiers = map[corev1.Capability]string{
	"SYS_MODULE":      "CRITICAL",
	"SYS_ADMIN":       "CRITICAL",
	"DAC_READ_SEARCH": "CRITICAL",
	"SYS_PTRACE":      "HIGH",
	"SYS_RAWIO":       "HIGH",
	"NET_ADMIN":       "MEDIUM",
	"NET_RAW":         "MEDIUM",
}

var sensitiveEnvPatterns = []string{
	"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
	"apitoken", "access_key", "secret_key", "aws_access", "aws_secret",
	"private_key", "auth_token", "bearer", "credential", "client_secret",
	"database_url", "jdbc_url", "mongo_uri", "redis_url", "connection_string",
	"ssh_private", "github_token", "slack_token", "slack_webhook",
	"encryption_key", "signing_key", "master_key",
}

// collectWorkloads gathers Deployments, DaemonSets, StatefulSets, Jobs, and CronJobs.
func collectWorkloads(ctx context.Context, c *Client, ns string, log *zap.Logger) ([]WorkloadInfo, error) {
	cs := c.Clientset()
	var workloads []WorkloadInfo

	// ── Deployments ───────────────────────────────────────────────────────────
	deploys, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list Deployments", zap.String("namespace", ns), zap.Error(err))
	} else {
		for _, d := range deploys.Items {
			wi := podSpecToWorkloadInfo("Deployment", d.Name, ns, d.Labels, d.Spec.Replicas, d.Spec.Template.Spec)
			workloads = append(workloads, wi)
		}
	}

	// ── DaemonSets ────────────────────────────────────────────────────────────
	dsets, err := cs.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list DaemonSets", zap.String("namespace", ns), zap.Error(err))
	} else {
		for _, d := range dsets.Items {
			wi := podSpecToWorkloadInfo("DaemonSet", d.Name, ns, d.Labels, nil, d.Spec.Template.Spec)
			workloads = append(workloads, wi)
		}
	}

	// ── StatefulSets ──────────────────────────────────────────────────────────
	ssets, err := cs.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list StatefulSets", zap.String("namespace", ns), zap.Error(err))
	} else {
		for _, s := range ssets.Items {
			wi := podSpecToWorkloadInfo("StatefulSet", s.Name, ns, s.Labels, s.Spec.Replicas, s.Spec.Template.Spec)
			workloads = append(workloads, wi)
		}
	}

	// ── Jobs ──────────────────────────────────────────────────────────────────
	jobs, err := cs.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list Jobs", zap.String("namespace", ns), zap.Error(err))
	} else {
		for _, j := range jobs.Items {
			wi := podSpecToWorkloadInfo("Job", j.Name, ns, j.Labels, nil, j.Spec.Template.Spec)
			workloads = append(workloads, wi)
		}
	}

	// ── CronJobs ──────────────────────────────────────────────────────────────
	cjobs, err := cs.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list CronJobs", zap.String("namespace", ns), zap.Error(err))
	} else {
		for _, cj := range cjobs.Items {
			wi := podSpecToWorkloadInfo("CronJob", cj.Name, ns, cj.Labels, nil, cj.Spec.JobTemplate.Spec.Template.Spec)
			workloads = append(workloads, wi)
		}
	}

	return workloads, nil
}

// collectPods gathers running pod metadata (no data values).
func collectPods(ctx context.Context, c *Client, ns string, log *zap.Logger) ([]PodInfo, error) {
	cs := c.Clientset()
	list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	pods := make([]PodInfo, 0, len(list.Items))
	for _, p := range list.Items {
		pi := PodInfo{
			Name:             p.Name,
			Namespace:        ns,
			Node:             p.Spec.NodeName,
			ServiceAccount:   p.Spec.ServiceAccountName,
			Phase:            string(p.Status.Phase),
			HostPID:          p.Spec.HostPID,
			HostNetwork:      p.Spec.HostNetwork,
			HostIPC:          p.Spec.HostIPC,
			Labels:           redactLabels(p.Labels),
			AutomountSAToken: p.Spec.AutomountServiceAccountToken,
		}

		// Resolve controlling workload from owner references.
		// ReplicaSet pods strip the RS hash to recover the Deployment name.
		for _, ref := range p.OwnerReferences {
			if ref.Controller != nil && !*ref.Controller {
				continue
			}
			kind, name := ref.Kind, ref.Name
			if kind == "ReplicaSet" {
				kind = "Deployment"
				if idx := lastNthIndex(name, '-', 2); idx > 0 {
					name = name[:idx]
				}
			}
			pi.OwnerKind = kind
			pi.OwnerName = name
			break
		}

		// Container security contexts.
		for _, ctr := range append(p.Spec.InitContainers, p.Spec.Containers...) {
			pi.ImageNames = append(pi.ImageNames, ctr.Image)
			if ctr.SecurityContext != nil && ctr.SecurityContext.Privileged != nil && *ctr.SecurityContext.Privileged {
				pi.PrivilegedContainers = append(pi.PrivilegedContainers, ctr.Name)
			}
			if ctr.SecurityContext != nil && ctr.SecurityContext.Capabilities != nil {
				hasDangerous := false
				for _, cap := range ctr.SecurityContext.Capabilities.Add {
					if tier, ok := capabilityTiers[cap]; ok {
						pi.CapabilityDetails = append(pi.CapabilityDetails, CapabilityDetail{
							Container: ctr.Name,
							Cap:       string(cap),
							Tier:      tier,
						})
						hasDangerous = true
					}
				}
				if hasDangerous {
					pi.DangerousCapabilities = append(pi.DangerousCapabilities, ctr.Name)
				}
			}
			// Detect plaintext secrets hardcoded in env var values.
			for _, ev := range ctr.Env {
				if ev.ValueFrom != nil || ev.Value == "" {
					continue
				}
				lower := strings.ToLower(ev.Name)
				for _, pat := range sensitiveEnvPatterns {
					if strings.Contains(lower, pat) {
						pi.PlaintextEnvVars = append(pi.PlaintextEnvVars, PlaintextEnvVar{
							Container: ctr.Name,
							EnvName:   ev.Name,
							Pattern:   pat,
							Value:     ev.Value,
						})
						break
					}
				}
			}
		}

		// Volumes (metadata only).
		// Build a set of volume names mounted read-only in all containers.
		roVolumes := make(map[string]bool)
		for _, ctr := range append(p.Spec.InitContainers, p.Spec.Containers...) {
			for _, vm := range ctr.VolumeMounts {
				if vm.ReadOnly {
					roVolumes[vm.Name] = true
				}
			}
		}
		for _, v := range p.Spec.Volumes {
			vr := extractVolumeRef(v)
			pi.Volumes = append(pi.Volumes, vr)
			if vr.SourceKind == "HostPath" {
				pi.HostPathMounts = append(pi.HostPathMounts, vr.HostPath)
				if roVolumes[v.Name] {
					pi.ReadOnlyHostPaths = append(pi.ReadOnlyHostPaths, vr.HostPath)
				}
			}
		}

		pods = append(pods, pi)
	}
	return pods, nil
}

// collectNamespaces returns namespace metadata.
func collectNamespaces(ctx context.Context, c *Client, log *zap.Logger) ([]NSInfo, error) {
	nsList, err := c.GetNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]NSInfo, 0, len(nsList))
	for _, ns := range nsList {
		result = append(result, NSInfo{
			Name:   ns.Name,
			Status: string(ns.Status.Phase),
			Labels: redactLabels(ns.Labels),
		})
	}
	return result, nil
}

// collectSecretsMeta lists Secret metadata. When captureValues is true (GET permission confirmed),
// the actual decoded secret values are included in SecretMeta.Values for authorized assessment.
func collectSecretsMeta(ctx context.Context, c *Client, ns string, captureValues bool, log *zap.Logger) ([]SecretMeta, error) {
	cs := c.Clientset()
	list, err := cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	result := make([]SecretMeta, 0, len(list.Items))
	for _, s := range list.Items {
		sm := SecretMeta{
			Name:      s.Name,
			Namespace: ns,
			Type:      string(s.Type),
			Labels:    redactLabels(s.Labels),
		}
		// For SA token secrets, capture the owning SA name from the annotation.
		if s.Type == corev1.SecretTypeServiceAccountToken {
			if saName, ok := s.Annotations["kubernetes.io/service-account.name"]; ok {
				sm.SAName = saName
			}
		}
		for k := range s.Data {
			sm.DataKeys = append(sm.DataKeys, k)
		}
		if captureValues && len(s.Data) > 0 {
			sm.Values = make(map[string]string, len(s.Data))
			for k, v := range s.Data {
				sm.Values[k] = string(v)
			}
		}
		result = append(result, sm)
	}
	return result, nil
}

// collectConfigMapsMeta lists ConfigMap metadata. When captureValues is true (GET permission confirmed),
// the actual configmap data is included in CMeta.Data for authorized assessment.
func collectConfigMapsMeta(ctx context.Context, c *Client, ns string, captureValues bool, log *zap.Logger) ([]CMeta, error) {
	cs := c.Clientset()
	list, err := cs.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	result := make([]CMeta, 0, len(list.Items))
	for _, cm := range list.Items {
		meta := CMeta{
			Name:      cm.Name,
			Namespace: ns,
			Labels:    redactLabels(cm.Labels),
		}
		for k := range cm.Data {
			meta.DataKeys = append(meta.DataKeys, k)
		}
		if captureValues && len(cm.Data) > 0 {
			meta.Data = make(map[string]string, len(cm.Data))
			for k, v := range cm.Data {
				meta.Data[k] = v
			}
		}
		result = append(result, meta)
	}
	return result, nil
}

// collectNodes gathers node metadata without sensitive data.
func collectNodes(ctx context.Context, c *Client, log *zap.Logger) ([]NodeInfo, error) {
	cs := c.Clientset()
	list, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	result := make([]NodeInfo, 0, len(list.Items))
	for _, n := range list.Items {
		ni := NodeInfo{
			Name:   n.Name,
			Labels: redactLabels(n.Labels),
			Roles:  nodeRoles(n.Labels),
		}
		for _, t := range n.Spec.Taints {
			ni.Taints = append(ni.Taints, t.Key+"="+string(t.Effect))
		}
		ni.Capacity = map[string]string{
			"cpu":    n.Status.Capacity.Cpu().String(),
			"memory": n.Status.Capacity.Memory().String(),
		}
		for _, addr := range n.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				ni.InternalIPs = append(ni.InternalIPs, addr.Address)
			}
		}
		result = append(result, ni)
	}
	return result, nil
}

// podSpecToWorkloadInfo converts a PodSpec into a WorkloadInfo (no data values).
func podSpecToWorkloadInfo(kind, name, ns string, labels map[string]string, replicas *int32, spec corev1.PodSpec) WorkloadInfo {
	wi := WorkloadInfo{
		Kind:             kind,
		Name:             name,
		Namespace:        ns,
		Labels:           redactLabels(labels),
		Replicas:         replicas,
		ServiceAccount:   spec.ServiceAccountName,
		HostPID:          spec.HostPID,
		HostIPC:          spec.HostIPC,
		HostNetwork:      spec.HostNetwork,
		AutomountSAToken: spec.AutomountServiceAccountToken,
	}

	for _, ctr := range append(spec.InitContainers, spec.Containers...) {
		wi.ImageNames = append(wi.ImageNames, ctr.Image)
		if ctr.SecurityContext != nil && ctr.SecurityContext.Privileged != nil && *ctr.SecurityContext.Privileged {
			wi.PrivilegedContainers = append(wi.PrivilegedContainers, ctr.Name)
		}
		if ctr.SecurityContext != nil && ctr.SecurityContext.Capabilities != nil {
			hasDangerous := false
			for _, cap := range ctr.SecurityContext.Capabilities.Add {
				if tier, ok := capabilityTiers[cap]; ok {
					wi.CapabilityDetails = append(wi.CapabilityDetails, CapabilityDetail{
						Container: ctr.Name,
						Cap:       string(cap),
						Tier:      tier,
					})
					hasDangerous = true
				}
			}
			if hasDangerous {
				wi.DangerousCapabilities = append(wi.DangerousCapabilities, ctr.Name)
			}
		}
		// Collect secret references from env vars (key names only — no values).
		for _, ev := range ctr.Env {
			if ev.ValueFrom != nil && ev.ValueFrom.SecretKeyRef != nil {
				wi.EnvSecretRefs = append(wi.EnvSecretRefs, EnvSecretRef{
					Container:  ctr.Name,
					SecretName: ev.ValueFrom.SecretKeyRef.Name,
					SecretKey:  ev.ValueFrom.SecretKeyRef.Key,
					EnvVar:     ev.Name,
				})
			}
		}
		// Collect secret references from envFrom (all keys injected as env vars).
		for _, ef := range ctr.EnvFrom {
			if ef.SecretRef != nil {
				wi.EnvSecretRefs = append(wi.EnvSecretRefs, EnvSecretRef{
					Container:  ctr.Name,
					SecretName: ef.SecretRef.Name,
				})
			}
		}
		// Detect plaintext secrets hardcoded in env var values (no ValueFrom reference).
		for _, ev := range ctr.Env {
			if ev.ValueFrom != nil || ev.Value == "" {
				continue
			}
			lower := strings.ToLower(ev.Name)
			for _, pat := range sensitiveEnvPatterns {
				if strings.Contains(lower, pat) {
					wi.PlaintextEnvVars = append(wi.PlaintextEnvVars, PlaintextEnvVar{
						Container: ctr.Name,
						EnvName:   ev.Name,
						Pattern:   pat,
						Value:     ev.Value,
					})
					break
				}
			}
		}
	}

	// Build a set of volume names mounted read-only in all containers.
	roVols := make(map[string]bool)
	for _, ctr := range append(spec.InitContainers, spec.Containers...) {
		for _, vm := range ctr.VolumeMounts {
			if vm.ReadOnly {
				roVols[vm.Name] = true
			}
		}
	}
	for _, v := range spec.Volumes {
		vr := extractVolumeRef(v)
		wi.Volumes = append(wi.Volumes, vr)
		if vr.SourceKind == "HostPath" {
			wi.HostPathMounts = append(wi.HostPathMounts, vr.HostPath)
			if roVols[v.Name] {
				wi.ReadOnlyHostPaths = append(wi.ReadOnlyHostPaths, vr.HostPath)
			}
		}
	}

	return wi
}

// extractVolumeRef converts a k8s Volume into our VolumeRef (metadata only).
func extractVolumeRef(v corev1.Volume) VolumeRef {
	vr := VolumeRef{Name: v.Name}
	switch {
	case v.Secret != nil:
		vr.SourceKind = "Secret"
		vr.SourceName = v.Secret.SecretName
	case v.ConfigMap != nil:
		vr.SourceKind = "ConfigMap"
		vr.SourceName = v.ConfigMap.Name
	case v.HostPath != nil:
		vr.SourceKind = "HostPath"
		vr.HostPath = v.HostPath.Path
	case v.EmptyDir != nil:
		vr.SourceKind = "EmptyDir"
	case v.PersistentVolumeClaim != nil:
		vr.SourceKind = "PVC"
		vr.SourceName = v.PersistentVolumeClaim.ClaimName
	case v.Projected != nil:
		vr.SourceKind = "Projected"
		// Detect serviceAccountToken projections with non-default audiences.
		for _, src := range v.Projected.Sources {
			if src.ServiceAccountToken != nil && src.ServiceAccountToken.Audience != "" {
				aud := src.ServiceAccountToken.Audience
				// Skip the default kubernetes audience values.
				if aud != "kubernetes" && aud != "kubernetes.default" && aud != "kubernetes.default.svc" {
					vr.Audience = aud
				}
			}
		}
	default:
		vr.SourceKind = "Other"
	}
	return vr
}

// lastNthIndex returns the index of the nth-from-last occurrence of sep in s,
// or -1 if there are fewer than n occurrences. Used to strip ReplicaSet hash suffixes.
func lastNthIndex(s string, sep byte, n int) int {
	idx := len(s)
	for i := 0; i < n; i++ {
		found := strings.LastIndexByte(s[:idx], sep)
		if found < 0 {
			return -1
		}
		idx = found
	}
	return idx
}
