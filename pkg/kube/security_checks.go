package kube

import (
	"fmt"
	"strings"
)

// AnalyzePodSecurity checks workloads and running pods for security misconfigurations.
// It inspects pod spec metadata only — it never reads secret values or environment variable data.
func AnalyzePodSecurity(workloads []WorkloadInfo, pods []PodInfo) []PodSecurityIssue {
	var findings []PodSecurityIssue

	for _, wl := range workloads {
		issues := workloadSecurityIssues(wl)
		if len(issues) > 0 {
			findings = append(findings, PodSecurityIssue{
				Namespace:    wl.Namespace,
				WorkloadKind: wl.Kind,
				WorkloadName: wl.Name,
				Issues:       issues,
				Severity:     podIssueSeverity(issues),
			})
		}
	}

	// Check standalone pods for issues not already covered by workload analysis.
	for _, pod := range pods {
		issues := podOnlySecurityIssues(pod)
		if len(issues) > 0 {
			findings = append(findings, PodSecurityIssue{
				Namespace:    pod.Namespace,
				WorkloadKind: "Pod",
				WorkloadName: pod.Name,
				Issues:       issues,
				Severity:     podIssueSeverity(issues),
			})
		}
	}

	return findings
}

func workloadSecurityIssues(wl WorkloadInfo) []string {
	var issues []string

	for _, c := range wl.PrivilegedContainers {
		issues = append(issues, fmt.Sprintf("container %q: privileged=true (full host capabilities)", c))
	}
	if wl.HostPID {
		issues = append(issues, "hostPID: true — container can observe all host processes")
	}
	if wl.HostIPC {
		issues = append(issues, "hostIPC: true — container can access host IPC namespace (shared memory)")
	}
	if wl.HostNetwork {
		issues = append(issues, "hostNetwork: true — container shares host network stack, bypasses NetworkPolicy")
	}
	for _, hp := range wl.HostPathMounts {
		issues = append(issues, fmt.Sprintf("hostPath mount %q — exposes host filesystem to container", hp))
	}
	if wl.AutomountSAToken == nil {
		issues = append(issues, "automountServiceAccountToken not explicitly disabled — API token injected by default")
	} else if *wl.AutomountSAToken {
		issues = append(issues, "automountServiceAccountToken: true — API token injected into pod")
	}
	for _, img := range wl.ImageNames {
		if isUnpinnedImage(img) {
			issues = append(issues, fmt.Sprintf("image %q uses :latest or has no tag (supply-chain risk)", img))
		}
	}

	return issues
}

// podOnlySecurityIssues catches issues only visible on running pods (hostIPC, privileged) that
// may not appear in workload specs (e.g., standalone pods or pods from controllers we didn't list).
func podOnlySecurityIssues(pod PodInfo) []string {
	var issues []string

	for _, c := range pod.PrivilegedContainers {
		issues = append(issues, fmt.Sprintf("container %q: privileged=true", c))
	}
	if pod.HostIPC {
		issues = append(issues, "hostIPC: true — shares host IPC namespace")
	}
	if pod.HostPID {
		issues = append(issues, "hostPID: true — can observe all host processes")
	}
	if pod.HostNetwork {
		issues = append(issues, "hostNetwork: true — shares host network stack")
	}
	for _, hp := range pod.HostPathMounts {
		issues = append(issues, fmt.Sprintf("hostPath mount %q — exposes host filesystem", hp))
	}

	return issues
}

func podIssueSeverity(issues []string) string {
	for _, iss := range issues {
		lower := strings.ToLower(iss)
		if strings.Contains(lower, "privileged=true") ||
			strings.Contains(lower, "hostpid") ||
			strings.Contains(lower, "hostipc") ||
			strings.Contains(lower, "hostpath") ||
			strings.Contains(lower, "hostnetwork") {
			return "HIGH"
		}
	}
	return "MEDIUM"
}

// isUnpinnedImage returns true for images using :latest or no tag (not digest-pinned).
func isUnpinnedImage(img string) bool {
	// Digest-pinned images (e.g. registry/image@sha256:abc...) are always safe.
	if strings.Contains(img, "@sha256:") {
		return false
	}
	idx := strings.LastIndex(img, ":")
	if idx < 0 {
		return true // no tag at all
	}
	tag := img[idx+1:]
	return tag == "latest" || tag == ""
}
