// Package defense provides defensive security monitoring data contracts.
// Designed for integration with eBPF-based tools like secrets-snitcher.
package defense

import "time"

// SecretAccessEvent records a secret access detected by eBPF monitoring.
type SecretAccessEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	PodName     string    `json:"pod_name"`
	Namespace   string    `json:"namespace"`
	SecretName  string    `json:"secret_name"`
	SecretKey   string    `json:"secret_key,omitempty"`
	ProcessName string    `json:"process_name"`
	PID         int       `json:"pid"`
	UID         int       `json:"uid"`
	Suspicious  bool      `json:"suspicious"`
	Reason      string    `json:"reason,omitempty"`
}

// DefenseReport contains all defensive monitoring data.
type DefenseReport struct {
	SecretAccesses  []SecretAccessEvent `json:"secret_accesses,omitempty"`
	SuspiciousPods  []SuspiciousPod     `json:"suspicious_pods,omitempty"`
	RuntimeFindings []RuntimeFinding    `json:"runtime_findings,omitempty"`
}

// SuspiciousPod describes a pod flagged by runtime monitoring.
type SuspiciousPod struct {
	PodName   string   `json:"pod_name"`
	Namespace string   `json:"namespace"`
	Reasons   []string `json:"reasons"`
	Score     float64  `json:"score"`
}

// RuntimeFinding describes a security-relevant runtime event.
type RuntimeFinding struct {
	Timestamp   time.Time `json:"timestamp"`
	PodName     string    `json:"pod_name"`
	Namespace   string    `json:"namespace"`
	Category    string    `json:"category"`    // "secret_access", "network_anomaly", "process_anomaly"
	Description string    `json:"description"`
	Severity    string    `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW
}

// SecretSnitcherConfig describes the configuration for secrets-snitcher eBPF integration.
type SecretSnitcherConfig struct {
	EventSocket string `json:"event_socket,omitempty"` // Unix socket or TCP endpoint
	EventFile   string `json:"event_file,omitempty"`   // File path for event log
	Enabled     bool   `json:"enabled"`
}
