package kube

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// probeKubeletReadOnly attempts an unauthenticated GET to port 10255 (/healthz) on each
// node's internal IP. Port 10255 is the kubelet read-only HTTP port — when open it exposes
// pod metadata, environment variables, and volume mounts without any credentials.
//
// This probe is only appropriate in offensive mode (running inside the cluster) since the
// kubelet port is only reachable from within the pod network.
func probeKubeletReadOnly(ctx context.Context, nodes []NodeInfo, log *zap.Logger) []KubeletProbeResult {
	if len(nodes) == 0 {
		return nil
	}

	type probeJob struct {
		nodeName string
		ip       string
	}

	var jobs []probeJob
	for _, n := range nodes {
		for _, ip := range n.InternalIPs {
			jobs = append(jobs, probeJob{nodeName: n.Name, ip: ip})
			break // one IP per node is enough
		}
	}

	if len(jobs) == 0 {
		log.Debug("kubelet probe: no node IPs available — skipping")
		return nil
	}

	// Reusable HTTP client with a short per-request timeout.
	httpClient := &http.Client{
		Timeout: 3 * time.Second,
		// Do not follow redirects — we only care about the initial response.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type probeResult struct {
		result KubeletProbeResult
	}
	ch := make(chan probeResult, len(jobs))

	for _, j := range jobs {
		go func(j probeJob) {
			url := fmt.Sprintf("http://%s:10255/healthz", j.ip)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				ch <- probeResult{KubeletProbeResult{NodeName: j.nodeName, IP: j.ip, ReadOnlyOpen: false}}
				return
			}
			resp, err := httpClient.Do(req)
			open := false
			if err == nil {
				resp.Body.Close()
				open = resp.StatusCode == http.StatusOK
			}
			ch <- probeResult{KubeletProbeResult{NodeName: j.nodeName, IP: j.ip, ReadOnlyOpen: open}}
		}(j)
	}

	var results []KubeletProbeResult
	for range jobs {
		r := <-ch
		results = append(results, r.result)
		if r.result.ReadOnlyOpen {
			log.Warn("kubelet read-only port open",
				zap.String("node", r.result.NodeName),
				zap.String("ip", r.result.IP),
				zap.Int("port", 10255))
		}
	}
	return results
}
