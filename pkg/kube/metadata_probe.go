package kube

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// probeMetadataEndpoints probes cloud metadata endpoints from within the current pod.
// Only meaningful when running in-cluster. Each endpoint is tested with a short timeout.
func probeMetadataEndpoints(ctx context.Context, log *zap.Logger) []MetadataProbeResult {
	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	result := MetadataProbeResult{}

	// AWS IMDSv1: GET http://169.254.169.254/latest/meta-data/
	result.MetadataV1 = probeURL(ctx, httpClient, "GET", "http://169.254.169.254/latest/meta-data/", nil)
	if result.MetadataV1 {
		log.Warn("AWS IMDSv1 reachable — credential theft possible without token hop")
		result.Provider = "aws"
	}

	// AWS IMDSv2: PUT with TTL header
	result.MetadataV2 = probeURL(ctx, httpClient, "PUT", "http://169.254.169.254/latest/api/token",
		map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
	if result.MetadataV2 && result.Provider == "" {
		result.Provider = "aws"
	}

	// GKE metadata server
	result.GKEMetadata = probeURL(ctx, httpClient, "GET", "http://metadata.google.internal/computeMetadata/v1/",
		map[string]string{"Metadata-Flavor": "Google"})
	if result.GKEMetadata {
		if result.Provider == "" {
			result.Provider = "gcp"
		}
		log.Warn("GKE metadata server reachable — SA token theft possible")
	}

	// Azure IMDS
	result.AzureIMDS = probeURL(ctx, httpClient, "GET",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		map[string]string{"Metadata": "true"})
	if result.AzureIMDS {
		if result.Provider == "" {
			result.Provider = "azure"
		}
		log.Warn("Azure IMDS reachable — managed identity token theft possible")
	}

	if !result.MetadataV1 && !result.MetadataV2 && !result.GKEMetadata && !result.AzureIMDS {
		return nil
	}

	return []MetadataProbeResult{result}
}

func probeURL(ctx context.Context, client *http.Client, method, url string, headers map[string]string) bool {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return false
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
