// Package ai provides the OpenAI integration for generating defensive risk narratives.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	openai "github.com/sashabaranov/go-openai"
	"github.com/hac01/k8scout/pkg/output"
	"go.uber.org/zap"
)

const systemPrompt = `You are a Kubernetes security expert producing a defensive risk assessment report.
You will be given a JSON summary of an enumeration scan of a Kubernetes cluster, including
discovered permissions, RBAC bindings, workload configurations, and risk findings.

Your task:
1. Write a concise executive summary (3-5 sentences) explaining the overall risk posture.
2. Produce a prioritized list of mitigations (numbered, most critical first).
3. Focus exclusively on DEFENSIVE guidance: describe risks and how to harden the cluster.
4. Do NOT include any offensive techniques, exploitation steps, or attack tooling references.
5. Keep language clear enough for both security engineers and platform teams.
6. Reference specific finding IDs (e.g., PRIV-LIST-SECRETS) where relevant.

Respond with valid JSON only:
{
  "summary": "<executive summary>",
  "mitigations": [
    "1. [CRITICAL] <most urgent action>",
    "2. [HIGH] <next action>",
    ...
  ]
}`

// GenerateNarrative calls the OpenAI API and returns an AINarrative.
func GenerateNarrative(
	ctx context.Context,
	apiKey, model string,
	report output.Report,
	log *zap.Logger,
) (*output.AINarrative, error) {
	client := openai.NewClient(apiKey)

	// Build a condensed summary to send — avoid sending the full graph to reduce tokens.
	summary, err := buildCondensedSummary(report)
	if err != nil {
		return nil, fmt.Errorf("building condensed summary: %w", err)
	}

	log.Debug("sending to OpenAI", zap.String("model", model), zap.Int("input_bytes", len(summary)))

	resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: "Analyze this Kubernetes enumeration result:\n\n" + summary},
		},
		Temperature:    0.3,
		ResponseFormat: &openai.ChatCompletionResponseFormat{Type: openai.ChatCompletionResponseFormatTypeJSONObject},
	})
	if err != nil {
		return nil, fmt.Errorf("OpenAI API call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("OpenAI returned no choices")
	}

	content := resp.Choices[0].Message.Content
	log.Debug("OpenAI response received", zap.Int("output_bytes", len(content)))

	var parsed struct {
		Summary     string   `json:"summary"`
		Mitigations []string `json:"mitigations"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil, fmt.Errorf("parsing OpenAI JSON response: %w\ncontent: %s", err, content)
	}

	return &output.AINarrative{
		Summary:     parsed.Summary,
		Mitigations: parsed.Mitigations,
		ModelUsed:   model,
	}, nil
}

// condensedReport is a token-efficient subset of the full report for the AI.
type condensedReport struct {
	Identity   string   `json:"identity"`
	Groups     []string `json:"groups"`
	Findings   []condensedFinding `json:"findings"`
	SSARAllowed []string `json:"ssar_allowed_checks"`
	Stats      map[string]int `json:"cluster_stats"`
}

type condensedFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Score       float64 `json:"score"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Mitigation  string `json:"mitigation"`
}

func buildCondensedSummary(r output.Report) (string, error) {
	cr := condensedReport{
		Identity: r.Identity.Username,
		Groups:   r.Identity.Groups,
		Stats: map[string]int{
			"namespaces":    len(r.ClusterObjects.Namespaces),
			"service_accounts": len(r.ClusterObjects.ServiceAccounts),
			"cluster_roles": len(r.ClusterObjects.ClusterRoles),
			"cluster_role_bindings": len(r.ClusterObjects.ClusterRoleBindings),
			"workloads":     len(r.ClusterObjects.Workloads),
			"pods":          len(r.ClusterObjects.Pods),
			"secrets":       len(r.ClusterObjects.SecretsMeta),
			"nodes":         len(r.ClusterObjects.Nodes),
		},
	}

	// Allowed SSAR checks summary.
	var allowed []string
	for _, c := range r.Permissions.SSARChecks {
		if c.Allowed {
			perm := c.Verb + ":" + c.Resource
			if c.Subresource != "" {
				perm += "/" + c.Subresource
			}
			if c.Namespace != "" {
				perm += "@" + c.Namespace
			}
			allowed = append(allowed, perm)
		}
	}
	cr.SSARAllowed = allowed

	// All findings.
	for _, f := range r.RiskFindings {
		cr.Findings = append(cr.Findings, condensedFinding{
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			Score:       f.Score,
			Title:       f.Title,
			Description: truncate(f.Description, 300),
			Mitigation:  truncate(f.Mitigation, 400),
		})
	}

	b, err := json.MarshalIndent(cr, "", "  ")
	return string(b), err
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
