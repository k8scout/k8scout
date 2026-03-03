package kube

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectWebhooks enumerates MutatingWebhookConfigurations and ValidatingWebhookConfigurations.
func collectWebhooks(ctx context.Context, c *Client, log *zap.Logger) ([]WebhookInfo, error) {
	cs := c.Clientset()
	var results []WebhookInfo

	// ── MutatingWebhookConfigurations ─────────────────────────────────────────
	mwcList, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list MutatingWebhookConfigurations (permission may be missing)", zap.Error(err))
	} else {
		for _, mwc := range mwcList.Items {
			for _, wh := range mwc.Webhooks {
				wi := WebhookInfo{
					Name:          mwc.Name + "/" + wh.Name,
					Kind:          "Mutating",
					FailurePolicy: webhookFailurePolicy(wh.FailurePolicy),
					HasNamespaceSelector: wh.NamespaceSelector != nil &&
						(len(wh.NamespaceSelector.MatchLabels) > 0 || len(wh.NamespaceSelector.MatchExpressions) > 0),
				}
				if wh.ClientConfig.Service != nil {
					wi.ServiceName = wh.ClientConfig.Service.Name
					wi.ServiceNS = wh.ClientConfig.Service.Namespace
				}
				if wh.ClientConfig.URL != nil {
					wi.URL = *wh.ClientConfig.URL
				}
				for _, r := range wh.Rules {
					for _, res := range r.Resources {
						ag := "*"
						if len(r.APIGroups) > 0 {
							ag = r.APIGroups[0]
						}
						wi.Rules = append(wi.Rules, fmt.Sprintf("%s/%s", ag, res))
					}
					for _, op := range r.Operations {
						wi.Operations = appendUnique(wi.Operations, string(op))
					}
				}
				results = append(results, wi)
			}
		}
		log.Debug("collected MutatingWebhookConfigurations", zap.Int("count", len(mwcList.Items)))
	}

	// ── ValidatingWebhookConfigurations ───────────────────────────────────────
	vwcList, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list ValidatingWebhookConfigurations (permission may be missing)", zap.Error(err))
	} else {
		for _, vwc := range vwcList.Items {
			for _, wh := range vwc.Webhooks {
				wi := WebhookInfo{
					Name:          vwc.Name + "/" + wh.Name,
					Kind:          "Validating",
					FailurePolicy: webhookFailurePolicy(wh.FailurePolicy),
					HasNamespaceSelector: wh.NamespaceSelector != nil &&
						(len(wh.NamespaceSelector.MatchLabels) > 0 || len(wh.NamespaceSelector.MatchExpressions) > 0),
				}
				if wh.ClientConfig.Service != nil {
					wi.ServiceName = wh.ClientConfig.Service.Name
					wi.ServiceNS = wh.ClientConfig.Service.Namespace
				}
				if wh.ClientConfig.URL != nil {
					wi.URL = *wh.ClientConfig.URL
				}
				for _, r := range wh.Rules {
					for _, res := range r.Resources {
						ag := "*"
						if len(r.APIGroups) > 0 {
							ag = r.APIGroups[0]
						}
						wi.Rules = append(wi.Rules, fmt.Sprintf("%s/%s", ag, res))
					}
					for _, op := range r.Operations {
						wi.Operations = appendUnique(wi.Operations, string(op))
					}
				}
				results = append(results, wi)
			}
		}
		log.Debug("collected ValidatingWebhookConfigurations", zap.Int("count", len(vwcList.Items)))
	}

	return results, nil
}

// webhookFailurePolicy converts a FailurePolicyType pointer to a string.
func webhookFailurePolicy(fp *admissionv1.FailurePolicyType) string {
	if fp == nil {
		return ""
	}
	return string(*fp)
}

// appendUnique appends s to slice only if not already present.
func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
