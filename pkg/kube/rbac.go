package kube

import (
	"context"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type rbacResult struct {
	ClusterRoles        []RoleInfo
	ClusterRoleBindings []BindingInfo
	Roles               []RoleInfo
	RoleBindings        []BindingInfo
	ServiceAccounts     []SAInfo
}

// collectRBAC enumerates all RBAC objects the current identity can see.
func collectRBAC(ctx context.Context, c *Client, namespaces []string, log *zap.Logger) (rbacResult, error) {
	cs := c.Clientset()
	result := rbacResult{}

	// ── ClusterRoles ──────────────────────────────────────────────────────────
	crList, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list ClusterRoles", zap.Error(err))
	} else {
		for _, cr := range crList.Items {
			ri := RoleInfo{
				Name:   cr.Name,
				Labels: redactLabels(cr.Labels),
			}
			for _, r := range cr.Rules {
				ri.Rules = append(ri.Rules, PolicyRule{
					Verbs:           nonEmpty(r.Verbs),
					APIGroups:       nonEmpty(r.APIGroups),
					Resources:       nonEmpty(r.Resources),
					ResourceNames:   nonEmpty(r.ResourceNames),
					NonResourceURLs: nonEmpty(r.NonResourceURLs),
				})
			}
			result.ClusterRoles = append(result.ClusterRoles, ri)
		}
		log.Debug("collected ClusterRoles", zap.Int("count", len(result.ClusterRoles)))
	}

	// ── ClusterRoleBindings ───────────────────────────────────────────────────
	crbList, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warn("cannot list ClusterRoleBindings", zap.Error(err))
	} else {
		for _, crb := range crbList.Items {
			bi := BindingInfo{
				Name:   crb.Name,
				Labels: redactLabels(crb.Labels),
				RoleRef: RoleRef{
					APIGroup: crb.RoleRef.APIGroup,
					Kind:     crb.RoleRef.Kind,
					Name:     crb.RoleRef.Name,
				},
			}
			for _, s := range crb.Subjects {
				bi.Subjects = append(bi.Subjects, Subject{
					Kind:      s.Kind,
					Name:      s.Name,
					Namespace: s.Namespace,
					APIGroup:  s.APIGroup,
				})
			}
			result.ClusterRoleBindings = append(result.ClusterRoleBindings, bi)
		}
		log.Debug("collected ClusterRoleBindings", zap.Int("count", len(result.ClusterRoleBindings)))
	}

	// ── Namespaced Roles and RoleBindings ─────────────────────────────────────
	for _, ns := range namespaces {
		// Roles
		roleList, err := cs.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Warn("cannot list Roles", zap.String("namespace", ns), zap.Error(err))
		} else {
			for _, r := range roleList.Items {
				ri := RoleInfo{
					Name:      r.Name,
					Namespace: ns,
					Labels:    redactLabels(r.Labels),
				}
				for _, rule := range r.Rules {
					ri.Rules = append(ri.Rules, PolicyRule{
						Verbs:         nonEmpty(rule.Verbs),
						APIGroups:     nonEmpty(rule.APIGroups),
						Resources:     nonEmpty(rule.Resources),
						ResourceNames: nonEmpty(rule.ResourceNames),
					})
				}
				result.Roles = append(result.Roles, ri)
			}
		}

		// RoleBindings
		rbList, err := cs.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Warn("cannot list RoleBindings", zap.String("namespace", ns), zap.Error(err))
		} else {
			for _, rb := range rbList.Items {
				bi := BindingInfo{
					Name:      rb.Name,
					Namespace: ns,
					Labels:    redactLabels(rb.Labels),
					RoleRef: RoleRef{
						APIGroup: rb.RoleRef.APIGroup,
						Kind:     rb.RoleRef.Kind,
						Name:     rb.RoleRef.Name,
					},
				}
				for _, s := range rb.Subjects {
					bi.Subjects = append(bi.Subjects, Subject{
						Kind:      s.Kind,
						Name:      s.Name,
						Namespace: s.Namespace,
					})
				}
				result.RoleBindings = append(result.RoleBindings, bi)
			}
		}

		// ServiceAccounts
		saList, err := cs.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Warn("cannot list ServiceAccounts", zap.String("namespace", ns), zap.Error(err))
		} else {
			for _, sa := range saList.Items {
				info := SAInfo{
					Name:        sa.Name,
					Namespace:   ns,
					Labels:      redactLabels(sa.Labels),
					Annotations: redactAnnotations(sa.Annotations),
				}
				for _, ips := range sa.ImagePullSecrets {
					info.ImagePullSecrets = append(info.ImagePullSecrets, ips.Name)
				}
				// Extract cloud workload identity annotations.
				ann := sa.Annotations
				if v := ann["eks.amazonaws.com/role-arn"]; v != "" {
					info.IRSARole = v
				}
				if v := ann["azure.workload.identity/client-id"]; v != "" {
					info.AzureIdentity = v
				}
				if v := ann["iam.gke.io/gcp-service-account"]; v != "" {
					info.GCPServiceAccount = v
				}
				result.ServiceAccounts = append(result.ServiceAccounts, info)
			}
		}
	}

	return result, nil
}

// redactLabels returns labels map with sensitive-looking values redacted.
func redactLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v // labels are generally safe; no data values here
	}
	return out
}

// redactAnnotations strips known sensitive annotation keys.
func redactAnnotations(ann map[string]string) map[string]string {
	if len(ann) == 0 {
		return nil
	}
	sensitive := map[string]bool{
		"kubectl.kubernetes.io/last-applied-configuration": true,
	}
	out := make(map[string]string, len(ann))
	for k, v := range ann {
		if sensitive[k] {
			out[k] = "[redacted]"
		} else {
			out[k] = v
		}
	}
	return out
}
