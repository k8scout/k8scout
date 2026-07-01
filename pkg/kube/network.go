package kube

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectNetworkPolicies enumerates NetworkPolicy objects in the given namespace.
func collectNetworkPolicies(ctx context.Context, c *Client, ns string, log *zap.Logger) ([]NetworkPolicyInfo, error) {
	cs := c.Clientset()
	npList, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing NetworkPolicies in %q: %w", ns, err)
	}

	var results []NetworkPolicyInfo
	for _, np := range npList.Items {
		info := NetworkPolicyInfo{
			Name:      np.Name,
			Namespace: np.Namespace,
			Labels:    np.Labels,
		}

		info.PodSelector = np.Spec.PodSelector.MatchLabels

		for _, pt := range np.Spec.PolicyTypes {
			info.PolicyTypes = append(info.PolicyTypes, string(pt))
		}

		for _, ing := range np.Spec.Ingress {
			rule := NetPolRule{}
			for _, port := range ing.Ports {
				np := NetPolPort{}
				if port.Protocol != nil {
					np.Protocol = string(*port.Protocol)
				}
				if port.Port != nil {
					np.Port = port.Port.String()
				}
				rule.Ports = append(rule.Ports, np)
			}
			for _, from := range ing.From {
				peer := NetPolPeer{}
				if from.PodSelector != nil {
					peer.PodSelector = from.PodSelector.MatchLabels
				}
				if from.NamespaceSelector != nil {
					peer.NamespaceSelector = from.NamespaceSelector.MatchLabels
				}
				if from.IPBlock != nil {
					peer.IPBlock = from.IPBlock.CIDR
				}
				rule.FromTo = append(rule.FromTo, peer)
			}
			info.IngressRules = append(info.IngressRules, rule)
		}

		for _, eg := range np.Spec.Egress {
			rule := NetPolRule{}
			for _, port := range eg.Ports {
				np := NetPolPort{}
				if port.Protocol != nil {
					np.Protocol = string(*port.Protocol)
				}
				if port.Port != nil {
					np.Port = port.Port.String()
				}
				rule.Ports = append(rule.Ports, np)
			}
			for _, to := range eg.To {
				peer := NetPolPeer{}
				if to.PodSelector != nil {
					peer.PodSelector = to.PodSelector.MatchLabels
				}
				if to.NamespaceSelector != nil {
					peer.NamespaceSelector = to.NamespaceSelector.MatchLabels
				}
				if to.IPBlock != nil {
					peer.IPBlock = to.IPBlock.CIDR
				}
				rule.FromTo = append(rule.FromTo, peer)
			}
			info.EgressRules = append(info.EgressRules, rule)
		}

		results = append(results, info)
	}

	log.Debug("collected NetworkPolicies", zap.String("namespace", ns), zap.Int("count", len(results)))
	return results, nil
}

// collectServices enumerates Service objects in the given namespace.
func collectServices(ctx context.Context, c *Client, ns string, log *zap.Logger) ([]ServiceInfo, error) {
	cs := c.Clientset()
	svcList, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing Services in %q: %w", ns, err)
	}

	var results []ServiceInfo
	for _, svc := range svcList.Items {
		info := ServiceInfo{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Type:      string(svc.Spec.Type),
			ClusterIP: svc.Spec.ClusterIP,
			Selector:  svc.Spec.Selector,
			Labels:    svc.Labels,
		}
		for _, port := range svc.Spec.Ports {
			sp := ServicePort{
				Name:       port.Name,
				Port:       port.Port,
				TargetPort: port.TargetPort.String(),
				Protocol:   string(port.Protocol),
				NodePort:   port.NodePort,
			}
			info.Ports = append(info.Ports, sp)
		}
		results = append(results, info)
	}

	log.Debug("collected Services", zap.String("namespace", ns), zap.Int("count", len(results)))
	return results, nil
}
