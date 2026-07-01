package kube

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectAWSAuth reads the aws-auth ConfigMap from kube-system, which maps
// AWS IAM roles/users to Kubernetes groups. system:masters grants cluster-admin.
func collectAWSAuth(ctx context.Context, c *Client, log *zap.Logger) *AWSAuthConfig {
	cs := c.Clientset()
	cm, err := cs.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	if err != nil {
		log.Debug("aws-auth ConfigMap not found (non-EKS cluster or restricted access)", zap.Error(err))
		return nil
	}

	result := &AWSAuthConfig{}

	if mapRoles, ok := cm.Data["mapRoles"]; ok {
		result.MapRoles = parseAWSAuthEntries(mapRoles)
	}
	if mapUsers, ok := cm.Data["mapUsers"]; ok {
		result.MapUsers = parseAWSAuthEntries(mapUsers)
	}

	log.Info("collected aws-auth ConfigMap",
		zap.Int("mapRoles", len(result.MapRoles)),
		zap.Int("mapUsers", len(result.MapUsers)))

	return result
}

// parseAWSAuthEntries parses the YAML-like entries in aws-auth ConfigMap fields.
// Each entry has rolearn/userarn, username, and groups.
func parseAWSAuthEntries(raw string) []AWSAuthEntry {
	var entries []AWSAuthEntry
	var current AWSAuthEntry
	inGroups := false

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "---" {
			continue
		}

		if strings.HasPrefix(trimmed, "- rolearn:") || strings.HasPrefix(trimmed, "- userarn:") {
			if current.ARN != "" {
				entries = append(entries, current)
			}
			current = AWSAuthEntry{}
			inGroups = false
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				current.ARN = strings.TrimSpace(parts[1])
			}
			if strings.Contains(trimmed, "rolearn") {
				current.Type = "role"
			} else {
				current.Type = "user"
			}
		} else if strings.HasPrefix(trimmed, "username:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				current.Username = strings.TrimSpace(parts[1])
			}
			inGroups = false
		} else if strings.HasPrefix(trimmed, "groups:") {
			inGroups = true
		} else if inGroups && strings.HasPrefix(trimmed, "- ") {
			group := strings.TrimPrefix(trimmed, "- ")
			current.Groups = append(current.Groups, strings.TrimSpace(group))
		}
	}
	if current.ARN != "" {
		entries = append(entries, current)
	}

	return entries
}

// detectEKSPodIdentity checks for the presence of EKS Pod Identity agent/webhook.
func detectEKSPodIdentity(ctx context.Context, c *Client, log *zap.Logger) *EKSPodIdentityInfo {
	cs := c.Clientset()

	// Check for eks-pod-identity-agent DaemonSet in kube-system.
	dsList, err := cs.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, ds := range dsList.Items {
		if strings.Contains(ds.Name, "pod-identity") || strings.Contains(ds.Name, "eks-pod-identity") {
			log.Info("EKS Pod Identity agent detected", zap.String("daemonset", ds.Name))
			return &EKSPodIdentityInfo{
				AgentDaemonSet: ds.Name,
				Enabled:        true,
			}
		}
	}

	// Also check for the pod-identity-webhook MutatingWebhookConfiguration.
	mwhList, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	for _, mwh := range mwhList.Items {
		if strings.Contains(mwh.Name, "pod-identity") {
			log.Info("EKS Pod Identity webhook detected", zap.String("webhook", mwh.Name))
			return &EKSPodIdentityInfo{
				WebhookName: mwh.Name,
				Enabled:     true,
			}
		}
	}

	return nil
}

// detectAADPodIdentity checks for the presence of AAD Pod Identity components (legacy AKS).
func detectAADPodIdentity(ctx context.Context, c *Client, log *zap.Logger) *AADPodIdentityInfo {
	cs := c.Clientset()

	result := &AADPodIdentityInfo{}

	// Check for aad-pod-identity pods in kube-system or any namespace.
	dsList, err := cs.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ds := range dsList.Items {
			if strings.Contains(ds.Name, "nmi") || strings.Contains(ds.Name, "aad-pod-identity") {
				result.NMIDaemonSet = ds.Name
				result.Enabled = true
			}
		}
	}

	depList, err := cs.AppsV1().Deployments("kube-system").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, dep := range depList.Items {
			if strings.Contains(dep.Name, "mic") || strings.Contains(dep.Name, "aad-pod-identity") {
				result.MICDeployment = dep.Name
				result.Enabled = true
			}
		}
	}

	if !result.Enabled {
		return nil
	}

	// Detect AzureIdentity CRDs via discovery API.
	_, resources, err := cs.Discovery().ServerGroupsAndResources()
	if err == nil {
		for _, rl := range resources {
			if strings.Contains(rl.GroupVersion, "aadpodidentity.k8s.io") {
				for _, r := range rl.APIResources {
					if r.Kind == "AzureIdentity" {
						result.CRDsPresent = true
					}
				}
			}
		}
	}

	log.Info("AAD Pod Identity detected (legacy)", zap.String("nmi", result.NMIDaemonSet))
	return result
}

// detectGKEFeatures detects GKE-specific features from node labels and system pods.
func detectGKEFeatures(ctx context.Context, c *Client, nodes []NodeInfo, log *zap.Logger) *GKEClusterInfo {
	result := &GKEClusterInfo{}

	// Detect Autopilot from node labels.
	for _, n := range nodes {
		if _, ok := n.Labels["cloud.google.com/gke-autopilot"]; ok {
			result.IsAutopilot = true
		}
		if v, ok := n.Labels["cloud.google.com/gke-os-distribution"]; ok {
			result.OSDistribution = v
		}
	}

	cs := c.Clientset()

	// Detect Config Connector via discovery API.
	_, resources, err := cs.Discovery().ServerGroupsAndResources()
	if err == nil {
		for _, rl := range resources {
			if strings.Contains(rl.GroupVersion, "cnrm.cloud.google.com") {
				result.ConfigConnectorEnabled = true
				for _, r := range rl.APIResources {
					result.ConfigConnectorCRDs = append(result.ConfigConnectorCRDs, r.Kind)
				}
			}
		}
	}

	// Detect metadata concealment from node annotations.
	for _, n := range nodes {
		if v, ok := n.Labels["cloud.google.com/metadata-proxy-ready"]; ok && v == "true" {
			result.MetadataConcealment = true
		}
	}

	if result.IsAutopilot || result.ConfigConnectorEnabled || result.MetadataConcealment {
		log.Info("GKE features detected",
			zap.Bool("autopilot", result.IsAutopilot),
			zap.Bool("config_connector", result.ConfigConnectorEnabled),
			zap.Bool("metadata_concealment", result.MetadataConcealment))
	}

	return result
}

// detectAzureKeyVaultCSI checks for Azure Key Vault CSI driver.
func detectAzureKeyVaultCSI(ctx context.Context, c *Client, log *zap.Logger) bool {
	cs := c.Clientset()
	dsList, err := cs.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false
	}
	for _, ds := range dsList.Items {
		if strings.Contains(ds.Name, "secrets-store-csi") || strings.Contains(ds.Name, "keyvault") {
			log.Info("Azure Key Vault CSI driver detected", zap.String("daemonset", ds.Name))
			return true
		}
	}
	return false
}

// detectGCPSAKeysInSecrets checks for GCP service account JSON keys stored in Kubernetes secrets.
func detectGCPSAKeysInSecrets(secrets []SecretMeta) []string {
	var flagged []string
	for _, s := range secrets {
		for _, key := range s.DataKeys {
			if key == "key.json" || key == "credentials.json" || key == "service-account.json" ||
				strings.HasSuffix(key, "-sa-key.json") || strings.HasSuffix(key, "-credentials.json") {
				flagged = append(flagged, fmt.Sprintf("%s/%s (key: %s)", s.Namespace, s.Name, key))
			}
		}
		if s.Type == "Opaque" {
			for _, key := range s.DataKeys {
				if strings.Contains(key, "gcp") && strings.HasSuffix(key, ".json") {
					flagged = append(flagged, fmt.Sprintf("%s/%s (key: %s)", s.Namespace, s.Name, key))
				}
			}
		}
	}
	return flagged
}

// ParseIRSARoleARN extracts account ID, role name, and path from an IRSA role ARN.
func ParseIRSARoleARN(arn string) (accountID, roleName, rolePath string, crossAccount bool) {
	// ARN format: arn:aws:iam::ACCOUNT_ID:role/PATH/ROLE_NAME
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "iam" {
		return "", "", "", false
	}
	accountID = parts[4]
	roleSpec := parts[5] // "role/name" or "role/path/name"
	if strings.HasPrefix(roleSpec, "role/") {
		rolePath = strings.TrimPrefix(roleSpec, "role/")
		pathParts := strings.Split(rolePath, "/")
		roleName = pathParts[len(pathParts)-1]
	}
	return accountID, roleName, rolePath, false
}
