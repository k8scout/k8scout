package kube

import (
	"context"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// dangerousGroups maps known operator API groups to the CRD kinds/resources that
// represent dangerous escalation or secret-access primitives within those operators.
var dangerousGroups = map[string][]struct{ Kind, Resource string }{
	"argoproj.io": {
		{"Application", "applications"},
		{"AppProject", "appprojects"},
	},
	"kustomize.toolkit.fluxcd.io": {
		{"Kustomization", "kustomizations"},
	},
	"helm.toolkit.fluxcd.io": {
		{"HelmRelease", "helmreleases"},
	},
	"source.toolkit.fluxcd.io": {
		{"GitRepository", "gitrepositories"},
	},
	"external-secrets.io": {
		{"ExternalSecret", "externalsecrets"},
		{"SecretStore", "secretstores"},
		{"ClusterSecretStore", "clustersecretstores"},
	},
	"secrets.hashicorp.com": {
		{"VaultStaticSecret", "vaultstaticsecrets"},
		{"VaultDynamicSecret", "vaultdynamicsecrets"},
	},
	"crossplane.io": {
		{"Provider", "providers"},
		{"ProviderConfig", "providerconfigs"},
	},
	// Azure AAD Pod Identity (legacy).
	"aadpodidentity.k8s.io": {
		{"AzureIdentity", "azureidentities"},
		{"AzureIdentityBinding", "azureidentitybindings"},
		{"AzureAssignedIdentity", "azureassignedidentities"},
	},
	// GKE Config Connector.
	"iam.cnrm.cloud.google.com": {
		{"IAMPolicy", "iampolicies"},
		{"IAMPolicyMember", "iampolicymembers"},
		{"IAMServiceAccount", "iamserviceaccounts"},
		{"IAMServiceAccountKey", "iamserviceaccountkeys"},
	},
	"compute.cnrm.cloud.google.com": {
		{"ComputeInstance", "computeinstances"},
		{"ComputeNetwork", "computenetworks"},
	},
	"storage.cnrm.cloud.google.com": {
		{"StorageBucket", "storagebuckets"},
	},
	// Azure Secrets Store CSI.
	"secrets-store.csi.x-k8s.io": {
		{"SecretProviderClass", "secretproviderclasses"},
	},
}

// collectCRDs discovers CRDs from dangerous operator groups using the Discovery API.
// No new Go module dependencies — uses the existing client-go discovery client.
func collectCRDs(ctx context.Context, c *Client, log *zap.Logger) ([]CRDInfo, error) {
	disco := c.Clientset().Discovery()
	groupList, err := disco.ServerGroups()
	if err != nil {
		log.Warn("CRD discovery: cannot list server groups", zap.Error(err))
		return nil, err
	}

	var results []CRDInfo
	for _, group := range groupList.Groups {
		kinds, ok := dangerousGroups[group.Name]
		if !ok {
			continue
		}
		// Resolve the preferred version for this group.
		preferredVersion := group.PreferredVersion.GroupVersion
		resources, err := disco.ServerResourcesForGroupVersion(preferredVersion)
		if err != nil {
			log.Warn("CRD discovery: cannot get resources for group",
				zap.String("group", group.Name), zap.Error(err))
			continue
		}
		// Build a lookup from resource name to APIResource.
		resMap := make(map[string]metav1.APIResource, len(resources.APIResources))
		for _, r := range resources.APIResources {
			resMap[r.Name] = r
		}
		for _, kd := range kinds {
			apiRes, ok := resMap[kd.Resource]
			if !ok {
				continue
			}
			scope := "Namespaced"
			if !apiRes.Namespaced {
				scope = "Cluster"
			}
			results = append(results, CRDInfo{
				Group:    group.Name,
				Kind:     kd.Kind,
				Resource: kd.Resource,
				Scope:    scope,
			})
		}
	}

	log.Debug("collected operator CRDs", zap.Int("count", len(results)))
	return results, nil
}
