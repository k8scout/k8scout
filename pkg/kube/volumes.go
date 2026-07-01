package kube

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectPVs enumerates PersistentVolume objects (cluster-scoped).
func collectPVs(ctx context.Context, c *Client, log *zap.Logger) ([]PVInfo, error) {
	cs := c.Clientset()
	pvList, err := cs.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing PersistentVolumes: %w", err)
	}

	var results []PVInfo
	for _, pv := range pvList.Items {
		info := PVInfo{
			Name: pv.Name,
		}
		if pv.Spec.StorageClassName != "" {
			info.StorageClass = pv.Spec.StorageClassName
		}
		for _, am := range pv.Spec.AccessModes {
			info.AccessModes = append(info.AccessModes, string(am))
		}
		if q, ok := pv.Spec.Capacity["storage"]; ok {
			info.Capacity = q.String()
		}
		if pv.Spec.ClaimRef != nil {
			info.ClaimRef = pv.Spec.ClaimRef.Namespace + "/" + pv.Spec.ClaimRef.Name
		}
		info.VolumeSource = pvSourceType(pv.Spec)
		results = append(results, info)
	}

	log.Debug("collected PersistentVolumes", zap.Int("count", len(results)))
	return results, nil
}

// collectPVCs enumerates PersistentVolumeClaim objects in the given namespace.
func collectPVCs(ctx context.Context, c *Client, ns string, log *zap.Logger) ([]PVCInfo, error) {
	cs := c.Clientset()
	pvcList, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing PVCs in %q: %w", ns, err)
	}

	var results []PVCInfo
	for _, pvc := range pvcList.Items {
		info := PVCInfo{
			Name:      pvc.Name,
			Namespace: pvc.Namespace,
		}
		if pvc.Spec.VolumeName != "" {
			info.VolumeName = pvc.Spec.VolumeName
		}
		if pvc.Spec.StorageClassName != nil {
			info.StorageClass = *pvc.Spec.StorageClassName
		}
		for _, am := range pvc.Spec.AccessModes {
			info.AccessModes = append(info.AccessModes, string(am))
		}
		results = append(results, info)
	}

	log.Debug("collected PVCs", zap.String("namespace", ns), zap.Int("count", len(results)))
	return results, nil
}

// pvSourceType returns a short label for the PV's volume source.
func pvSourceType(spec corev1.PersistentVolumeSpec) string {
	src := spec.PersistentVolumeSource
	switch {
	case src.AWSElasticBlockStore != nil:
		return "AWSElasticBlockStore"
	case src.GCEPersistentDisk != nil:
		return "GCEPersistentDisk"
	case src.AzureDisk != nil:
		return "AzureDisk"
	case src.AzureFile != nil:
		return "AzureFile"
	case src.NFS != nil:
		return "NFS"
	case src.HostPath != nil:
		return "HostPath"
	case src.CSI != nil:
		return src.CSI.Driver
	default:
		return "Unknown"
	}
}
