/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package helpers

import (
	"context"
	"fmt"
	"os"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// Phase constants to avoid goconst issues
	PhaseError   = "Error"
	PhaseExpired = "Expired"
	PhaseReady   = "Ready"
)

// GetKubeUserNamespace returns the namespace where all KubeUser resources should be created
func GetKubeUserNamespace() string {
	namespace := os.Getenv("KUBEUSER_NAMESPACE")
	if namespace == "" {
		namespace = "kubeuser" // fallback to default
	}
	return namespace
}

func CreateOrUpdate(ctx context.Context, r client.Client, obj client.Object) error {
	key := types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}
	existing := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, key, existing)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, obj)
	} else if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

// UpdateUserStatus calculates and updates the user status based on current state
func UpdateUserStatus(ctx context.Context, r client.Client, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)
	logger.Info("Updating user status", "name", user.Name)

	// Check if user certificate has expired (only if ExpiryTime is set)
	if user.Status.ExpiryTime != "" {
		if expiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			if time.Now().After(expiry) {
				user.Status.Phase = PhaseExpired
				user.Status.Message = "User certificate has expired"
				logger.Info("User certificate has expired", "expiry", user.Status.ExpiryTime)
			} else {
				// Certificate is still valid, set user as active
				SetActiveStatus(user)
			}
		} else {
			logger.Error(err, "Failed to parse expiry time", "expiryTime", user.Status.ExpiryTime)
			// If we can't parse expiry time, assume user is active
			SetActiveStatus(user)
		}
	} else {
		// No expiry time set yet (certificate not issued), set user as active
		SetActiveStatus(user)
	}

	// Add condition for better status tracking
	now := metav1.NewTime(time.Now())
	conditionType := PhaseReady
	conditionStatus := metav1.ConditionTrue
	conditionReason := "UserProvisioned"
	conditionMessage := user.Status.Message

	switch user.Status.Phase {
	case "Error":
		conditionType = PhaseReady
		conditionStatus = metav1.ConditionFalse
		conditionReason = "ProvisioningFailed"
	case "Expired":
		conditionType = PhaseReady
		conditionStatus = metav1.ConditionFalse
		conditionReason = "CertificateExpired"
	case "Pending":
		conditionType = PhaseReady
		conditionStatus = metav1.ConditionFalse
		conditionReason = "Provisioning"
	}

	// Update or add condition
	updatedConditions := []metav1.Condition{}
	conditionFound := false
	for _, condition := range user.Status.Conditions {
		if condition.Type == conditionType {
			condition.Status = conditionStatus
			condition.Reason = conditionReason
			condition.Message = conditionMessage
			condition.LastTransitionTime = now
			conditionFound = true
		}
		updatedConditions = append(updatedConditions, condition)
	}

	if !conditionFound {
		newCondition := metav1.Condition{
			Type:               conditionType,
			Status:             conditionStatus,
			Reason:             conditionReason,
			Message:            conditionMessage,
			LastTransitionTime: now,
		}
		updatedConditions = append(updatedConditions, newCondition)
	}
	user.Status.Conditions = updatedConditions

	logger.Info("Updating status", "phase", user.Status.Phase, "expiry", user.Status.ExpiryTime, "message", user.Status.Message)
	err := r.Status().Update(ctx, user)
	if err != nil {
		logger.Error(err, "Failed to update user status")
		return err
	}
	logger.Info("Successfully updated user status")
	return nil
}

// SetActiveStatus sets the user status to active based on role assignments
func SetActiveStatus(user *authv1alpha1.User) {
	user.Status.Phase = "Active"

	// Count different types of bindings
	var namespacedRoles, namespacedClusterRoles int
	for _, role := range user.Spec.Roles {
		if role.ExistingRole != "" {
			namespacedRoles++
		} else if role.ExistingClusterRole != "" {
			namespacedClusterRoles++
		}
	}
	clusterWideRoles := len(user.Spec.ClusterRoles)
	totalBindings := namespacedRoles + namespacedClusterRoles + clusterWideRoles

	if totalBindings == 0 {
		user.Status.Message = "No role bindings configured"
		return
	}

	// Build detailed message
	var parts []string
	if namespacedRoles > 0 {
		parts = append(parts, fmt.Sprintf("%d namespace-scoped Role(s)", namespacedRoles))
	}
	if namespacedClusterRoles > 0 {
		parts = append(parts, fmt.Sprintf("%d ClusterRole(s) bound to namespace(s)", namespacedClusterRoles))
	}
	if clusterWideRoles > 0 {
		parts = append(parts, fmt.Sprintf("%d cluster-wide ClusterRole(s)", clusterWideRoles))
	}

	if len(parts) == 1 {
		user.Status.Message = fmt.Sprintf("Active with %s", parts[0])
	} else if len(parts) == 2 {
		user.Status.Message = fmt.Sprintf("Active with %s and %s", parts[0], parts[1])
	} else {
		user.Status.Message = fmt.Sprintf("Active with %s, %s, and %s", parts[0], parts[1], parts[2])
	}
}

// RoleBindingMatches checks if two RoleBindings are functionally equivalent
func RoleBindingMatches(existing, desired *rbacv1.RoleBinding) bool {
	// Check if RoleRef matches
	if existing.RoleRef != desired.RoleRef {
		return false
	}

	// Check if subjects match (we expect exactly one subject)
	if len(existing.Subjects) != 1 || len(desired.Subjects) != 1 {
		return false
	}

	return existing.Subjects[0].Kind == desired.Subjects[0].Kind &&
		existing.Subjects[0].Name == desired.Subjects[0].Name
}

// ClusterRoleBindingMatches checks if two ClusterRoleBindings are functionally equivalent
func ClusterRoleBindingMatches(existing, desired *rbacv1.ClusterRoleBinding) bool {
	// Check if RoleRef matches
	if existing.RoleRef != desired.RoleRef {
		return false
	}

	// Check if subjects match (we expect exactly one subject)
	if len(existing.Subjects) != 1 || len(desired.Subjects) != 1 {
		return false
	}

	return existing.Subjects[0].Kind == desired.Subjects[0].Kind &&
		existing.Subjects[0].Name == desired.Subjects[0].Name
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func RemoveString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}
