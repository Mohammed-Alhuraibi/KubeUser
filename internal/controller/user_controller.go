/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/certs"
	"github.com/openkube-hub/KubeUser/internal/controller/cleanup"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	"github.com/openkube-hub/KubeUser/internal/controller/rbac"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// UserReconciler reconciles a User object
type UserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// RBAC rules
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/finalizers,verbs=update
// Core resources
// +kubebuilder:rbac:groups="",resources=configmaps;secrets;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods;replicasets,verbs=get;list;watch;create;update;patch;delete
// Apps resources
// +kubebuilder:rbac:groups=apps,resources=deployments;replicasets,verbs=get;list;watch;create;update;patch;delete
// RBAC resources with bind permission
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;clusterroles,verbs=get;list;watch;bind
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete;bind
// CSR resources
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=approve,resourceNames=kubernetes.io/kube-apiserver-client
// Admission resources
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;patch

// Reconcile main loop
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("=== START RECONCILE ===", "user", req.Name)

	var user authv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		logger.Info("User not found, ignoring", "user", req.Name, "error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	username := user.Name
	logger.Info("Reconciling User", "name", username, "generation", user.Generation, "resourceVersion", user.ResourceVersion)

	// Ensure initial status is set
	logger.Info("Checking initial status", "currentPhase", user.Status.Phase)
	if user.Status.Phase == "" {
		logger.Info("Setting initial status to Pending")
		user.Status.Phase = "Pending"
		user.Status.Message = "Initializing user resources"
		if err := r.Status().Update(ctx, &user); err != nil {
			logger.Error(err, "Failed to set initial status")
			// Don't return error, continue with reconciliation
		} else {
			logger.Info("Successfully set initial status")
		}
	} else {
		logger.Info("Status already set, skipping initial status", "phase", user.Status.Phase)
	}

	// Handle deletion
	logger.Info("Checking deletion", "deletionTimestamp", user.DeletionTimestamp)
	if !user.DeletionTimestamp.IsZero() {
		logger.Info("User is being deleted, starting cleanup")
		if helpers.ContainsString(user.Finalizers, cleanup.UserFinalizer) {
			logger.Info("Cleaning up user resources")
			cleanup.CleanupUserResources(ctx, r.Client, &user)
			logger.Info("Removing finalizer")
			user.Finalizers = helpers.RemoveString(user.Finalizers, cleanup.UserFinalizer)
			if err := r.Update(ctx, &user); err != nil {
				logger.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			logger.Info("Successfully cleaned up and removed finalizer")
		}
		logger.Info("=== END RECONCILE (DELETION) ===")
		return ctrl.Result{}, nil
	}

	// Ensure finalizer
	logger.Info("Checking finalizer", "currentFinalizers", user.Finalizers)
	if !helpers.ContainsString(user.Finalizers, cleanup.UserFinalizer) {
		logger.Info("Adding finalizer", "finalizer", cleanup.UserFinalizer)
		user.Finalizers = append(user.Finalizers, cleanup.UserFinalizer)
		if err := r.Update(ctx, &user); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		logger.Info("Successfully added finalizer")
	} else {
		logger.Info("Finalizer already exists, skipping")
	}

	// Get user resources namespace (must exist)
	userNamespace := helpers.GetKubeUserNamespace()
	logger.Info("Using user resources namespace", "namespace", userNamespace)

	// === Reconcile RoleBindings ===
	logger.Info("Starting RoleBindings reconciliation", "rolesCount", len(user.Spec.Roles))
	if err := rbac.ReconcileRoleBindings(ctx, r.Client, &user); err != nil {
		logger.Error(err, "Failed to reconcile RoleBindings")
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Failed to reconcile RoleBindings: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}
	logger.Info("RoleBindings reconciliation completed")

	// === Reconcile ClusterRoleBindings ===
	logger.Info("Starting ClusterRoleBindings reconciliation", "clusterRolesCount", len(user.Spec.ClusterRoles))
	if err := rbac.ReconcileClusterRoleBindings(ctx, r.Client, &user); err != nil {
		logger.Error(err, "Failed to reconcile ClusterRoleBindings")
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Failed to reconcile ClusterRoleBindings: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}
	logger.Info("ClusterRoleBindings reconciliation completed")

	// Update status after successful RBAC reconciliation
	logger.Info("*** CALLING updateUserStatus ***")
	if err := helpers.UpdateUserStatus(ctx, r.Client, &user); err != nil {
		logger.Error(err, "Failed to update user status")
		// Don't return error, continue with certificate processing
	} else {
		logger.Info("*** updateUserStatus completed successfully ***")
	}

	// Ensure cert-based kubeconfig
	logger.Info("Starting certificate/kubeconfig processing")
	requeue, err := certs.EnsureCertKubeconfig(ctx, r.Client, &user)
	if err != nil {
		logger.Error(err, "Failed to ensure certificate kubeconfig")
		logger.Info("=== END RECONCILE (CERT ERROR) ===")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if requeue {
		logger.Info("Certificate processing needs requeue")
		logger.Info("=== END RECONCILE (REQUEUE) ===")
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}
	logger.Info("Certificate/kubeconfig processing completed")

	// Requeue if user is close to expiry to handle cleanup
	logger.Info("Checking expiry for requeue", "phase", user.Status.Phase, "expiryTime", user.Status.ExpiryTime)
	if user.Status.Phase == "Active" && user.Status.ExpiryTime != "" {
		if expiryTime, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			timeUntilExpiry := time.Until(expiryTime)
			logger.Info("Time until expiry", "duration", timeUntilExpiry)
			if timeUntilExpiry <= 0 {
				// User has expired, mark as expired
				logger.Info("User has expired, updating status")
				user.Status.Phase = helpers.PhaseExpired
				user.Status.Message = "User access has expired"
				_ = r.Status().Update(ctx, &user)
				logger.Info("=== END RECONCILE (EXPIRED) ===")
				return ctrl.Result{}, nil
			} else if timeUntilExpiry < 24*time.Hour {
				// Requeue to check expiry more frequently
				logger.Info("User expires soon, requeueing in 1 hour")
				logger.Info("=== END RECONCILE (EXPIRY REQUEUE) ===")
				return ctrl.Result{RequeueAfter: time.Hour}, nil
			}
		} else {
			logger.Error(err, "Failed to parse expiry time", "expiryTime", user.Status.ExpiryTime)
		}
	}

	logger.Info("=== END RECONCILE (SUCCESS) ===, requeueing in 30 minutes")
	return ctrl.Result{RequeueAfter: 30 * time.Minute}, nil // Regular reconciliation
}

// SetupWithManager wires the controller
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.User{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&corev1.Secret{}).
		Named("user").
		Complete(r)
}
