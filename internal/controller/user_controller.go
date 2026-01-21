/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/auth"
	"github.com/openkube-hub/KubeUser/internal/controller/cleanup"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	"github.com/openkube-hub/KubeUser/internal/controller/rbac"
	"github.com/openkube-hub/KubeUser/internal/controller/renewal"
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
	Scheme            *runtime.Scheme
	AuthManager       *auth.Manager
	RenewalCalculator *renewal.RenewalCalculator
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

	// Validate auth specification
	logger.Info("Validating auth specification", "authType", user.Spec.Auth.Type, "authTTL", user.Spec.Auth.TTL)
	if err := auth.ValidateAuthSpec(&user); err != nil {
		logger.Error(err, "Invalid auth specification")
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Invalid auth specification: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}
	logger.Info("Auth specification validation passed")

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

	// Ensure authentication credentials using auth manager
	logger.Info("Starting authentication credential processing")
	if r.AuthManager == nil {
		r.AuthManager = auth.NewManager(r.Client)
	}

	err := r.AuthManager.Ensure(ctx, &user)
	if err != nil {
		logger.Error(err, "Failed to ensure authentication credentials")

		// Check if this is a requeue error
		if strings.Contains(err.Error(), "requeue needed") {
			logger.Info("Authentication processing needs requeue")
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}

		// For OIDC not implemented error, set appropriate status
		if strings.Contains(err.Error(), "not yet implemented") {
			user.Status.Phase = helpers.PhaseError
			user.Status.Message = fmt.Sprintf("Authentication type not implemented: %v", err)
			_ = r.Status().Update(ctx, &user)
			return ctrl.Result{}, err
		}

		// Other errors
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Failed to ensure authentication: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	logger.Info("Authentication credential processing completed")

	// Requeue based on auto-renewal configuration
	logger.Info("Calculating requeue strategy", "phase", user.Status.Phase, "autoRenew", user.Spec.Auth.AutoRenew)

	if user.Spec.Auth.AutoRenew && user.Status.Phase == "Active" {
		requeueAfter, err := r.calculateSmartRequeue(ctx, &user)
		if err != nil {
			logger.Error(err, "Failed to calculate smart requeue, using default")
			logger.Info("=== END RECONCILE (DEFAULT REQUEUE) ===")
			return ctrl.Result{RequeueAfter: 30 * time.Minute}, nil
		}

		logger.Info("Smart requeue calculated", "requeueAfter", requeueAfter)
		logger.Info("=== END RECONCILE (SMART REQUEUE) ===")
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Legacy expiry-based requeue for non-auto-renewal users
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

// calculateSmartRequeue calculates the optimal requeue time for auto-renewal
func (r *UserReconciler) calculateSmartRequeue(ctx context.Context, user *authv1alpha1.User) (time.Duration, error) {
	logger := logf.FromContext(ctx)

	// Initialize renewal calculator if not already done
	if r.RenewalCalculator == nil {
		r.RenewalCalculator = renewal.NewRenewalCalculator()
	}

	// Get certificate duration
	certDuration := auth.GetAuthDuration(user)

	// Use NextRenewalTime from status if available (most efficient)
	if user.Status.NextRenewalTime != nil {
		now := time.Now()
		renewalTime := user.Status.NextRenewalTime.Time

		if renewalTime.Before(now) {
			// Should renew immediately
			logger.Info("Certificate should renew immediately")
			return 0, nil
		}

		requeueAfter := renewalTime.Sub(now)

		// Add small jitter to prevent thundering herd
		jitter := time.Duration(rand.Int63n(int64(5 * time.Minute)))
		requeueAfter += jitter

		// Cap requeue time to reasonable limits
		if requeueAfter > 24*time.Hour {
			requeueAfter = 24 * time.Hour
		}
		if requeueAfter < 1*time.Minute {
			requeueAfter = 1 * time.Minute
		}

		logger.Info("Smart requeue calculated from NextRenewalTime",
			"renewalTime", renewalTime.Format(time.RFC3339),
			"requeueAfter", requeueAfter,
			"jitter", jitter)

		return requeueAfter, nil
	}

	// Fallback: calculate from certificate expiry
	if user.Status.ExpiryTime != "" {
		certExpiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime)
		if err != nil {
			return 0, fmt.Errorf("failed to parse certificate expiry: %w", err)
		}

		requeueAfter, err := r.RenewalCalculator.GetRequeueAfter(user, certExpiry, certDuration)
		if err != nil {
			return 0, fmt.Errorf("failed to calculate requeue time: %w", err)
		}

		logger.Info("Smart requeue calculated from certificate expiry",
			"certExpiry", certExpiry.Format(time.RFC3339),
			"requeueAfter", requeueAfter)

		return requeueAfter, nil
	}

	// No certificate information available, use default
	logger.Info("No certificate information available, using default requeue")
	return 30 * time.Minute, nil
}

// SetupWithManager wires the controller
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize auth manager
	if r.AuthManager == nil {
		r.AuthManager = auth.NewManager(r.Client)
	}

	// Initialize renewal calculator
	if r.RenewalCalculator == nil {
		r.RenewalCalculator = renewal.NewRenewalCalculator()
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.User{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&corev1.Secret{}).
		Named("user").
		Complete(r)
}
