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

// Reconcile orchestrates the user reconciliation process using focused helper methods.
// It implements an idempotent update pattern to minimize etcd writes and prevent infinite loops.
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("=== START RECONCILE ===", "user", req.Name)

	var user authv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		logger.Info("User not found, ignoring", "user", req.Name, "error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling User", "name", user.Name, "generation", user.Generation, "resourceVersion", user.ResourceVersion)

	// Track status changes to implement idempotent updates
	statusChanged := false

	// Initialize status if needed
	if changed := r.ensureInitialStatus(&user); changed {
		statusChanged = true
	}

	// Validate auth specification
	if err := auth.ValidateAuthSpec(&user); err != nil {
		logger.Error(err, "Invalid auth specification")
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Invalid auth specification: %v", err)
		statusChanged = true
		return r.finishReconcile(ctx, &user, statusChanged, err)
	}

	// Handle deletion
	if !user.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &user)
	}

	// Ensure finalizer
	if err := r.ensureFinalizer(ctx, &user); err != nil {
		return ctrl.Result{}, err
	}

	// Reconcile RBAC resources
	if err := r.reconcileRBAC(ctx, &user); err != nil {
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Failed to reconcile RBAC: %v", err)
		statusChanged = true
		return r.finishReconcile(ctx, &user, statusChanged, err)
	}

	// Reconcile authentication credentials
	result, err := r.reconcileAuthentication(ctx, &user)
	if err != nil {
		// Handle specific error cases
		if strings.Contains(err.Error(), "requeue needed") {
			logger.Info("Authentication processing needs requeue")
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}

		if strings.Contains(err.Error(), "not yet implemented") {
			user.Status.Phase = helpers.PhaseError
			user.Status.Message = fmt.Sprintf("Authentication type not implemented: %v", err)
			statusChanged = true
			return r.finishReconcile(ctx, &user, statusChanged, err)
		}

		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Failed to ensure authentication: %v", err)
		statusChanged = true
		return r.finishReconcile(ctx, &user, statusChanged, ctrl.Result{RequeueAfter: 5 * time.Second}, nil)
	}
	if result != nil {
		return *result, nil
	}

	// Sync status fields (including NextRenewalAt management)
	if changed := r.syncStatusFields(ctx, &user); changed {
		statusChanged = true
	}

	// Update status once if any changes occurred
	if statusChanged {
		if err := r.Status().Update(ctx, &user); err != nil {
			logger.Error(err, "Failed to update user status")
			return ctrl.Result{RequeueAfter: 5 * time.Second}, err
		}
		logger.Info("Status updated successfully")
	}

	// Calculate optimal requeue strategy
	requeueResult := r.calculateRequeue(ctx, &user)
	logger.Info("=== END RECONCILE ===", "requeueAfter", requeueResult.RequeueAfter)
	return requeueResult, nil
}

// ensureInitialStatus sets the initial status if not already set.
// Returns true if the status was changed.
func (r *UserReconciler) ensureInitialStatus(user *authv1alpha1.User) bool {
	if user.Status.Phase == "" {
		user.Status.Phase = "Pending"
		user.Status.Message = "Initializing user resources"
		return true
	}
	return false
}

// handleDeletion manages the user deletion process including cleanup and finalizer removal.
func (r *UserReconciler) handleDeletion(ctx context.Context, user *authv1alpha1.User) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("User is being deleted, starting cleanup")

	if helpers.ContainsString(user.Finalizers, cleanup.UserFinalizer) {
		logger.Info("Cleaning up user resources")
		cleanup.CleanupUserResources(ctx, r.Client, user)

		logger.Info("Removing finalizer")
		user.Finalizers = helpers.RemoveString(user.Finalizers, cleanup.UserFinalizer)
		if err := r.Update(ctx, user); err != nil {
			logger.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
		logger.Info("Successfully cleaned up and removed finalizer")
	}

	logger.Info("=== END RECONCILE (DELETION) ===")
	return ctrl.Result{}, nil
}

// ensureFinalizer adds the user finalizer if not present.
func (r *UserReconciler) ensureFinalizer(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)

	if !helpers.ContainsString(user.Finalizers, cleanup.UserFinalizer) {
		logger.Info("Adding finalizer", "finalizer", cleanup.UserFinalizer)
		user.Finalizers = append(user.Finalizers, cleanup.UserFinalizer)
		if err := r.Update(ctx, user); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return err
		}
		logger.Info("Successfully added finalizer")
	}
	return nil
}

// reconcileRBAC handles both RoleBindings and ClusterRoleBindings reconciliation.
func (r *UserReconciler) reconcileRBAC(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)

	// Reconcile RoleBindings
	logger.Info("Starting RoleBindings reconciliation", "rolesCount", len(user.Spec.Roles))
	if err := rbac.ReconcileRoleBindings(ctx, r.Client, user); err != nil {
		logger.Error(err, "Failed to reconcile RoleBindings")
		return fmt.Errorf("failed to reconcile RoleBindings: %w", err)
	}
	logger.Info("RoleBindings reconciliation completed")

	// Reconcile ClusterRoleBindings
	logger.Info("Starting ClusterRoleBindings reconciliation", "clusterRolesCount", len(user.Spec.ClusterRoles))
	if err := rbac.ReconcileClusterRoleBindings(ctx, r.Client, user); err != nil {
		logger.Error(err, "Failed to reconcile ClusterRoleBindings")
		return fmt.Errorf("failed to reconcile ClusterRoleBindings: %w", err)
	}
	logger.Info("ClusterRoleBindings reconciliation completed")

	// Update status after successful RBAC reconciliation
	logger.Info("Updating user status after RBAC reconciliation")
	if err := helpers.UpdateUserStatus(ctx, r.Client, user); err != nil {
		logger.Error(err, "Failed to update user status")
		// Don't return error, continue with reconciliation
	} else {
		logger.Info("User status updated successfully")
	}

	return nil
}

// reconcileAuthentication manages authentication credentials and handles auth-specific errors.
// Returns a ctrl.Result pointer if immediate return is needed, otherwise nil.
func (r *UserReconciler) reconcileAuthentication(ctx context.Context, user *authv1alpha1.User) (*ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("Starting authentication credential processing")

	// Initialize auth manager if needed
	if r.AuthManager == nil {
		r.AuthManager = auth.NewManager(r.Client)
	}

	err := r.AuthManager.Ensure(ctx, user)
	if err != nil {
		logger.Error(err, "Failed to ensure authentication credentials")
		return nil, err
	}

	logger.Info("Authentication credential processing completed")
	return nil, nil
}

// syncStatusFields manages status field synchronization, including NextRenewalAt field management.
// Returns true if any status fields were changed.
func (r *UserReconciler) syncStatusFields(ctx context.Context, user *authv1alpha1.User) bool {
	logger := logf.FromContext(ctx)
	changed := false

	// Handle NextRenewalAt field based on autoRenew setting
	// Explicit purging: if autoRenew is disabled, explicitly set NextRenewalAt to nil
	if !user.Spec.Auth.AutoRenew && user.Status.NextRenewalAt != nil {
		logger.Info("Auto-renewal disabled, explicitly clearing NextRenewalAt field")
		user.Status.NextRenewalAt = nil
		changed = true
	} else if user.Spec.Auth.AutoRenew && user.Status.NextRenewalAt == nil && user.Status.ExpiryTime != "" {
		// Auto-renewal enabled but NextRenewalAt is not set - calculate it from existing certificate
		logger.Info("Auto-renewal enabled but NextRenewalAt not set, calculating from existing certificate")
		if certExpiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			certDuration := auth.GetAuthDuration(user)
			issuedAt := certExpiry.Add(-certDuration) // Approximate issued time

			renewalTime := renewal.CalculateNextRenewal(issuedAt, certExpiry, user.Spec.Auth.RenewBefore)
			user.Status.NextRenewalAt = &renewalTime
			changed = true
			logger.Info("Successfully calculated NextRenewalAt field", "nextRenewalAt", renewalTime.Time.Format(time.RFC3339))
		} else {
			logger.Error(err, "Failed to parse existing certificate expiry time", "expiryTime", user.Status.ExpiryTime)
		}
	}

	return changed
}

// finishReconcile handles the final status update and error logging.
// It supports both error and result-based returns for flexibility.
func (r *UserReconciler) finishReconcile(ctx context.Context, user *authv1alpha1.User, statusChanged bool, args ...interface{}) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	// Update status if changed
	if statusChanged {
		if err := r.Status().Update(ctx, user); err != nil {
			logger.Error(err, "Failed to update user status during error handling")
			return ctrl.Result{RequeueAfter: 5 * time.Second}, err
		}
	}

	// Handle different argument patterns
	switch len(args) {
	case 1:
		// Single error argument
		if err, ok := args[0].(error); ok {
			return ctrl.Result{}, err
		}
	case 2:
		// Result and error arguments
		if result, ok := args[0].(ctrl.Result); ok {
			if err, ok := args[1].(error); ok {
				return result, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// calculateRequeue determines the optimal requeue strategy based on user state and configuration.
func (r *UserReconciler) calculateRequeue(ctx context.Context, user *authv1alpha1.User) ctrl.Result {
	logger := logf.FromContext(ctx)

	// No requeue for users in terminal states
	if user.Status.Phase == helpers.PhaseError || user.Status.Phase == helpers.PhaseExpired {
		logger.Info("User in terminal state, no requeue needed", "phase", user.Status.Phase)
		return ctrl.Result{}
	}

	// Smart requeue for auto-renewal enabled users
	if user.Spec.Auth.AutoRenew && user.Status.Phase == "Active" {
		requeueAfter, err := r.calculateSmartRequeue(ctx, user)
		if err != nil {
			logger.Error(err, "Failed to calculate smart requeue, using default")
			return ctrl.Result{RequeueAfter: 30 * time.Minute}
		}
		logger.Info("Smart requeue calculated", "requeueAfter", requeueAfter)
		return ctrl.Result{RequeueAfter: requeueAfter}
	}

	// Legacy expiry-based requeue for non-auto-renewal users
	if user.Status.Phase == "Active" && user.Status.ExpiryTime != "" {
		if expiryTime, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			timeUntilExpiry := time.Until(expiryTime)
			logger.Info("Time until expiry", "duration", timeUntilExpiry)

			if timeUntilExpiry <= 0 {
				// User has expired, mark as expired and update status
				logger.Info("User has expired, updating status")
				user.Status.Phase = helpers.PhaseExpired
				user.Status.Message = "User access has expired"
				// Note: Status update will be handled by the caller
				return ctrl.Result{}
			} else if timeUntilExpiry < 24*time.Hour {
				// Requeue to check expiry more frequently
				logger.Info("User expires soon, requeueing in 1 hour")
				return ctrl.Result{RequeueAfter: time.Hour}
			}
		} else {
			logger.Error(err, "Failed to parse expiry time", "expiryTime", user.Status.ExpiryTime)
		}
	}

	// Default requeue for active users
	logger.Info("Using default requeue interval")
	return ctrl.Result{RequeueAfter: 30 * time.Minute}
}

// calculateSmartRequeue calculates the optimal requeue time for auto-renewal.
// It uses NextRenewalAt from status when available for efficiency, with jitter to prevent thundering herd.
func (r *UserReconciler) calculateSmartRequeue(ctx context.Context, user *authv1alpha1.User) (time.Duration, error) {
	logger := logf.FromContext(ctx)

	// Initialize renewal calculator if not already done
	if r.RenewalCalculator == nil {
		r.RenewalCalculator = renewal.NewRenewalCalculator()
	}

	// Get certificate duration
	certDuration := auth.GetAuthDuration(user)

	// Use NextRenewalAt from status if available (most efficient)
	if user.Status.NextRenewalAt != nil {
		now := time.Now()
		renewalTime := user.Status.NextRenewalAt.Time

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

		logger.Info("Smart requeue calculated from NextRenewalAt",
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
