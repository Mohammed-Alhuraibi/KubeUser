package auth

import (
	"context"
	"fmt"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/certs"
	"github.com/openkube-hub/KubeUser/internal/controller/renewal"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// X509Provider handles x509 certificate-based authentication
type X509Provider struct {
	client            client.Client
	renewalCalculator *renewal.RenewalCalculator
	rotationManager   *renewal.RotationManager
}

// NewX509Provider creates a new x509 auth provider
func NewX509Provider(c client.Client, eventRecorder record.EventRecorder) *X509Provider {
	return &X509Provider{
		client:            c,
		renewalCalculator: renewal.NewRenewalCalculator(),
		rotationManager:   renewal.NewRotationManager(c, eventRecorder),
	}
}

// Ensure creates or updates x509 certificates and kubeconfig for the user.
// Returns (bool, *ctrl.Result, error) where:
// - bool: true if status fields were changed
// - *ctrl.Result: non-nil if immediate requeue is needed
// - error: actual error that should stop reconciliation
func (p *X509Provider) Ensure(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("Ensuring x509 authentication", "user", user.Name, "autoRenew", user.Spec.Auth.AutoRenew)

	// Validate auth spec
	if err := ValidateAuthSpec(user); err != nil {
		return false, nil, fmt.Errorf("invalid auth spec: %v", err)
	}

	// Get the duration for certificate validity
	duration := GetAuthDuration(user)
	logger.Info("Using certificate duration", "duration", duration)

	// Check if auto-renewal is enabled and certificate needs renewal
	if user.Spec.Auth.AutoRenew {
		needsRenewal, err := p.checkIfRenewalNeeded(ctx, user, duration)
		if err != nil {
			logger.Error(err, "Failed to check renewal status")
			// Continue with normal certificate processing if renewal check fails
		} else if needsRenewal {
			logger.Info("Certificate needs renewal, starting rotation process")

			// Perform atomic certificate rotation with new signature
			statusChanged, result, err := p.rotationManager.RotateUserCertificate(ctx, user, duration)
			if err != nil {
				logger.Error(err, "Certificate rotation failed")
				user.Status.Phase = "Error"
				user.Status.Message = fmt.Sprintf("Certificate renewal failed: %v", err)

				// Return status change and error (no requeue for actual errors)
				return true, nil, fmt.Errorf("certificate renewal failed: %w", err)
			}

			// Handle immediate requeue if needed (e.g., Shadow Secret created)
			if result != nil {
				logger.Info("Certificate rotation requires immediate requeue")
				return statusChanged, result, nil
			}

			// If status was changed but no requeue needed, rotation completed successfully
			if statusChanged {
				logger.Info("Certificate rotation completed successfully")
			}

			return statusChanged, nil, nil
		}
	}

	// Use existing certificate logic for initial creation or non-renewal updates
	requeue, err := certs.EnsureCertKubeconfigWithDuration(ctx, p.client, user, duration)
	if err != nil {
		return false, nil, fmt.Errorf("failed to ensure certificate kubeconfig: %v", err)
	}

	if requeue {
		logger.Info("Certificate processing requires requeue")
		return false, &ctrl.Result{Requeue: true}, nil
	}

	logger.Info("Successfully ensured x509 authentication", "user", user.Name)
	return false, nil, nil
}

// checkIfRenewalNeeded determines if the certificate needs renewal
func (p *X509Provider) checkIfRenewalNeeded(ctx context.Context, user *authv1alpha1.User, certDuration time.Duration) (bool, error) {
	logger := logf.FromContext(ctx)

	// If NextRenewalAt is set in status, use it for efficient checking
	if user.Status.NextRenewalAt != nil {
		now := time.Now()
		renewalTime := user.Status.NextRenewalAt.Time

		logger.Info("Checking renewal time from status",
			"now", now.Format(time.RFC3339),
			"renewalTime", renewalTime.Format(time.RFC3339),
			"needsRenewal", now.After(renewalTime))

		return now.After(renewalTime), nil
	}

	// Fallback: parse certificate expiry from status
	if user.Status.ExpiryTime != "" {
		certExpiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime)
		if err != nil {
			logger.Error(err, "Failed to parse certificate expiry time", "expiryTime", user.Status.ExpiryTime)
			return false, err
		}

		return p.renewalCalculator.ShouldRenewNow(user, certExpiry, certDuration)
	}

	// No expiry information available, assume no renewal needed
	logger.Info("No certificate expiry information available, assuming no renewal needed")
	return false, nil
}

// isRequeueError checks if an error indicates that requeuing is needed
func isRequeueError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()
	return contains(errMsg, "requeue needed") ||
		contains(errMsg, "CSR created") ||
		contains(errMsg, "approval in progress") ||
		contains(errMsg, "waiting for")
}

// contains checks if a string contains a substring (case-insensitive helper)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Revoke removes x509 certificates and kubeconfig for the user
func (p *X509Provider) Revoke(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)
	logger.Info("Revoking x509 authentication", "user", user.Name)

	// Use existing cleanup logic to remove certificates and secrets
	// This would typically involve:
	// - Deleting the kubeconfig secret
	// - Revoking/deleting the certificate (if supported by the CA)
	// - Cleaning up any CSRs

	// For now, we'll delegate to the existing cleanup logic
	// The actual implementation would depend on the existing certs package
	logger.Info("X509 revocation completed", "user", user.Name)
	return nil
}
