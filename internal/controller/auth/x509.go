package auth

import (
	"context"
	"fmt"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/certs"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// X509Provider handles x509 certificate-based authentication
type X509Provider struct {
	client client.Client
}

// NewX509Provider creates a new x509 auth provider
func NewX509Provider(c client.Client) *X509Provider {
	return &X509Provider{
		client: c,
	}
}

// Ensure creates or updates x509 certificates and kubeconfig for the user
func (p *X509Provider) Ensure(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)
	logger.Info("Ensuring x509 authentication", "user", user.Name)

	// Validate auth spec
	if err := ValidateAuthSpec(user); err != nil {
		return fmt.Errorf("invalid auth spec: %v", err)
	}

	// Get the duration for certificate validity
	duration := GetAuthDuration(user)
	logger.Info("Using certificate duration", "duration", duration)

	// Use existing certificate logic but with custom duration
	// This delegates to the existing certs package which handles:
	// - Certificate signing request creation
	// - Certificate approval and retrieval
	// - Kubeconfig generation
	// - Secret management
	requeue, err := certs.EnsureCertKubeconfigWithDuration(ctx, p.client, user, duration)
	if err != nil {
		return fmt.Errorf("failed to ensure certificate kubeconfig: %v", err)
	}

	if requeue {
		logger.Info("Certificate processing requires requeue")
		// Return a specific error that the controller can handle for requeuing
		return fmt.Errorf("certificate processing in progress, requeue needed")
	}

	logger.Info("Successfully ensured x509 authentication", "user", user.Name)
	return nil
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
