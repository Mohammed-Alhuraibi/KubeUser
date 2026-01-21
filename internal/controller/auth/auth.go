package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Auth type constants
const (
	AuthTypeX509 = "x509"
	AuthTypeOIDC = "oidc"
)

// Provider defines the interface for authentication providers
type Provider interface {
	// Ensure creates or updates authentication credentials for the user
	Ensure(ctx context.Context, user *authv1alpha1.User) error

	// Revoke removes authentication credentials for the user
	Revoke(ctx context.Context, user *authv1alpha1.User) error
}

// Manager handles routing to appropriate auth providers
type Manager struct {
	client client.Client
	x509   Provider
	oidc   Provider
}

// NewManager creates a new auth manager with the provided client
func NewManager(c client.Client) *Manager {
	return &Manager{
		client: c,
		x509:   NewX509Provider(c),
		oidc:   NewOIDCProvider(c),
	}
}

// Ensure delegates to the appropriate auth provider based on user spec
func (m *Manager) Ensure(ctx context.Context, user *authv1alpha1.User) error {
	// Validate renewal configuration first
	if err := ValidateRenewalConfig(user); err != nil {
		return fmt.Errorf("invalid renewal configuration: %w", err)
	}

	provider, err := m.getProvider(user)
	if err != nil {
		return err
	}

	return provider.Ensure(ctx, user)
}

// Revoke delegates to the appropriate auth provider based on user spec
func (m *Manager) Revoke(ctx context.Context, user *authv1alpha1.User) error {
	provider, err := m.getProvider(user)
	if err != nil {
		return err
	}

	return provider.Revoke(ctx, user)
}

// getProvider returns the appropriate auth provider based on user spec
func (m *Manager) getProvider(user *authv1alpha1.User) (Provider, error) {
	authType := user.Spec.Auth.Type
	if authType == "" {
		authType = AuthTypeX509 // default
	}

	switch authType {
	case AuthTypeX509:
		return m.x509, nil
	case AuthTypeOIDC:
		return m.oidc, nil
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", authType)
	}
}

// ValidateAuthSpec validates the auth specification for the user
func ValidateAuthSpec(user *authv1alpha1.User) error {
	authSpec := user.Spec.Auth

	// Validate auth type
	if authSpec.Type != "" && authSpec.Type != AuthTypeX509 && authSpec.Type != AuthTypeOIDC {
		return fmt.Errorf("unsupported auth type: %s, must be '%s' or '%s'", authSpec.Type, AuthTypeX509, AuthTypeOIDC)
	}

	// Validate TTL for x509
	if authSpec.Type == AuthTypeX509 || authSpec.Type == "" {
		if authSpec.TTL != "" {
			duration, err := time.ParseDuration(authSpec.TTL)
			if err != nil {
				return fmt.Errorf("invalid TTL format: %v", err)
			}

			if duration <= 0 {
				return fmt.Errorf("TTL must be positive, got: %v", duration)
			}

			// Enforce minimum duration (configurable for testing)
			minDuration := getMinimumDuration()
			if duration < minDuration {
				return fmt.Errorf("TTL must be at least %v, got: %v", minDuration, duration)
			}

			// Enforce maximum duration (1 year)
			maxDuration := 365 * 24 * time.Hour
			if duration > maxDuration {
				return fmt.Errorf("TTL must not exceed %v, got: %v", maxDuration, duration)
			}
		}
	}

	// For OIDC, TTL is ignored (placeholder)

	return nil
}

// GetAuthDuration returns the parsed duration from auth spec, with defaults
func GetAuthDuration(user *authv1alpha1.User) time.Duration {
	authSpec := user.Spec.Auth

	// Default duration is 3 months
	defaultDuration := 90 * 24 * time.Hour // 2160h

	if authSpec.TTL == "" {
		return defaultDuration
	}

	duration, err := time.ParseDuration(authSpec.TTL)
	if err != nil {
		return defaultDuration
	}

	return duration
}

// getMinimumDuration returns the minimum allowed duration for certificates
// Can be overridden with KUBEUSER_MIN_DURATION environment variable for testing
// Note: Kubernetes requires a minimum of 10 minutes (600 seconds) for CSR expirationSeconds
func getMinimumDuration() time.Duration {
	if minDurStr := os.Getenv("KUBEUSER_MIN_DURATION"); minDurStr != "" {
		if minDur, err := time.ParseDuration(minDurStr); err == nil {
			return minDur
		}
	}
	// Default minimum is 10 minutes (Kubernetes minimum requirement)
	return 10 * time.Minute
}

// ValidateRenewalConfig validates the renewal configuration in the user spec
func ValidateRenewalConfig(user *authv1alpha1.User) error {
	if !user.Spec.Auth.AutoRenew {
		return nil // No validation needed if auto-renewal is disabled
	}

	// Parse certificate duration
	var certDuration time.Duration
	if user.Spec.Auth.TTL != "" {
		var err error
		certDuration, err = time.ParseDuration(user.Spec.Auth.TTL)
		if err != nil {
			return fmt.Errorf("invalid TTL format: %v", err)
		}
	} else {
		certDuration = 90 * 24 * time.Hour // Default 3 months
	}

	// Validate renewBefore if specified
	if user.Spec.Auth.RenewBefore != nil {
		renewBefore := user.Spec.Auth.RenewBefore.Duration

		if renewBefore <= 0 {
			return fmt.Errorf("renewBefore must be positive, got: %v", renewBefore)
		}

		if renewBefore >= certDuration {
			return fmt.Errorf("renewBefore (%v) must be less than certificate TTL (%v)", renewBefore, certDuration)
		}

		// Ensure renewBefore is at least 2 minutes for very short certificates
		minBuffer := 2 * time.Minute
		if renewBefore < minBuffer && certDuration <= 10*time.Minute {
			return fmt.Errorf("renewBefore (%v) must be at least %v for certificates shorter than 10 minutes", renewBefore, minBuffer)
		}
	}

	return nil
}
