package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Auth type constants
const (
	AuthTypeX509 = "x509"
	AuthTypeOIDC = "oidc"
)

// Default values for authentication configuration
const (
	DefaultTTL = "2160h" // 90 days
)

// Provider defines the interface for authentication providers
type Provider interface {
	// Ensure creates or updates authentication credentials for the user
	// Returns (bool, *ctrl.Result, error) where:
	// - bool: true if status fields were changed
	// - *ctrl.Result: non-nil if immediate requeue is needed
	// - error: actual error that should stop reconciliation
	Ensure(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error)

	// Revoke removes authentication credentials for the user
	Revoke(ctx context.Context, user *authv1alpha1.User) error
}

// Manager handles routing to appropriate auth providers
type Manager struct {
	client        client.Client
	eventRecorder record.EventRecorder
	x509          Provider
	oidc          Provider
}

// NewManager creates a new auth manager with the provided client and event recorder
func NewManager(c client.Client, eventRecorder record.EventRecorder) *Manager {
	return &Manager{
		client:        c,
		eventRecorder: eventRecorder,
		x509:          NewX509Provider(c, eventRecorder),
		oidc:          NewOIDCProvider(c),
	}
}

// Ensure delegates to the appropriate auth provider based on user spec.
// Returns (bool, *ctrl.Result, error) where:
// - bool: true if status fields were changed
// - *ctrl.Result: non-nil if immediate requeue is needed
// - error: actual error that should stop reconciliation
func (m *Manager) Ensure(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error) {
	// Validate renewal configuration first
	if err := ValidateRenewalConfig(user); err != nil {
		return false, nil, fmt.Errorf("invalid renewal configuration: %w", err)
	}

	provider, err := m.getProvider(user)
	if err != nil {
		return false, nil, err
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
// MANDATORY IDENTITY: Auth type must be explicitly specified (no defaults)
func (m *Manager) getProvider(user *authv1alpha1.User) (Provider, error) {
	// MANDATORY IDENTITY ENFORCEMENT: Auth must be non-nil
	if user.Spec.Auth == nil {
		return nil, fmt.Errorf("authentication section is mandatory: spec.auth must be specified")
	}

	// MANDATORY IDENTITY ENFORCEMENT: Type must be non-nil pointer
	if user.Spec.Auth.Type == nil {
		return nil, fmt.Errorf("authentication type is mandatory: spec.auth.type must be specified")
	}

	authType := *user.Spec.Auth.Type

	// MANDATORY IDENTITY ENFORCEMENT: No defaulting - type must be explicit
	if authType == "" {
		return nil, fmt.Errorf("authentication type is mandatory: spec.auth.type must be specified")
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
// MANDATORY IDENTITY: Enforces explicit authentication type specification
func ValidateAuthSpec(user *authv1alpha1.User) error {
	// MANDATORY IDENTITY ENFORCEMENT: Auth must be non-nil
	if user.Spec.Auth == nil {
		return fmt.Errorf("authentication section is mandatory: spec.auth must be specified")
	}

	authSpec := *user.Spec.Auth

	// MANDATORY IDENTITY ENFORCEMENT: Auth type must be explicitly specified (nil pointer check)
	if authSpec.Type == nil || *authSpec.Type == "" {
		return fmt.Errorf("authentication type is mandatory: spec.auth.type must be specified (e.g., 'x509' or 'oidc')")
	}

	authType := *authSpec.Type

	// Validate auth type is supported
	if authType != AuthTypeX509 && authType != AuthTypeOIDC {
		return fmt.Errorf("unsupported auth type: %s, must be '%s' or '%s'", authType, AuthTypeX509, AuthTypeOIDC)
	}

	// Validate TTL for x509
	if authType == AuthTypeX509 {
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
	// Default duration is 90 days (2160h)
	defaultDuration := 90 * 24 * time.Hour

	// Defensive check: if Auth is nil, return default
	if user.Spec.Auth == nil {
		return defaultDuration
	}

	authSpec := *user.Spec.Auth

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
// Production default is 24h to prevent Thundering Herd loops and API-server exhaustion
func getMinimumDuration() time.Duration {
	if minDurStr := os.Getenv("KUBEUSER_MIN_DURATION"); minDurStr != "" {
		if minDur, err := time.ParseDuration(minDurStr); err == nil {
			return minDur
		}
	}
	// Production minimum is 24 hours to prevent excessive renewal loops
	return 24 * time.Hour
}

// ValidateRenewalConfig validates the renewal configuration in the user spec
func ValidateRenewalConfig(user *authv1alpha1.User) error {
	// Defensive check: if Auth is nil, return error
	if user.Spec.Auth == nil {
		return fmt.Errorf("authentication section is mandatory")
	}

	if !helpers.GetAutoRenew(user) {
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

// GetSafeAuthSpec returns a nil-safe AuthSpec with defaults applied.
// This is the SINGLE SOURCE OF TRUTH for authentication defaults across the entire system.
// Used by: Webhook (mutation), Controller (reconciliation), and Validation logic.
//
// Logic:
// - If user.Spec.Auth is nil, returns a zero-spec (validation will handle the error)
// - If Type is nil, returns zero-spec (invalid configuration)
// - Applies production defaults for secondary fields:
//   - TTL: DefaultTTL (2160h = 90 days)
//   - AutoRenew: true
//
// This ensures the mutating webhook persists the exact same defaults that the controller expects.
func GetSafeAuthSpec(user *authv1alpha1.User) authv1alpha1.AuthSpec {
	// Return zero-spec if Auth is nil; webhook prevents this in production
	if user.Spec.Auth == nil {
		return authv1alpha1.AuthSpec{}
	}

	spec := *user.Spec.Auth

	// Handle nil Type pointer - return zero-spec to signify invalid configuration
	if spec.Type == nil {
		return authv1alpha1.AuthSpec{}
	}

	// Apply defaults for secondary fields
	if spec.TTL == "" {
		spec.TTL = DefaultTTL
	}

	if spec.AutoRenew == nil {
		trueVal := true
		spec.AutoRenew = &trueVal
	}

	return spec
}
