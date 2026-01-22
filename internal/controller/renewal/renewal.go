/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package renewal

import (
	"fmt"
	"math/rand"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// DefaultRenewalPercentage is the default percentage of certificate lifetime
	// after which renewal should occur (cert-manager style: 1/3 = 33%)
	DefaultRenewalPercentage = 0.33

	// MinimumRenewalBuffer is the absolute minimum time before expiry
	// that we must maintain for short-lived certificates (safety floor)
	MinimumRenewalBuffer = 2 * time.Minute

	// MaxJitterPercentage is the maximum jitter to add to renewal time
	// to prevent thundering herd (5% of renewal window)
	MaxJitterPercentage = 0.05
)

// RenewalCalculator handles smart renewal time calculations
type RenewalCalculator struct {
	// MinRenewalBuffer can be overridden for testing
	MinRenewalBuffer time.Duration
}

// NewRenewalCalculator creates a new renewal calculator
func NewRenewalCalculator() *RenewalCalculator {
	return &RenewalCalculator{
		MinRenewalBuffer: MinimumRenewalBuffer,
	}
}

// CalculateRenewalTime implements the smart renewal calculation logic
// Hierarchy: Custom renewBefore > 33% Rule > Safety Floor
func (rc *RenewalCalculator) CalculateRenewalTime(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (time.Time, error) {
	var renewalTime time.Time

	// Validate inputs
	if certDuration <= 0 {
		return time.Time{}, fmt.Errorf("certificate duration must be positive, got: %v", certDuration)
	}

	if certExpiry.IsZero() {
		return time.Time{}, fmt.Errorf("certificate expiry time cannot be zero")
	}

	// Step 1: Check for custom renewBefore setting
	if user.Spec.Auth.RenewBefore != nil {
		customRenewBefore := user.Spec.Auth.RenewBefore.Duration

		// Validate that renewBefore is less than certificate duration
		if customRenewBefore >= certDuration {
			return time.Time{}, fmt.Errorf("renewBefore (%v) must be less than certificate TTL (%v)", customRenewBefore, certDuration)
		}

		// Additional validation for very short certificates
		if customRenewBefore <= 0 {
			return time.Time{}, fmt.Errorf("renewBefore must be positive, got: %v", customRenewBefore)
		}

		renewalTime = certExpiry.Add(-customRenewBefore)
	} else {
		// Step 2: Apply 33% rule (cert-manager style)
		renewalBuffer := time.Duration(float64(certDuration) * DefaultRenewalPercentage)
		renewalTime = certExpiry.Add(-renewalBuffer)
	}

	// Step 3: Apply safety floor for short-lived certificates
	safetyFloorTime := certExpiry.Add(-rc.MinRenewalBuffer)
	if renewalTime.After(safetyFloorTime) {
		renewalTime = safetyFloorTime
	}

	// Step 4: Ensure renewal time is not in the past
	now := time.Now()
	if renewalTime.Before(now) {
		// Certificate needs immediate renewal
		renewalTime = now
	}

	return renewalTime, nil
}

// CalculateRenewalTimeWithJitter adds jitter to prevent thundering herd
func (rc *RenewalCalculator) CalculateRenewalTimeWithJitter(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (time.Time, error) {
	baseRenewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		return time.Time{}, err
	}

	// Calculate jitter window (5% of the renewal buffer)
	renewalBuffer := certExpiry.Sub(baseRenewalTime)
	jitterWindow := time.Duration(float64(renewalBuffer) * MaxJitterPercentage)

	// Add random jitter (can be negative to spread load)
	jitter := time.Duration(rand.Int63n(int64(jitterWindow*2))) - jitterWindow

	return baseRenewalTime.Add(jitter), nil
}

// ShouldRenewNow checks if a certificate should be renewed immediately
func (rc *RenewalCalculator) ShouldRenewNow(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (bool, error) {
	renewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		return false, err
	}

	return time.Now().After(renewalTime), nil
}

// GetRequeueAfter calculates the duration until the next renewal check
func (rc *RenewalCalculator) GetRequeueAfter(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (time.Duration, error) {
	renewalTime, err := rc.CalculateRenewalTimeWithJitter(user, certExpiry, certDuration)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	if renewalTime.Before(now) {
		// Should renew immediately
		return 0, nil
	}

	requeueAfter := renewalTime.Sub(now)

	// Cap the requeue time to reasonable limits
	maxRequeue := 24 * time.Hour
	if requeueAfter > maxRequeue {
		requeueAfter = maxRequeue
	}

	// Minimum requeue time to avoid excessive API calls
	minRequeue := 1 * time.Minute
	if requeueAfter < minRequeue {
		requeueAfter = minRequeue
	}

	return requeueAfter, nil
}

// UpdateUserRenewalStatus updates the user status with renewal information
func (rc *RenewalCalculator) UpdateUserRenewalStatus(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) error {
	renewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		return err
	}

	// Update status fields with consolidated NextRenewalAt
	user.Status.ExpiryTime = certExpiry.Format(time.RFC3339)
	user.Status.NextRenewalAt = &metav1.Time{Time: renewalTime}
	user.Status.CertificateExpiry = "Certificate"

	return nil
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
			// Auto-fix: set renewBefore to 50% of TTL if it's >= TTL
			fixedRenewBefore := time.Duration(float64(certDuration) * 0.5)
			user.Spec.Auth.RenewBefore = &metav1.Duration{Duration: fixedRenewBefore}
			return fmt.Errorf("renewBefore (%v) was >= TTL (%v), auto-corrected to 50%% of TTL (%v)", renewBefore, certDuration, fixedRenewBefore)
		}

		// Ensure renewBefore is at least 2 minutes shorter than TTL for safety
		minSafetyBuffer := 2 * time.Minute
		if certDuration-renewBefore < minSafetyBuffer {
			// Auto-fix: ensure at least 2 minutes safety buffer
			fixedRenewBefore := certDuration - minSafetyBuffer
			if fixedRenewBefore <= 0 {
				// For very short certificates, use 50% rule
				fixedRenewBefore = time.Duration(float64(certDuration) * 0.5)
			}
			user.Spec.Auth.RenewBefore = &metav1.Duration{Duration: fixedRenewBefore}
			return fmt.Errorf("renewBefore (%v) too close to TTL (%v), auto-corrected to %v for safety", renewBefore, certDuration, fixedRenewBefore)
		}
	}

	return nil
}

// CalculateNextRenewal calculates the next renewal time based on certificate info
func CalculateNextRenewal(issuedAt, expiry time.Time, renewBefore *metav1.Duration) metav1.Time {
	var renewalTime time.Time

	certDuration := expiry.Sub(issuedAt)

	if renewBefore != nil {
		// Use custom renewBefore setting
		renewalTime = expiry.Add(-renewBefore.Duration)
	} else {
		// Use 1/3 rule (cert-manager standard)
		renewalBuffer := time.Duration(float64(certDuration) * DefaultRenewalPercentage)
		renewalTime = expiry.Add(-renewalBuffer)
	}

	// Safety floor: ensure at least 2 minutes before expiry
	safetyFloorTime := expiry.Add(-MinimumRenewalBuffer)
	if renewalTime.After(safetyFloorTime) {
		renewalTime = safetyFloorTime
	}

	// Ensure renewal time is not in the past
	now := time.Now()
	if renewalTime.Before(now) {
		renewalTime = now
	}

	return metav1.Time{Time: renewalTime}
}
