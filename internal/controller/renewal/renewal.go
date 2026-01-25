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

	if certDuration <= 0 || certExpiry.IsZero() {
		return time.Time{}, fmt.Errorf("invalid duration or expiry")
	}

	// Step 1: Prioritize custom renewBefore
	if user.Spec.Auth.RenewBefore != nil && user.Spec.Auth.RenewBefore.Duration > 0 {
		customRenewBefore := user.Spec.Auth.RenewBefore.Duration

		// Safety Check: If RenewBefore is actually longer than the TTL,
		// we force it to 50% so the cert has at least some life.
		if customRenewBefore >= certDuration {
			customRenewBefore = time.Duration(float64(certDuration) * 0.5)
		}

		renewalTime = certExpiry.Add(-customRenewBefore)
	} else {
		// Step 2: Fallback to 33% rule
		renewalBuffer := time.Duration(float64(certDuration) * DefaultRenewalPercentage)
		renewalTime = certExpiry.Add(-renewalBuffer)
	}

	// Step 3: Global Safety Floor
	// Ensure we NEVER renew later than 2 minutes before expiry
	latestAllowedRenewal := certExpiry.Add(-rc.MinRenewalBuffer)
	if renewalTime.After(latestAllowedRenewal) {
		renewalTime = latestAllowedRenewal
	}

	// Step 4: Don't return a time in the past
	if renewalTime.Before(time.Now()) {
		return time.Now(), nil
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

	// Only set NextRenewalAt if auto-renewal is enabled
	if user.Spec.Auth.AutoRenew {
		user.Status.NextRenewalAt = &metav1.Time{Time: renewalTime}
	} else {
		// Explicitly clear the field if auto-renewal is disabled
		user.Status.NextRenewalAt = nil
	}

	return nil
}

// ValidateRenewalConfig validates the renewal configuration in the user spec
// Controller mode: Auto-corrects dangerous values and logs warnings
// Webhook mode: Should reject dangerous configurations (handled in webhook layer)
func ValidateRenewalConfig(user *authv1alpha1.User) error {
	if !user.Spec.Auth.AutoRenew {
		return nil
	}

	var certDuration time.Duration
	if user.Spec.Auth.TTL != "" {
		d, err := time.ParseDuration(user.Spec.Auth.TTL)
		if err != nil {
			return fmt.Errorf("invalid TTL format: %v", err)
		}
		certDuration = d
	} else {
		certDuration = 90 * 24 * time.Hour // Default 90 days
	}

	if user.Spec.Auth.RenewBefore != nil {
		renewBefore := user.Spec.Auth.RenewBefore.Duration

		if renewBefore <= 0 {
			return fmt.Errorf("renewBefore must be positive")
		}

		// PRODUCTION HARDENING: Strictly cap renewBefore at 50% of TTL
		// This prevents aggressive renewal loops and API-server exhaustion
		maxAllowed := time.Duration(float64(certDuration) * 0.5)
		if renewBefore > maxAllowed {
			// Controller auto-corrects in memory and logs warning
			user.Spec.Auth.RenewBefore = &metav1.Duration{Duration: maxAllowed}
			return fmt.Errorf("renewBefore too aggressive, capped at 50%% (%v) for production stability", maxAllowed)
		}

		// PRODUCTION HARDENING: Fixed 5-minute safety floor
		// Ensures even short-lived test certificates have guaranteed life before renewal
		const safetyFloor = 5 * time.Minute
		if certDuration-renewBefore < safetyFloor {
			fixed := certDuration - safetyFloor
			if fixed <= 0 {
				fixed = time.Duration(float64(certDuration) * 0.5) // Fallback to 50%
			}
			user.Spec.Auth.RenewBefore = &metav1.Duration{Duration: fixed}
			return fmt.Errorf("renewBefore too close to expiry, auto-corrected to %v for safety (5-minute buffer)", fixed)
		}
	}
	return nil
}

// CalculateNextRenewal calculates the next renewal time based on certificate info
// PRODUCTION HARDENING: Uses fixed 5-minute safety floor instead of proportional buffer
func CalculateNextRenewal(issuedAt, expiry time.Time, renewBefore *metav1.Duration) metav1.Time {
	certDuration := expiry.Sub(issuedAt)
	var renewalTime time.Time

	if renewBefore != nil {
		renewalTime = expiry.Add(-renewBefore.Duration)
	} else {
		renewalBuffer := time.Duration(float64(certDuration) * DefaultRenewalPercentage)
		renewalTime = expiry.Add(-renewalBuffer)
	}

	// PRODUCTION HARDENING: Fixed 5-minute safety floor
	// Guarantees at least 5 minutes of certificate life before renewal triggers
	// Prevents immediate renewal loops even for short-lived test certificates
	const safetyFloor = 5 * time.Minute
	safetyFloorTime := expiry.Add(-safetyFloor)
	if renewalTime.After(safetyFloorTime) {
		renewalTime = safetyFloorTime
	}

	if renewalTime.Before(time.Now()) {
		renewalTime = time.Now()
	}

	return metav1.Time{Time: renewalTime}
}
