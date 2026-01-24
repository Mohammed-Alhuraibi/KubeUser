/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package observability

import (
	"context"
	"fmt"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// EventRecorder provides methods for recording Kubernetes events related to certificate renewal
type EventRecorder struct {
	client   client.Client
	recorder record.EventRecorder
	scheme   *runtime.Scheme
}

// NewEventRecorder creates a new event recorder
func NewEventRecorder(k8sClient client.Client, recorder record.EventRecorder, scheme *runtime.Scheme) *EventRecorder {
	return &EventRecorder{
		client:   k8sClient,
		recorder: recorder,
		scheme:   scheme,
	}
}

// RecordRenewalStarted records an event when certificate renewal starts
func (er *EventRecorder) RecordRenewalStarted(ctx context.Context, user *authv1alpha1.User, renewalTime time.Time) {
	message := fmt.Sprintf("Certificate renewal started. Next renewal scheduled for %s", renewalTime.Format(time.RFC3339))
	er.recorder.Event(user, corev1.EventTypeNormal, "RenewalStarted", message)

	logger := logf.FromContext(ctx)
	logger.Info("Recorded renewal started event", "user", user.Name, "renewalTime", renewalTime)
}

// RecordRenewalCompleted records an event when certificate renewal completes successfully
func (er *EventRecorder) RecordRenewalCompleted(ctx context.Context, user *authv1alpha1.User, newExpiry time.Time) {
	message := fmt.Sprintf("Certificate renewal completed successfully. New certificate expires at %s", newExpiry.Format(time.RFC3339))
	er.recorder.Event(user, corev1.EventTypeNormal, "RenewalCompleted", message)

	logger := logf.FromContext(ctx)
	logger.Info("Recorded renewal completed event", "user", user.Name, "newExpiry", newExpiry)
}

// RecordRenewalFailed records an event when certificate renewal fails
func (er *EventRecorder) RecordRenewalFailed(ctx context.Context, user *authv1alpha1.User, err error) {
	message := fmt.Sprintf("Certificate renewal failed: %v", err)
	er.recorder.Event(user, corev1.EventTypeWarning, "RenewalFailed", message)

	logger := logf.FromContext(ctx)
	logger.Error(err, "Recorded renewal failed event", "user", user.Name)
}

// RecordRenewalScheduled records an event when the next renewal is scheduled
func (er *EventRecorder) RecordRenewalScheduled(ctx context.Context, user *authv1alpha1.User, nextRenewal time.Time) {
	timeUntilRenewal := time.Until(nextRenewal)
	message := fmt.Sprintf("Next certificate renewal scheduled for %s (in %s)",
		nextRenewal.Format(time.RFC3339),
		timeUntilRenewal.Round(time.Minute))
	er.recorder.Event(user, corev1.EventTypeNormal, "RenewalScheduled", message)

	logger := logf.FromContext(ctx)
	logger.Info("Recorded renewal scheduled event", "user", user.Name, "nextRenewal", nextRenewal)
}

// RecordCertificateExpiring records an event when certificate is approaching expiry
func (er *EventRecorder) RecordCertificateExpiring(ctx context.Context, user *authv1alpha1.User, expiry time.Time) {
	timeUntilExpiry := time.Until(expiry)
	message := fmt.Sprintf("Certificate is expiring soon. Expires at %s (in %s)",
		expiry.Format(time.RFC3339),
		timeUntilExpiry.Round(time.Minute))
	er.recorder.Event(user, corev1.EventTypeWarning, "CertificateExpiring", message)

	logger := logf.FromContext(ctx)
	logger.Info("Recorded certificate expiring event", "user", user.Name, "expiry", expiry)
}

// RecordAutoRenewalEnabled records an event when auto-renewal is enabled
func (er *EventRecorder) RecordAutoRenewalEnabled(ctx context.Context, user *authv1alpha1.User) {
	var message string
	if user.Spec.Auth.RenewBefore != nil {
		message = fmt.Sprintf("Auto-renewal enabled with custom renewBefore: %s", user.Spec.Auth.RenewBefore.Duration)
	} else {
		message = "Auto-renewal enabled with default 33% renewal threshold"
	}
	er.recorder.Event(user, corev1.EventTypeNormal, "AutoRenewalEnabled", message)

	logger := logf.FromContext(ctx)
	logger.Info("Recorded auto-renewal enabled event", "user", user.Name)
}

// RecordAutoRenewalDisabled records an event when auto-renewal is disabled
func (er *EventRecorder) RecordAutoRenewalDisabled(ctx context.Context, user *authv1alpha1.User) {
	message := "Auto-renewal disabled. Certificate will not be automatically renewed"
	er.recorder.Event(user, corev1.EventTypeNormal, "AutoRenewalDisabled", message)

	logger := logf.FromContext(ctx)
	logger.Info("Recorded auto-renewal disabled event", "user", user.Name)
}

// UpdateConditions updates the status conditions for the user
func UpdateConditions(user *authv1alpha1.User, conditionType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()

	newCondition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	// Find existing condition and update it, or append new one
	updated := false
	for i, condition := range user.Status.Conditions {
		if condition.Type == conditionType {
			// Only update LastTransitionTime if status changed
			if condition.Status != status {
				user.Status.Conditions[i] = newCondition
			} else {
				// Keep original transition time but update reason and message
				user.Status.Conditions[i].Reason = reason
				user.Status.Conditions[i].Message = message
			}
			updated = true
			break
		}
	}

	if !updated {
		user.Status.Conditions = append(user.Status.Conditions, newCondition)
	}
}

// SetReadyCondition sets the Ready condition
func SetReadyCondition(user *authv1alpha1.User, ready bool, reason, message string) {
	status := metav1.ConditionTrue
	if !ready {
		status = metav1.ConditionFalse
	}
	UpdateConditions(user, "Ready", status, reason, message)
}

// SetRenewingCondition sets the Renewing condition
func SetRenewingCondition(user *authv1alpha1.User, renewing bool, reason, message string) {
	status := metav1.ConditionTrue
	if !renewing {
		status = metav1.ConditionFalse
	}
	UpdateConditions(user, "Renewing", status, reason, message)
}

// SetAutoRenewalCondition sets the AutoRenewal condition
func SetAutoRenewalCondition(user *authv1alpha1.User, enabled bool, reason, message string) {
	status := metav1.ConditionTrue
	if !enabled {
		status = metav1.ConditionFalse
	}
	UpdateConditions(user, "AutoRenewal", status, reason, message)
}
