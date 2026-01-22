/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package renewal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/certs"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// RotationState represents the current state of certificate rotation
type RotationState int

const (
	RotationStateIdle RotationState = iota
	RotationStateGeneratingKey
	RotationStateCreatingCSR
	RotationStateApprovingCSR
	RotationStateWaitingForCert
	RotationStateUpdatingSecret
	RotationStateComplete
	RotationStateError
)

// RotationManager handles atomic certificate rotation with forward secrecy
type RotationManager struct {
	client client.Client
}

// NewRotationManager creates a new rotation manager
func NewRotationManager(client client.Client) *RotationManager {
	return &RotationManager{
		client: client,
	}
}

// RotateUserCertificate performs atomic certificate rotation with forward secrecy
func (rm *RotationManager) RotateUserCertificate(ctx context.Context, user *authv1alpha1.User, certDuration time.Duration) error {
	logger := logf.FromContext(ctx)
	username := user.Name

	logger.Info("Starting atomic certificate rotation", "user", username, "duration", certDuration)

	// Record renewal attempt
	attempt := authv1alpha1.RenewalAttempt{
		Timestamp: metav1.Now(),
		Success:   false,
		Message:   "Starting certificate rotation",
	}

	// Step 1: Generate new private key for forward secrecy
	logger.Info("Generating new private key for forward secrecy")
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		attempt.Message = fmt.Sprintf("Failed to generate private key: %v", err)
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	newKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(newPrivateKey),
	})

	// Step 2: Create CSR from new key
	logger.Info("Creating CSR from new private key")
	csrPEM, err := rm.createCSRFromKey(username, newKeyPEM)
	if err != nil {
		attempt.Message = fmt.Sprintf("Failed to create CSR: %v", err)
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Step 3: Create deterministic CSR name for idempotency
	csrName := rm.generateCSRName(username)
	attempt.CSRName = csrName

	logger.Info("Creating CSR with deterministic name", "csrName", csrName)

	// Step 4: Create or get existing CSR
	csr, created, err := rm.createOrGetCSR(ctx, csrName, username, csrPEM, certDuration)
	if err != nil {
		attempt.Message = fmt.Sprintf("Failed to create/get CSR: %v", err)
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("failed to create/get CSR: %w", err)
	}

	if created {
		logger.Info("Created new CSR", "csrName", csrName)
		// CSR was just created, need to wait for it to be processed
		attempt.Message = "CSR created, waiting for approval"
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("CSR created, requeue needed for approval")
	}

	// Step 5: Auto-approve CSR if not already approved
	approved, err := rm.autoApproveCSR(ctx, csr)
	if err != nil {
		attempt.Message = fmt.Sprintf("Failed to approve CSR: %v", err)
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("failed to approve CSR: %w", err)
	}

	if !approved {
		logger.Info("CSR approval in progress", "csrName", csrName)
		attempt.Message = "CSR approval in progress"
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("CSR approval in progress, requeue needed")
	}

	// Step 6: Wait for signed certificate
	if len(csr.Status.Certificate) == 0 {
		logger.Info("Waiting for signed certificate", "csrName", csrName)
		attempt.Message = "Waiting for signed certificate"
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("waiting for signed certificate, requeue needed")
	}

	signedCert := csr.Status.Certificate
	logger.Info("Received signed certificate", "certLength", len(signedCert))

	// Step 7: Atomic secret update (zero-downtime)
	err = rm.atomicSecretUpdate(ctx, user, newKeyPEM, signedCert)
	if err != nil {
		attempt.Message = fmt.Sprintf("Failed to update secret: %v", err)
		rm.recordRenewalAttempt(user, attempt)
		return fmt.Errorf("failed to update secret atomically: %w", err)
	}

	// Step 8: Cleanup old CSR (best effort)
	if err := rm.cleanupCSR(ctx, csrName); err != nil {
		logger.Error(err, "Failed to cleanup CSR, will retry on next reconciliation", "csrName", csrName)
		// Don't fail the rotation for cleanup errors, but log for monitoring
	}

	// Step 9: Update user status with new certificate info (best effort)
	err = rm.updateUserStatusAfterRotation(ctx, user, signedCert, certDuration)
	if err != nil {
		logger.Error(err, "Failed to update user status after rotation, will retry on next reconciliation")
		// Don't fail the rotation for status update errors
	}

	// Record successful renewal
	attempt.Success = true
	attempt.Message = "Certificate rotation completed successfully"
	rm.recordRenewalAttempt(user, attempt)

	logger.Info("Certificate rotation completed successfully", "user", username)
	return nil
}

// generateCSRName creates a deterministic CSR name for idempotency
func (rm *RotationManager) generateCSRName(username string) string {
	// Use a more granular timestamp (1-minute windows) with rotation counter
	// This reduces collision probability while maintaining idempotency
	timestamp := time.Now().Unix() / 60 // 1-minute windows for better granularity
	return fmt.Sprintf("%s-renewal-%d", username, timestamp)
}

// createCSRFromKey creates a CSR from the given private key
func (rm *RotationManager) createCSRFromKey(username string, keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: username,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}), nil
}

// createOrGetCSR creates a new CSR or returns existing one for idempotency
func (rm *RotationManager) createOrGetCSR(ctx context.Context, csrName, username string, csrPEM []byte, certDuration time.Duration) (*certv1.CertificateSigningRequest, bool, error) {
	// Try to get existing CSR first
	var existingCSR certv1.CertificateSigningRequest
	err := rm.client.Get(ctx, types.NamespacedName{Name: csrName}, &existingCSR)
	if err == nil {
		// CSR already exists
		return &existingCSR, false, nil
	}

	if !apierrors.IsNotFound(err) {
		return nil, false, fmt.Errorf("failed to check for existing CSR: %w", err)
	}

	// Create new CSR
	expirationSeconds := int32(certDuration.Seconds())
	newCSR := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
			Labels: map[string]string{
				"auth.openkube.io/user":     username,
				"auth.openkube.io/renewal":  "true",
				"auth.openkube.io/rotation": "true",
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:           csrPEM,
			Usages:            []certv1.KeyUsage{certv1.UsageClientAuth},
			SignerName:        certv1.KubeAPIServerClientSignerName,
			ExpirationSeconds: &expirationSeconds,
		},
	}

	err = rm.client.Create(ctx, newCSR)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create CSR: %w", err)
	}

	return newCSR, true, nil
}

// autoApproveCSR approves the CSR using the controller's identity with validation
func (rm *RotationManager) autoApproveCSR(ctx context.Context, csr *certv1.CertificateSigningRequest) (bool, error) {
	logger := logf.FromContext(ctx)

	// Check if already approved
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certv1.CertificateApproved && condition.Status == corev1.ConditionTrue {
			return true, nil
		}
		if condition.Type == certv1.CertificateDenied && condition.Status == corev1.ConditionTrue {
			return false, fmt.Errorf("CSR was denied: %s", condition.Message)
		}
	}

	// Validate CSR before approval for security
	if err := rm.validateCSRForApproval(csr); err != nil {
		logger.Error(err, "CSR validation failed", "csrName", csr.Name)
		return false, fmt.Errorf("CSR validation failed: %w", err)
	}

	// Approve the CSR
	logger.Info("Auto-approving validated CSR", "csrName", csr.Name)
	csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         corev1.ConditionTrue,
		Reason:         "AutoApprovedByKubeUser",
		Message:        "Approved by kubeuser-operator for certificate renewal",
		LastUpdateTime: metav1.Now(),
	})

	err := rm.client.SubResource("approval").Update(ctx, csr)
	if err != nil {
		return false, fmt.Errorf("failed to approve CSR: %w", err)
	}

	return false, nil // Just approved, need to wait for certificate
}

// atomicSecretUpdate performs zero-downtime secret update with rollback capability
func (rm *RotationManager) atomicSecretUpdate(ctx context.Context, user *authv1alpha1.User, newKeyPEM, signedCert []byte) error {
	logger := logf.FromContext(ctx)
	username := user.Name
	userNamespace := helpers.GetKubeUserNamespace()

	// Get cluster CA and API server info
	caDataB64, err := rm.getClusterCABase64(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster CA: %w", err)
	}

	apiServer := rm.getAPIServerURL()

	// Build new kubeconfig
	newKubeconfig := rm.buildKubeconfig(apiServer, caDataB64, signedCert, newKeyPEM, username)

	// Backup existing secrets for rollback
	keySecretName := fmt.Sprintf("%s-key", username)
	cfgSecretName := fmt.Sprintf("%s-kubeconfig", username)

	var oldKeySecret, oldCfgSecret *corev1.Secret

	// Backup key secret
	oldKeySecret = &corev1.Secret{}
	err = rm.client.Get(ctx, types.NamespacedName{Name: keySecretName, Namespace: userNamespace}, oldKeySecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to backup key secret: %w", err)
	}
	if apierrors.IsNotFound(err) {
		oldKeySecret = nil // No existing secret to backup
	}

	// Backup kubeconfig secret
	oldCfgSecret = &corev1.Secret{}
	err = rm.client.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, oldCfgSecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to backup kubeconfig secret: %w", err)
	}
	if apierrors.IsNotFound(err) {
		oldCfgSecret = nil // No existing secret to backup
	}

	// Update key secret first
	keySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      keySecretName,
			Namespace: userNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"key.pem": newKeyPEM,
		},
	}

	err = helpers.CreateOrUpdate(ctx, rm.client, keySecret)
	if err != nil {
		return fmt.Errorf("failed to update key secret: %w", err)
	}

	// Update kubeconfig secret with rollback on failure
	cfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfgSecretName,
			Namespace: userNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"config": newKubeconfig,
		},
	}

	err = helpers.CreateOrUpdate(ctx, rm.client, cfgSecret)
	if err != nil {
		// Rollback key secret on kubeconfig update failure
		logger.Error(err, "Failed to update kubeconfig secret, rolling back key secret")
		if oldKeySecret != nil {
			if rollbackErr := helpers.CreateOrUpdate(ctx, rm.client, oldKeySecret); rollbackErr != nil {
				logger.Error(rollbackErr, "Failed to rollback key secret")
			}
		}
		return fmt.Errorf("failed to update kubeconfig secret: %w", err)
	}

	logger.Info("Atomic secret update completed successfully", "user", username)
	return nil
}

// cleanupCSR removes the CSR after successful rotation
func (rm *RotationManager) cleanupCSR(ctx context.Context, csrName string) error {
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: csrName},
	}

	err := rm.client.Delete(ctx, csr)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete CSR: %w", err)
	}

	return nil
}

// updateUserStatusAfterRotation updates user status with new certificate information
func (rm *RotationManager) updateUserStatusAfterRotation(ctx context.Context, user *authv1alpha1.User, signedCert []byte, certDuration time.Duration) error {
	// Extract certificate expiry
	certExpiry, err := rm.extractCertificateExpiry(signedCert)
	if err != nil {
		return fmt.Errorf("failed to extract certificate expiry: %w", err)
	}

	// Calculate renewal time
	calculator := NewRenewalCalculator()
	err = calculator.UpdateUserRenewalStatus(user, certExpiry, certDuration)
	if err != nil {
		return fmt.Errorf("failed to update renewal status: %w", err)
	}

	// Update phase
	user.Status.Phase = "Active"
	user.Status.Message = "Certificate renewed successfully"

	// Update conditions
	now := metav1.Now()
	readyCondition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             "CertificateRenewed",
		Message:            "Certificate has been successfully renewed",
	}

	renewingCondition := metav1.Condition{
		Type:               "Renewing",
		Status:             metav1.ConditionFalse,
		LastTransitionTime: now,
		Reason:             "RenewalComplete",
		Message:            "Certificate renewal completed",
	}

	// Update or add conditions
	user.Status.Conditions = rm.updateConditions(user.Status.Conditions, readyCondition)
	user.Status.Conditions = rm.updateConditions(user.Status.Conditions, renewingCondition)

	return rm.client.Status().Update(ctx, user)
}

// Helper methods

func (rm *RotationManager) getClusterCABase64(ctx context.Context) (string, error) {
	// Use the existing implementation from certs package
	return certs.GetClusterCABase64(ctx, rm.client)
}

func (rm *RotationManager) getAPIServerURL() string {
	// Use the existing logic
	return certs.GetAPIServerURL()
}

func (rm *RotationManager) buildKubeconfig(apiServer, caDataB64 string, signedCert, keyPEM []byte, username string) []byte {
	// Use the existing implementation from certs package
	return certs.BuildCertKubeconfig(apiServer, caDataB64, signedCert, keyPEM, username)
}

func (rm *RotationManager) extractCertificateExpiry(certData []byte) (time.Time, error) {
	// Use the existing implementation from certs package
	return certs.ExtractCertificateExpiryWithFormatDetection(certData)
}

func (rm *RotationManager) updateConditions(conditions []metav1.Condition, newCondition metav1.Condition) []metav1.Condition {
	for i, condition := range conditions {
		if condition.Type == newCondition.Type {
			conditions[i] = newCondition
			return conditions
		}
	}
	return append(conditions, newCondition)
}

func (rm *RotationManager) recordRenewalAttempt(user *authv1alpha1.User, attempt authv1alpha1.RenewalAttempt) {
	// Add to renewal history (keep last 10 attempts)
	user.Status.RenewalHistory = append(user.Status.RenewalHistory, attempt)
	if len(user.Status.RenewalHistory) > 10 {
		user.Status.RenewalHistory = user.Status.RenewalHistory[1:]
	}
}

// validateCSRForApproval validates a CSR before auto-approval for security
func (rm *RotationManager) validateCSRForApproval(csr *certv1.CertificateSigningRequest) error {
	// Validate signer name
	if csr.Spec.SignerName != certv1.KubeAPIServerClientSignerName {
		return fmt.Errorf("invalid signer name: %s", csr.Spec.SignerName)
	}

	// Validate usages
	expectedUsages := []certv1.KeyUsage{certv1.UsageClientAuth}
	if len(csr.Spec.Usages) != len(expectedUsages) {
		return fmt.Errorf("invalid usages count: expected %d, got %d", len(expectedUsages), len(csr.Spec.Usages))
	}

	for i, usage := range csr.Spec.Usages {
		if usage != expectedUsages[i] {
			return fmt.Errorf("invalid usage at index %d: expected %s, got %s", i, expectedUsages[i], usage)
		}
	}

	// Validate labels
	if csr.Labels == nil {
		return fmt.Errorf("missing required labels")
	}

	if csr.Labels["auth.openkube.io/renewal"] != "true" {
		return fmt.Errorf("missing or invalid renewal label")
	}

	if csr.Labels["auth.openkube.io/rotation"] != "true" {
		return fmt.Errorf("missing or invalid rotation label")
	}

	// Validate CSR content
	block, _ := pem.Decode(csr.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("invalid CSR PEM format")
	}

	csrReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Validate common name matches expected user
	expectedUsername := csr.Labels["auth.openkube.io/user"]
	if csrReq.Subject.CommonName != expectedUsername {
		return fmt.Errorf("CSR common name %s doesn't match expected user %s", csrReq.Subject.CommonName, expectedUsername)
	}

	return nil
}
