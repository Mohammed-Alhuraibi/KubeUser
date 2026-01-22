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

// RotateUserCertificate performs stateful certificate rotation using Shadow Secret pattern
func (rm *RotationManager) RotateUserCertificate(ctx context.Context, user *authv1alpha1.User, certDuration time.Duration) error {
	logger := logf.FromContext(ctx)
	username := user.Name
	userUID := string(user.UID)

	logger.Info("Starting stateful certificate rotation", "user", username, "uid", userUID, "duration", certDuration)

	// Step 1: Check for existing Shadow Secret (stateful rotation)
	shadowSecret, shadowExists, err := rm.getShadowSecret(ctx, username)
	if err != nil {
		return fmt.Errorf("failed to check shadow secret: %w", err)
	}

	var keyPEM []byte
	var csrName string

	if !shadowExists {
		// Step 1a: Generate new private key and CSR name, save to Shadow Secret
		logger.Info("No shadow secret found, generating new key and CSR name")

		newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			rm.recordRenewalAttempt(user, authv1alpha1.RenewalAttempt{
				Timestamp: metav1.Now(),
				Success:   false,
				Message:   fmt.Sprintf("Failed to generate private key: %v", err),
			})
			return fmt.Errorf("failed to generate private key: %w", err)
		}

		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(newPrivateKey),
		})

		// Generate unique CSR name using User UID for true uniqueness
		csrName = rm.generateUniqueCSRName(username, userUID)

		// Create Shadow Secret with owner reference
		err = rm.createShadowSecret(ctx, user, username, keyPEM, csrName)
		if err != nil {
			rm.recordRenewalAttempt(user, authv1alpha1.RenewalAttempt{
				Timestamp: metav1.Now(),
				Success:   false,
				Message:   fmt.Sprintf("Failed to create shadow secret: %v", err),
				CSRName:   csrName,
			})
			return fmt.Errorf("failed to create shadow secret: %w", err)
		}

		// Record shadow secret creation (but don't mark as failed - this is progress)
		rm.recordRenewalAttempt(user, authv1alpha1.RenewalAttempt{
			Timestamp: metav1.Now(),
			Success:   false, // Not complete yet, but not a failure
			Message:   "Shadow secret created, proceeding with CSR creation",
			CSRName:   csrName,
		})

		logger.Info("Shadow secret created, continuing with CSR creation", "csrName", csrName)
		// Don't return here - continue with CSR creation in the same reconcile loop
	} else {
		// Step 1b: Retrieve key and CSR name from existing Shadow Secret
		keyPEM = shadowSecret.Data["key.pem"]
		csrName = string(shadowSecret.Data["csr.name"])

		if len(keyPEM) == 0 || csrName == "" {
			// Corrupted shadow secret, delete and retry
			logger.Error(nil, "Corrupted shadow secret found, deleting", "shadowSecret", shadowSecret.Name)
			if err := rm.deleteShadowSecret(ctx, username); err != nil {
				logger.Error(err, "Failed to delete corrupted shadow secret")
			}
			return fmt.Errorf("corrupted shadow secret found, deleted and requeue needed")
		}

		logger.Info("Using existing shadow secret", "csrName", csrName)
	}

	// Step 2: Ensure CSR exists
	csr, err := rm.ensureCSRExists(ctx, user, csrName, username, keyPEM, certDuration)
	if err != nil {
		rm.recordRenewalAttempt(user, authv1alpha1.RenewalAttempt{
			Timestamp: metav1.Now(),
			Success:   false,
			Message:   fmt.Sprintf("Failed to ensure CSR exists: %v", err),
			CSRName:   csrName,
		})
		return fmt.Errorf("failed to ensure CSR exists: %w", err)
	}

	// Step 3: Programmatically approve CSR
	approved, err := rm.ensureCSRApproved(ctx, csr)
	if err != nil {
		rm.recordRenewalAttempt(user, authv1alpha1.RenewalAttempt{
			Timestamp: metav1.Now(),
			Success:   false,
			Message:   fmt.Sprintf("Failed to approve CSR: %v", err),
			CSRName:   csrName,
		})
		return fmt.Errorf("failed to approve CSR: %w", err)
	}

	if !approved {
		logger.Info("CSR approval in progress", "csrName", csrName)
		return fmt.Errorf("CSR approval in progress, requeue needed")
	}

	// Step 4: Wait for signed certificate
	if len(csr.Status.Certificate) == 0 {
		logger.Info("Waiting for signed certificate", "csrName", csrName)
		return fmt.Errorf("waiting for signed certificate, requeue needed")
	}

	signedCert := csr.Status.Certificate
	logger.Info("Received signed certificate", "certLength", len(signedCert))

	// Step 5: Atomic update to primary Kubeconfig Secret (The Flip)
	err = rm.atomicSecretUpdate(ctx, user, keyPEM, signedCert)
	if err != nil {
		rm.recordRenewalAttempt(user, authv1alpha1.RenewalAttempt{
			Timestamp: metav1.Now(),
			Success:   false,
			Message:   fmt.Sprintf("Failed to update primary secret: %v", err),
			CSRName:   csrName,
		})
		return fmt.Errorf("failed to update primary secret atomically: %w", err)
	}

	logger.Info("Primary secret updated successfully", "user", username)

	// Step 6: Cleanup Shadow Secret and CSR (only after successful primary update)
	if err := rm.cleanupRotationResources(ctx, username, csrName); err != nil {
		logger.Error(err, "Failed to cleanup rotation resources, will retry on next reconciliation")
		// Don't fail the rotation for cleanup errors, but log for monitoring
	}

	// Update user status with new certificate info (best effort)
	err = rm.updateUserStatusAfterRotation(ctx, user, signedCert, certDuration)
	if err != nil {
		logger.Error(err, "Failed to update user status after rotation, will retry on next reconciliation")
		// Don't fail the rotation for status update errors
	}

	// Record successful renewal
	rm.recordRenewalAttempt(user, authv1alpha1.RenewalAttempt{
		Timestamp: metav1.Now(),
		Success:   true,
		Message:   "Certificate rotation completed successfully",
		CSRName:   csrName,
	})

	logger.Info("Certificate rotation completed successfully", "user", username)
	return nil
}

// generateUniqueCSRName creates a unique CSR name using User UID for true uniqueness
func (rm *RotationManager) generateUniqueCSRName(username, userUID string) string {
	// Use User UID for true uniqueness across the cluster
	// This ensures no collisions even if users are recreated with same name
	return fmt.Sprintf("%s-renewal-%s", username, userUID[:8])
}

// getShadowSecret retrieves the shadow secret if it exists
func (rm *RotationManager) getShadowSecret(ctx context.Context, username string) (*corev1.Secret, bool, error) {
	shadowSecretName := fmt.Sprintf("%s-rotation-temp", username)
	userNamespace := helpers.GetKubeUserNamespace()

	shadowSecret := &corev1.Secret{}
	err := rm.client.Get(ctx, types.NamespacedName{
		Name:      shadowSecretName,
		Namespace: userNamespace,
	}, shadowSecret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get shadow secret: %w", err)
	}

	return shadowSecret, true, nil
}

// createShadowSecret creates a shadow secret with owner reference
func (rm *RotationManager) createShadowSecret(ctx context.Context, user *authv1alpha1.User, username string, keyPEM []byte, csrName string) error {
	shadowSecretName := fmt.Sprintf("%s-rotation-temp", username)
	userNamespace := helpers.GetKubeUserNamespace()

	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shadowSecretName,
			Namespace: userNamespace,
			Labels: map[string]string{
				"auth.openkube.io/user":     username,
				"auth.openkube.io/rotation": "true",
				"auth.openkube.io/shadow":   "true",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         user.APIVersion,
					Kind:               user.Kind,
					Name:               user.Name,
					UID:                user.UID,
					Controller:         &[]bool{true}[0],
					BlockOwnerDeletion: &[]bool{true}[0],
				},
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"key.pem":  keyPEM,
			"csr.name": []byte(csrName),
		},
	}

	return rm.client.Create(ctx, shadowSecret)
}

// deleteShadowSecret removes the shadow secret
func (rm *RotationManager) deleteShadowSecret(ctx context.Context, username string) error {
	shadowSecretName := fmt.Sprintf("%s-rotation-temp", username)
	userNamespace := helpers.GetKubeUserNamespace()

	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shadowSecretName,
			Namespace: userNamespace,
		},
	}

	err := rm.client.Delete(ctx, shadowSecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete shadow secret: %w", err)
	}

	return nil
}

// ensureCSRExists creates CSR if it doesn't exist, returns existing one otherwise
func (rm *RotationManager) ensureCSRExists(ctx context.Context, user *authv1alpha1.User, csrName, username string, keyPEM []byte, certDuration time.Duration) (*certv1.CertificateSigningRequest, error) {
	logger := logf.FromContext(ctx)

	// Try to get existing CSR first
	var existingCSR certv1.CertificateSigningRequest
	err := rm.client.Get(ctx, types.NamespacedName{Name: csrName}, &existingCSR)
	if err == nil {
		logger.Info("Found existing CSR", "csrName", csrName)
		return &existingCSR, nil
	}

	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to check for existing CSR: %w", err)
	}

	// Create CSR from stored key
	logger.Info("Creating new CSR from stored key", "csrName", csrName)
	csrPEM, err := rm.createCSRFromKey(username, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR from stored key: %w", err)
	}

	expirationSeconds := int32(certDuration.Seconds())
	newCSR := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
			Labels: map[string]string{
				"auth.openkube.io/user":     username,
				"auth.openkube.io/renewal":  "true",
				"auth.openkube.io/rotation": "true",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         user.APIVersion,
					Kind:               user.Kind,
					Name:               user.Name,
					UID:                user.UID,
					Controller:         &[]bool{false}[0], // Not a controller reference to avoid conflicts
					BlockOwnerDeletion: &[]bool{true}[0],
				},
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
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	logger.Info("Created new CSR", "csrName", csrName)
	return newCSR, nil
}

// ensureCSRApproved approves the CSR if not already approved
func (rm *RotationManager) ensureCSRApproved(ctx context.Context, csr *certv1.CertificateSigningRequest) (bool, error) {
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

	// Get fresh copy of CSR to avoid conflicts
	freshCSR := &certv1.CertificateSigningRequest{}
	err := rm.client.Get(ctx, types.NamespacedName{Name: csr.Name}, freshCSR)
	if err != nil {
		return false, fmt.Errorf("failed to get fresh CSR for approval: %w", err)
	}

	freshCSR.Status.Conditions = append(freshCSR.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         corev1.ConditionTrue,
		Reason:         "AutoApprovedByKubeUser",
		Message:        "Approved by kubeuser-operator for certificate renewal",
		LastUpdateTime: metav1.Now(),
	})

	err = rm.client.SubResource("approval").Update(ctx, freshCSR)
	if err != nil {
		return false, fmt.Errorf("failed to approve CSR: %w", err)
	}

	logger.Info("CSR approved successfully", "csrName", csr.Name)
	return false, nil // Just approved, need to wait for certificate
}

// cleanupRotationResources removes shadow secret and CSR after successful rotation
func (rm *RotationManager) cleanupRotationResources(ctx context.Context, username, csrName string) error {
	logger := logf.FromContext(ctx)

	// Delete shadow secret
	if err := rm.deleteShadowSecret(ctx, username); err != nil {
		logger.Error(err, "Failed to delete shadow secret", "username", username)
		return fmt.Errorf("failed to delete shadow secret: %w", err)
	}

	// Delete CSR
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: csrName},
	}

	err := rm.client.Delete(ctx, csr)
	if err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete CSR", "csrName", csrName)
		return fmt.Errorf("failed to delete CSR: %w", err)
	}

	logger.Info("Cleanup completed successfully", "username", username, "csrName", csrName)
	return nil
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

// IsRotationInProgress checks if a rotation is currently in progress for a user
func (rm *RotationManager) IsRotationInProgress(ctx context.Context, username string) (bool, string, error) {
	shadowSecret, exists, err := rm.getShadowSecret(ctx, username)
	if err != nil {
		return false, "", fmt.Errorf("failed to check rotation progress: %w", err)
	}

	if !exists {
		return false, "", nil
	}

	csrName := string(shadowSecret.Data["csr.name"])
	return true, csrName, nil
}

// GetRotationRequeueDelay returns appropriate requeue delay based on certificate duration
func (rm *RotationManager) GetRotationRequeueDelay(certDuration time.Duration) time.Duration {
	// For short-TTL certificates (< 1 hour), use aggressive requeuing
	if certDuration < time.Hour {
		return 10 * time.Second
	}

	// For medium-TTL certificates (< 24 hours), use moderate requeuing
	if certDuration < 24*time.Hour {
		return 30 * time.Second
	}

	// For long-TTL certificates, use conservative requeuing
	return 2 * time.Minute
}

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
