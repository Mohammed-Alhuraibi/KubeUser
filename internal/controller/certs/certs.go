/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	inClusterCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

func EnsureCertKubeconfig(ctx context.Context, r client.Client, user *authv1alpha1.User) (bool, error) {
	// Use default duration (3 months)
	defaultDuration := 90 * 24 * time.Hour
	return EnsureCertKubeconfigWithDuration(ctx, r, user, defaultDuration)
}

// EnsureCertKubeconfigWithDuration ensures certificate kubeconfig with custom duration
func EnsureCertKubeconfigWithDuration(ctx context.Context, r client.Client, user *authv1alpha1.User, duration time.Duration) (bool, error) {
	username := user.Name
	userNamespace := helpers.GetKubeUserNamespace()
	keySecretName := fmt.Sprintf("%s-key", username)
	cfgSecretName := fmt.Sprintf("%s-kubeconfig", username)
	csrName := fmt.Sprintf("%s-csr", username)

	// Verify that the target namespace exists
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: userNamespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return false, fmt.Errorf("target namespace '%s' does not exist - please create it before deploying KubeUser or use Helm with --create-namespace", userNamespace)
		}
		return false, fmt.Errorf("failed to verify namespace '%s': %w", userNamespace, err)
	}

	// Check if certificate needs rotation
	// Rotation threshold can be configured via KUBEUSER_ROTATION_THRESHOLD environment variable
	rotationThreshold := getRotationThreshold(duration)

	needsRotation, err := checkCertificateRotation(ctx, r, cfgSecretName, rotationThreshold)
	if err != nil {
		return false, fmt.Errorf("failed to check certificate rotation: %w", err)
	}

	if needsRotation {
		// Clean up existing resources for rotation
		logger := logf.FromContext(ctx)
		logger.Info("Certificate needs rotation, cleaning up existing resources", "user", username)
		if err := cleanupCertificateResources(ctx, r, cfgSecretName, csrName); err != nil {
			return false, fmt.Errorf("failed to cleanup certificate resources: %w", err)
		}
	}

	// 1. Load/create key Secret
	var keySecret corev1.Secret
	err = r.Get(ctx, types.NamespacedName{Name: keySecretName, Namespace: userNamespace}, &keySecret)
	var keyPEM []byte
	if apierrors.IsNotFound(err) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return false, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		keySecret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: keySecretName, Namespace: userNamespace},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"key.pem": keyPEM},
		}
		if err := r.Create(ctx, &keySecret); err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	} else {
		keyPEM = keySecret.Data["key.pem"]
	}

	// 2. If kubeconfig already exists, return
	var existingCfg corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, &existingCfg); err == nil {
		return false, nil
	}

	// 3. CSR from key
	csrPEM, err := csrFromKey(username, keyPEM)
	if err != nil {
		return false, err
	}

	// 4. Create/get CSR
	var csr certv1.CertificateSigningRequest
	err = r.Get(ctx, types.NamespacedName{Name: csrName}, &csr)
	if apierrors.IsNotFound(err) {
		// Convert duration to seconds for CSR
		expirationSeconds := int32(duration.Seconds())

		csr = certv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{Name: csrName, Labels: map[string]string{"auth.openkube.io/user": username}},
			Spec: certv1.CertificateSigningRequestSpec{
				Request:           csrPEM,
				Usages:            []certv1.KeyUsage{certv1.UsageClientAuth},
				SignerName:        certv1.KubeAPIServerClientSignerName,
				ExpirationSeconds: &expirationSeconds,
			},
		}
		if err := r.Create(ctx, &csr); err != nil {
			return false, err
		}
		return true, nil
	} else if err != nil {
		return false, err
	}

	// 5. Approve CSR if not approved
	approved := false
	for _, c := range csr.Status.Conditions {
		if c.Type == certv1.CertificateApproved && c.Status == corev1.ConditionTrue {
			approved = true
		}
	}
	if !approved {
		csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
			Type:           certv1.CertificateApproved,
			Status:         corev1.ConditionTrue,
			Reason:         "AutoApproved",
			Message:        "Approved by kubeuser-operator",
			LastUpdateTime: metav1.Now(),
		})
		if err := r.SubResource("approval").Update(ctx, &csr); err != nil {
			return false, err
		}
		return true, nil
	}

	// 6. Wait for cert
	if len(csr.Status.Certificate) == 0 {
		return true, nil
	}
	signedCert := csr.Status.Certificate

	// 7. Cluster CA
	caDataB64, err := getClusterCABase64(ctx, r)
	if err != nil {
		return false, err
	}

	// 8. API server URL
	apiServer := os.Getenv("KUBERNETES_API_SERVER")
	if apiServer == "" {
		apiServer = "https://kubernetes.default.svc"
	}

	// 9. Kubeconfig
	kcfg := buildCertKubeconfig(apiServer, caDataB64,
		base64.StdEncoding.EncodeToString(signedCert),
		base64.StdEncoding.EncodeToString(keyPEM),
		username)

	// 9.5. Extract certificate expiry time
	logger := logf.FromContext(ctx)
	logger.Info("Extracting certificate expiry", "certLength", len(signedCert))
	logger.Info("Certificate data preview", "first20bytes", string(signedCert[:helpers.Min(20, len(signedCert))]))

	// Try to extract certificate expiry with proper format detection
	certExpiryTime, err := extractCertificateExpiryWithFormatDetection(signedCert)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate expiry: %w", err)
	}
	logger.Info("Successfully extracted certificate expiry", "expiry", certExpiryTime)

	// Update user status with actual certificate expiry and renewal time
	user.Status.ExpiryTime = certExpiryTime.Format(time.RFC3339)
	user.Status.CertificateExpiry = "Certificate"

	// Calculate renewal time based on rotation threshold (already calculated earlier)
	renewalTime := certExpiryTime.Add(-rotationThreshold)
	user.Status.RenewalTime = renewalTime.Format(time.RFC3339)

	logger.Info("Certificate times calculated",
		"expiry", certExpiryTime.Format(time.RFC3339),
		"renewal", renewalTime.Format(time.RFC3339),
		"rotationThreshold", rotationThreshold)

	if err := r.Status().Update(ctx, user); err != nil {
		return false, fmt.Errorf("failed to update user status with certificate expiry: %w", err)
	}

	// 10. Save kubeconfig
	cfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: cfgSecretName, Namespace: userNamespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"config": kcfg},
	}
	return false, helpers.CreateOrUpdate(ctx, r, cfgSecret)
}

func csrFromKey(username string, keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("decode key failed")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	csrTemplate := x509.CertificateRequest{Subject: pkix.Name{CommonName: username}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func getClusterCABase64(ctx context.Context, r client.Client) (string, error) {
	if data, err := os.ReadFile(filepath.Clean(inClusterCAPath)); err == nil && len(data) > 0 {
		return base64.StdEncoding.EncodeToString(data), nil
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kube-root-ca.crt"}, &cm); err == nil {
		if crt, ok := cm.Data["ca.crt"]; ok {
			return base64.StdEncoding.EncodeToString([]byte(crt)), nil
		}
	}
	return "", errors.New("CA not found")
}

func buildCertKubeconfig(apiServer, caDataB64, certDataB64, keyDataB64, username string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: cluster
contexts:
- context:
    cluster: cluster
    namespace: default
    user: %s
  name: %s@cluster
current-context: %s@cluster
users:
- name: %s
  user:
    client-certificate-data: %s
    client-key-data: %s
`, caDataB64, apiServer, username, username, username, username, certDataB64, keyDataB64))
}

// extractCertificateExpiryWithFormatDetection tries multiple formats to extract certificate expiry
func extractCertificateExpiryWithFormatDetection(certData []byte) (time.Time, error) {
	// Method 1: Try as base64-encoded PEM (most likely)
	if certTime, err := tryBase64PEM(certData); err == nil {
		return certTime, nil
	}

	// Method 2: Try as raw PEM (less likely)
	if certTime, err := tryRawPEM(certData); err == nil {
		return certTime, nil
	}

	// Method 3: Try as raw DER (least likely)
	if certTime, err := tryRawDER(certData); err == nil {
		return certTime, nil
	}

	return time.Time{}, errors.New("unable to parse certificate in any known format")
}

// tryBase64PEM tries to parse as base64-encoded PEM
func tryBase64PEM(certData []byte) (time.Time, error) {
	// Decode base64
	certPEM, err := base64.StdEncoding.DecodeString(string(certData))
	if err != nil {
		return time.Time{}, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Decode PEM to get DER
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("PEM decode failed")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// tryRawPEM tries to parse as raw PEM data
func tryRawPEM(certData []byte) (time.Time, error) {
	// Decode PEM to get DER
	block, _ := pem.Decode(certData)
	if block == nil {
		return time.Time{}, errors.New("PEM decode failed")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// tryRawDER tries to parse as raw DER data
func tryRawDER(certData []byte) (time.Time, error) {
	// Parse certificate directly
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// checkCertificateRotation checks if a certificate needs rotation based on expiry
func checkCertificateRotation(ctx context.Context, r client.Client, cfgSecretName string, rotationThreshold time.Duration) (bool, error) {
	userNamespace := helpers.GetKubeUserNamespace()
	var existingCfg corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, &existingCfg); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil // No existing certificate, no rotation needed
		}
		return false, err
	}

	// Extract certificate from kubeconfig
	kubeconfigData := existingCfg.Data["config"]
	if kubeconfigData == nil {
		return false, nil // No kubeconfig data, needs recreation
	}

	// Parse kubeconfig to extract client certificate
	certData, err := extractClientCertFromKubeconfig(kubeconfigData)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate from kubeconfig: %w", err)
	}

	// Check certificate expiry
	certExpiry, err := extractCertificateExpiryWithFormatDetection(certData)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate expiry: %w", err)
	}

	// Check if certificate is expiring soon
	timeUntilExpiry := time.Until(certExpiry)
	return timeUntilExpiry < rotationThreshold, nil
}

// extractClientCertFromKubeconfig extracts client certificate data from kubeconfig YAML
func extractClientCertFromKubeconfig(kubeconfigData []byte) ([]byte, error) {
	// Simple regex approach to extract client-certificate-data
	// In a production environment, you might want to use a proper YAML parser
	lines := strings.Split(string(kubeconfigData), "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "client-certificate-data:") {
			parts := strings.SplitN(trimmedLine, ":", 2)
			if len(parts) == 2 {
				certData := strings.TrimSpace(parts[1])
				// Return the base64 encoded certificate data as bytes
				return []byte(certData), nil
			}
		}
	}
	return nil, errors.New("client certificate data not found in kubeconfig")
}

// cleanupCertificateResources removes existing certificate resources for rotation
func cleanupCertificateResources(ctx context.Context, r client.Client, cfgSecretName, csrName string) error {
	logger := logf.FromContext(ctx)
	userNamespace := helpers.GetKubeUserNamespace()

	// Delete kubeconfig secret
	kubeconfigSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, kubeconfigSecret); err == nil {
		logger.Info("Deleting kubeconfig secret for rotation", "secret", cfgSecretName)
		if err := r.Delete(ctx, kubeconfigSecret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete kubeconfig secret: %w", err)
		}
	}

	// Delete existing CSR
	existingCSR := &certv1.CertificateSigningRequest{}
	if err := r.Get(ctx, types.NamespacedName{Name: csrName}, existingCSR); err == nil {
		logger.Info("Deleting existing CSR for rotation", "csr", csrName)
		if err := r.Delete(ctx, existingCSR); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete existing CSR: %w", err)
		}
	}

	// Optionally generate new private key for better security
	// For now, we'll reuse the existing key to maintain consistency
	// In a future enhancement, you might want to rotate keys as well

	return nil
}

// getRotationThreshold returns the rotation threshold for certificates
// Can be overridden with KUBEUSER_ROTATION_THRESHOLD environment variable
// Default: rotate when remaining lifetime ≤ 25% of original TTL
func getRotationThreshold(certDuration time.Duration) time.Duration {
	if thresholdStr := os.Getenv("KUBEUSER_ROTATION_THRESHOLD"); thresholdStr != "" {
		if threshold, err := time.ParseDuration(thresholdStr); err == nil {
			return threshold
		}
	}

	// Default: rotate when 25% of lifetime remains (75% consumed)
	// This means certificates rotate when they have 20-30% of their lifetime left
	return certDuration / 4 // 25% of original duration
}

// GetClusterCABase64 gets the cluster CA certificate in base64 format (exported for renewal package)
func GetClusterCABase64(ctx context.Context, r client.Client) (string, error) {
	return getClusterCABase64(ctx, r)
}

// GetAPIServerURL gets the API server URL (exported for renewal package)
func GetAPIServerURL() string {
	apiServer := os.Getenv("KUBERNETES_API_SERVER")
	if apiServer == "" {
		apiServer = "https://kubernetes.default.svc"
	}
	return apiServer
}

// BuildCertKubeconfig builds a kubeconfig with certificate authentication (exported for renewal package)
func BuildCertKubeconfig(apiServer, caDataB64 string, signedCert, keyPEM []byte, username string) []byte {
	return buildCertKubeconfig(apiServer, caDataB64,
		base64.StdEncoding.EncodeToString(signedCert),
		base64.StdEncoding.EncodeToString(keyPEM),
		username)
}

// ExtractCertificateExpiryWithFormatDetection extracts certificate expiry (exported for renewal package)
func ExtractCertificateExpiryWithFormatDetection(certData []byte) (time.Time, error) {
	return extractCertificateExpiryWithFormatDetection(certData)
}
