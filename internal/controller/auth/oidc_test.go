package auth

import (
	"context"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestOIDCProvider_Ensure(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = authv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	provider := NewOIDCProvider(client)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
		},
		Spec: authv1alpha1.UserSpec{
			Auth: authv1alpha1.AuthSpec{
				Type: "oidc",
				TTL:  "24h", // ignored for OIDC
			},
		},
	}

	ctx := context.Background()

	// Test ensure - should fail with not implemented error
	_, _, err := provider.Ensure(ctx, user)
	if err == nil {
		t.Error("OIDC ensure should fail with not implemented error")
	}

	expectedError := "OIDC authentication is not yet implemented (stub only)"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestOIDCProvider_Revoke(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = authv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	provider := NewOIDCProvider(client)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
		},
		Spec: authv1alpha1.UserSpec{
			Auth: authv1alpha1.AuthSpec{
				Type: "oidc",
			},
		},
	}

	ctx := context.Background()

	// Test revoke - should not error (stub implementation)
	err := provider.Revoke(ctx, user)
	if err != nil {
		t.Errorf("OIDC revoke should not error: %v", err)
	}
}
