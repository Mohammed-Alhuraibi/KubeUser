# Webhook Validation for User Resources

## Overview

The KubeUser operator includes an admission webhook that validates User resources before they are persisted to etcd. This prevents the creation of User objects that reference non-existent Roles or ClusterRoles, ensuring RBAC integrity.

## Features

- **Pre-persistence validation**: User resources are validated before being stored in etcd
- **Role existence validation**: Verifies that all referenced Roles exist in their specified namespaces
- **ClusterRole existence validation**: Verifies that all referenced ClusterRoles exist
- **Mutual exclusion validation**: Ensures only one of `existingRole` or `existingClusterRole` is specified per role entry
- **Required field validation**: Ensures at least one role reference is provided when roles are specified
- **Auth specification validation**: Validates TTL, renewBefore, and other auth configuration
- **Renewal configuration validation**: Validates auto-renewal settings when enabled
- **Clear error messages**: Provides descriptive error messages when validation fails

## How it Works

1. When a User resource is created or updated, the Kubernetes API server sends an admission review to the webhook
2. The webhook validates that:
   - All referenced Roles exist in their specified namespaces
   - All referenced ClusterRoles exist
   - Each role entry has exactly one of `existingRole` or `existingClusterRole` specified
   - Auth specification is valid (TTL within limits, valid duration format)
   - Renewal configuration is valid when auto-renewal is enabled
3. If validation passes, the User resource is allowed to be persisted
4. If validation fails, the operation is rejected with a clear error message

## Webhook Certificate Management

The webhook requires TLS certificates to communicate securely with the Kubernetes API server. Certificate management varies by environment:

### Local Development and Testing
Uses **self-signed certificates** managed internally by the controller without requiring cert-manager.

### Production Environments
Uses **cert-manager** for proper certificate lifecycle management:

- **Self-signed issuer**: A self-signed Certificate Authority is created for the webhook
- **Automatic renewal**: cert-manager handles certificate renewal automatically
- **CA injection**: cert-manager automatically injects the CA bundle into the ValidatingAdmissionWebhook configuration
- **RSA 2048-bit keys** with proper key usage for server authentication

## Prerequisites

### For Local Development
- No additional prerequisites - webhook certificates are self-managed

### For Production
- **cert-manager**: Must be installed in your cluster
  ```bash
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml
  ```

## Configuration

The webhook configuration is located in `config/webhook/` and includes:

- `issuer.yaml`: Self-signed issuer and certificate configuration (for cert-manager deployments)
- `service.yaml`: Service configuration for the webhook server
- `manifests.yaml`: ValidatingAdmissionWebhook configuration
- `kustomization.yaml`: Kustomize configuration for certificate management

## Validation Examples

### Valid User Resource
```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: jane-doe
spec:
  auth:
    type: x509
    ttl: "2160h"  # 3 months
    autoRenew: true
  roles:
    - namespace: default
      existingRole: developer  # This role must exist in the 'default' namespace
    - namespace: production
      existingClusterRole: view  # This ClusterRole must exist, bound to 'production' namespace
  clusterRoles:
    - existingClusterRole: view  # This ClusterRole must exist, bound cluster-wide
```

### Validation Errors

**Missing Role:**
```
error validating User resource: role 'non-existent-role' not found in namespace 'default'
```

**Missing ClusterRole:**
```
error validating User resource: clusterrole 'non-existent-cluster-role' not found
```

**Both role types specified:**
```
error validating User resource: cannot specify both existingRole and existingClusterRole for namespace 'default'
```

**No role specified:**
```
error validating User resource: either existingRole or existingClusterRole must be specified for namespace 'default'
```

**Invalid TTL:**
```
error validating User resource: invalid auth specification: TTL must not exceed 8760h0m0s, got: 17520h0m0s
```

**Invalid renewal configuration:**
```
error validating User resource: invalid renewal configuration: renewBefore too aggressive, capped at 90% (54m0s)
```

## Deployment

The webhook is automatically deployed when you apply the default configuration:

```bash
kubectl apply -k config/default
```

## Troubleshooting

### Webhook Certificate Issues

#### For Local Development
Check controller logs for certificate generation issues:
```bash
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -i webhook
```

#### For Production (cert-manager)
Check that cert-manager is running and the certificate is ready:
```bash
kubectl get certificates -n kubeuser
kubectl get secrets kubeuser-webhook-certs -n kubeuser
kubectl describe certificate kubeuser-webhook-cert -n kubeuser
```

### Webhook Validation Issues

Check the webhook configuration and logs:
```bash
# Check webhook configuration
kubectl get validatingwebhookconfiguration user.auth.openkube.io -o yaml

# Check webhook logs
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep webhook

# Check webhook service
kubectl get service -n kubeuser kubeuser-webhook-service
```

### Testing Validation

Create a User resource that references a non-existent role to test validation:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: test-user
spec:
  roles:
    - namespace: default
      existingRole: non-existent-role
EOF
```

This should fail with a validation error message.

Test mutual exclusion validation:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: test-user-invalid
spec:
  roles:
    - namespace: default
      existingRole: some-role
      existingClusterRole: some-cluster-role  # This should fail
EOF
```

Test invalid TTL validation:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: test-invalid-ttl
spec:
  auth:
    type: x509
    ttl: "17520h"  # 2 years - should fail (max is 1 year)
  clusterRoles:
    - existingClusterRole: view
EOF
```

## Security Considerations

- The webhook validates RBAC references, preventing the creation of Users with invalid permissions
- Validation occurs before persistence, preventing invalid states in etcd
- The webhook runs with minimal required permissions
- Certificate management is handled appropriately for each environment (self-signed for dev, cert-manager for production)
- Mutual exclusion validation prevents ambiguous role specifications

## Related Documentation

- [Certificate Management](certificate-management.md) - Details about user certificate creation and storage
- [Auto-Renewal Feature](auto-renewal.md) - User certificate renewal and rotation details
- [User Management](../README.md) - Overall user management features