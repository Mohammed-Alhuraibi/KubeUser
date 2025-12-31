# KubeUser Helm Chart

This Helm chart deploys the KubeUser operator, a Kubernetes-native user management system that automates user authentication and authorization through declarative custom resources.

## Prerequisites

- Kubernetes 1.20+
- Helm 3.0+
- Cluster admin permissions

## Installation

### Quick Start

```bash
# Add the chart repository (if published)
helm repo add kubeuser https://charts.example.com/kubeuser

# Install with automatic namespace creation (recommended)
helm install kubeuser ./helm/kubeuser --create-namespace -n kubeuser

# Or install into existing namespace
helm install kubeuser ./helm/kubeuser -n existing-namespace
```

**Important**: 
- Everything (controller + user secrets) goes in the same namespace specified by `-n`
- Use `--create-namespace` for new namespaces or ensure the namespace exists first

### Custom Installation

```bash
# Install with custom configuration and namespace creation
helm install kubeuser ./helm/kubeuser \
  --create-namespace -n kubeuser \
  --set image.tag=v0.2.0 \
  --set webhook.enabled=true \
  --set metrics.enabled=true

# Install into existing namespace
helm install kubeuser ./helm/kubeuser -n my-existing-namespace
```

## Configuration

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Controller image repository | `ghcr.io/openkube-hub/kubeuser-controller` |
| `image.tag` | Controller image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of controller replicas | `2` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `webhook.enabled` | Enable webhook server | `true` |
| `webhook.service.port` | Webhook service port | `443` |
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.service.port` | Metrics service port | `8080` |
| `rbac.create` | Create RBAC resources | `true` |
| `crds.install` | Install CustomResourceDefinitions | `true` |
| `commonLabels.environment` | Common environment label | `test` |

## Usage Examples

### Basic User Creation

After installation, create a user with namespace-scoped access:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  roles:
    # Bind a namespace-scoped Role
    - namespace: "development"
      existingRole: "developer"
    - namespace: "staging"
      existingRole: "viewer"
```

### User with ClusterRole in Specific Namespaces

Bind a ClusterRole with RoleBinding to grant permissions only in specific namespaces:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob
spec:
  roles:
    # Bind ClusterRole 'view' with RoleBinding in specific namespaces
    - namespace: "team-a"
      existingClusterRole: "view"
    - namespace: "team-b"
      existingClusterRole: "edit"
```

### User with Cluster-wide Access

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: charlie-admin
spec:
  clusterRoles:
    # Bind ClusterRole with ClusterRoleBinding for cluster-wide access
    - existingClusterRole: "cluster-admin"
```

### Mixed Permissions

Combine namespace-scoped and cluster-wide permissions:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: dave
spec:
  roles:
    # Namespace-scoped Role
    - namespace: "production"
      existingRole: "deployer"
    # ClusterRole bound to specific namespace
    - namespace: "monitoring"
      existingClusterRole: "view"
  clusterRoles:
    # Cluster-wide access
    - existingClusterRole: "cluster-reader"
```

## Upgrading

```bash
# Upgrade to a new version
helm upgrade kubeuser ./helm/kubeuser \
  --set image.tag=v0.3.0

# Upgrade with new values
helm upgrade kubeuser ./helm/kubeuser -f custom-values.yaml
```

## Uninstallation

```bash
# Uninstall the release
helm uninstall kubeuser

# Clean up CRDs (if needed)
kubectl delete crd users.auth.openkube.io
```

## Troubleshooting

### Common Issues

1. **Webhook Certificate Issues**
   ```bash
   # Check webhook certificate secret
   kubectl get secret kubeuser-webhook-certs -n kubeuser
   
   # View webhook logs
   kubectl logs -f deployment/kubeuser-controller-manager -n kubeuser
   ```

2. **RBAC Permission Issues**
   ```bash
   # Verify ClusterRoleBinding
   kubectl get clusterrolebinding | grep kubeuser
   
   # Check service account
   kubectl get serviceaccount -n kubeuser
   ```

3. **CRD Issues**
   ```bash
   # Verify CRD installation
   kubectl get crd users.auth.openkube.io -o yaml
   ```

## Development

### Running Tests

```bash
# Validate chart templates
helm lint ./helm/kubeuser

# Dry run installation
helm install kubeuser ./helm/kubeuser --dry-run --debug

# Template rendering
helm template kubeuser ./helm/kubeuser
```

## Contributing

Please refer to the main project repository for contribution guidelines:
https://github.com/openkube-hub/KubeUser