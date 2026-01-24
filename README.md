# KubeUser

Lightweight Kubernetes-native user management operator that simplifies user authentication and authorization through declarative custom resources.

## Overview

KubeUser automates Kubernetes user management through declarative custom resources. It handles certificate generation, RBAC binding, and kubeconfig creation automatically.

### Why KubeUser?

Kubernetes-native user management - no certificate handling , no Keycloak required.


### Architecture Overview

KubeUser follows the standard Kubernetes operator pattern:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User CRD      │───▶│  User Controller │───▶│  RBAC Resources │
│  (Custom Res.)  │    │  (Reconciler)    │    │ (Roles/Bindings)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │ Certificate &   │
                       │ Kubeconfig Gen  │
                       └─────────────────┘
```

## Quick installation
```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml
# Wait for cert-manager to be ready
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=60s
```
```bash
helm repo add kubeuser https://openkube-hub.github.io/KubeUser
export KUBERNETES_API_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

# Install with automatic namespace creation (recommended)
helm install kubeuser kubeuser/kubeuser --create-namespace -n kubeuser \
  --set env.KUBERNETES_API_SERVER="$KUBERNETES_API_SERVER"
  
# verify installation
kubectl get pods -n kubeuser
```

**Important**: The controller requires a namespace for storing user certificates. Use `--create-namespace` or install into an existing namespace. The controller will NOT automatically create namespaces for GitOps compatibility.

## Security Considerations
**Deleting a User does NOT invalidate issued ceriticates.**

When deleting a User:
- RBAC bindings removed immediately (no permissions)
- secrets deleted
- Certificated remain valid until expiry (~1 year)

#### 🚧 implemented Features
- [X] Declarative User CRD with status tracking and finalizers
- [X] Automatic client certificate generation via Kubernetes CSR API
- [X] Certificate rotation 30 days before expiry
- [X] Kubeconfig generation stored as Kubernetes secrets
- [X] Namespace-scoped Role bindings (Role + RoleBinding)
- [X] Namespace-scoped ClusterRole bindings (ClusterRole + RoleBinding)
- [X] Dynamic RBAC reconciliation with automatic cleanup
- [X] Admission webhook validation with TLS/HTTPS
- [X] Role/ClusterRole existence validation
- [X] High availability with leader election
- [X] Prometheus metrics endpoint (HTTPS :8443) with RBAC protection
- [X] Health probes (liveness and readiness)
- [X] Helm chart and Kustomize deployment options

#### 🚧 Planned Features
- [ ] User Groups (UserGroup CRD)
- [ ] Predefined role templates library
- [ ] Certificate revocation mechanism
- [ ] OIDC, LDAP/AD, and SSO integration
- [ ] Enhanced metrics with Grafana dashboards and Prometheus alerts
- [ ] CLI tool and Web UI

## 📦 Installation Instructions

### Prerequisites

- **Kubernetes cluster** (v1.28+)
- **kubectl** configured to access your cluster with cluster-admin permissions
- **cert-manager** (required for webhook certificates)
- **Docker** (for building images locally)
- **kind** or **minikube** (for local testing)

#### Install cert-manager

KubeUser requires cert-manager for webhook certificate management:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=60s
```

### Deployment Options

#### Option 1: Using Helm (Recommended)

KubeUser publishes Helm charts via GitHub Pages. To install using Helm:

```bash
helm repo add kubeuser https://openkube-hub.github.io/KubeUser
helm repo update

```bash
# Install with automatic namespace creation (recommended)
helm upgrade --install kubeuser kubeuser/kubeuser \
  --create-namespace \
  --namespace kubeuser \
  --version <version>

# Or install into existing namespace
helm upgrade --install kubeuser kubeuser/kubeuser \
  --namespace existing-namespace \
  --version <version>

# List available versions
helm search repo kubeuser --versions

# Upgrade to a new version later
# helm upgrade kubeuser kubeuser/kubeuser -n kubeuser --version <new-version>

# Uninstall
# helm uninstall kubeuser -n kubeuser
```

Notes:
- All resource names are prefixed by the Helm release name (e.g., `kubeuser`).
- The chart defaults the image.tag to the chart version; override with `--set image.tag=<tag>` if needed.

#### Option 2: Using Kustomize

```bash
# Clone the repository
git clone https://github.com/openkube-hub/KubeUser.git
cd KubeUser

# Create namespace first (required)
kubectl create namespace kubeuser

# Deploy using kustomize
kubectl apply -k config/default

# Wait for controller to be ready
kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n kubeuser --timeout=120s
```

#### Option 3: Local Development with kind

For local testing and development:

```bash
# Build the Docker image
make docker-build

# Load image into kind cluster
kind load docker-image ghcr.io/openkube-hub/kubeuser-controller:latest --name <your-cluster-name>

# Deploy with local image
kubectl apply -k config/default

# Update deployment to use local image
kubectl patch deployment kubeuser-controller-manager -n kubeuser -p '{"spec":{"template":{"spec":{"containers":[{"name":"manager","imagePullPolicy":"Never"}]}}}}'
```

### Verification

Verify the installation:

```bash
# Check controller status
kubectl get pods -n kubeuser

# Check webhook certificate
kubectl get certificates -n kubeuser

# Check CRDs
kubectl get crd users.auth.openkube.io
```


## 🚀 Quick Start / Usage

### Basic User Creation

Create a user with namespace-scoped access:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509        # Default, can be omitted
    ttl: "72h"        # 3 days (default: 2160h = 3 months)
    autoRenew: false  # Default, can be omitted
  roles:
    - namespace: "development"
      existingRole: "developer"
    - namespace: "staging"
      existingRole: "viewer"
```

### User with Cluster-wide Access

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob-admin
spec:
  auth:
    type: x509
    ttl: "2160h"      # 3 months (default)
    autoRenew: true   # Enable automatic renewal
  clusterRoles:
    - existingClusterRole: "cluster-admin"
```

### Mixed Permissions Example

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: contractor-jane
spec:
  auth:
    type: x509
    ttl: "720h"       # 30 days
    autoRenew: true
    renewBefore: "72h" # Renew 3 days before expiry
  roles:
    - namespace: "project-x"
      existingRole: "developer"
    - namespace: "testing"
      existingRole: "tester"
    - namespace: "monitoring"
      existingClusterRole: "view"  # Bind cluster role to specific namespace
  clusterRoles:
    - existingClusterRole: "view"  # Read-only cluster access
```

### Using Existing Cluster Roles in Namespace Scope

KubeUser supports binding existing cluster roles to specific namespaces, providing fine-grained access control:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: namespace-admin
spec:
  auth:
    type: x509
    ttl: "168h"       # 1 week
    autoRenew: true
    renewBefore: "24h" # Renew 1 day before expiry
  roles:
    - namespace: "production"
      existingClusterRole: "admin"  # Full admin access to production namespace only
    - namespace: "staging"
      existingClusterRole: "edit"   # Edit access to staging namespace only
    - namespace: "development"
      existingClusterRole: "view"   # Read-only access to development namespace
```

This approach allows you to:
- Reuse well-defined cluster roles (admin, edit, view) in namespace-specific contexts
- Maintain consistent permission sets across different namespaces
- Avoid creating duplicate namespace-scoped roles

### Auto-Renewal Examples

#### Basic Auto-Renewal (33% Rule)
```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice-auto
spec:
  auth:
    type: x509
    ttl: "24h"        # 24 hour certificate
    autoRenew: true   # Renews after 16 hours (33% rule)
  clusterRoles:
    - existingClusterRole: "view"
```

#### Custom Renewal Timing
```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob-custom
spec:
  auth:
    type: x509
    ttl: "2h"         # 2 hour certificate
    autoRenew: true
    renewBefore: "30m" # Renew 30 minutes before expiry
  roles:
    - namespace: "development"
      existingClusterRole: "edit"
```

#### Short-lived Certificate
```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: charlie-short
spec:
  auth:
    type: x509
    ttl: "10m"        # 10 minute certificate (minimum)
    autoRenew: true
    renewBefore: "3m" # Auto-corrected if too aggressive
  roles:
    - namespace: "testing"
      existingRole: "tester"
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.auth` | `AuthSpec` | No | Authentication configuration (optional, uses defaults) |
| `spec.auth.type` | `string` | No | Authentication method: `x509` or `oidc` (default: `x509`) |
| `spec.auth.ttl` | `string` | No | Certificate lifetime (default: `2160h` = 3 months) |
| `spec.auth.autoRenew` | `boolean` | No | Enable automatic certificate renewal (default: `false`) |
| `spec.auth.renewBefore` | `string` | No | Renew this duration before expiry (overrides 33% rule) |
| `spec.roles` | `[]RoleSpec` | No | List of namespace-scoped role bindings |
| `spec.roles[].namespace` | `string` | Yes | Target namespace for the role binding |
| `spec.roles[].existingRole` | `string` | No* | Name of the existing Role in the namespace |
| `spec.roles[].existingClusterRole` | `string` | No* | Name of the existing ClusterRole to bind to the namespace |
| `spec.clusterRoles` | `[]ClusterRoleSpec` | No | List of cluster-wide role bindings |
| `spec.clusterRoles[].existingClusterRole` | `string` | Yes | Name of the existing ClusterRole |

*Note: Either `existingRole` or `existingClusterRole` must be specified for each role entry.*


### Managing Users

```bash
# Create sample namespace and role
kubectl create ns dev
kubectl create role developer --verb=get,list,watch --resource=pods -n dev

# Apply user configuration
kubectl apply -f test/test-user.yaml

# Check user status
kubectl get users
kubectl describe user jane

# Get the generated kubeconfig
kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > /tmp/kubeconfig

# Test user access
kubectl --kubeconfig /tmp/kubeconfig get pods -n dev

# Delete user (cleans up all associated resources)
kubectl delete user jane
```

### Comprehensive Testing

For thorough testing of all features, use the provided test script:

```bash
# Run the comprehensive test suite
./test-kubeuser.sh
```

This script tests:
- Prerequisites validation
- Controller deployment health
- User creation and RBAC bindings
- Certificate generation and kubeconfig creation
- User access validation
- Certificate rotation
- Resource cleanup

#### Manual Testing Steps

1. **Setup test environment:**
   ```bash
   kubectl apply -f test/test-setup.yaml
   ```

2. **Create a test user:**
   ```bash
   kubectl apply -f test/test-user-jane-1.yaml
   ```

3. **Verify user creation:**
   ```bash
   kubectl get users
   kubectl describe user jane
   ```

4. **Check generated resources:**
   ```bash
   # Check secrets
   kubectl get secrets -n kubeuser | grep jane
   
   # Check RBAC bindings
   kubectl get rolebindings -n dev | grep jane
   kubectl get clusterrolebindings | grep jane
   
   # Check CSR (if still present)
   kubectl get csr -l auth.openkube.io/user=jane
   ```

5. **Test user access:**
   ```bash
   # Extract kubeconfig
   kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > /tmp/jane.kubeconfig
   
   # Test authentication
   kubectl --kubeconfig /tmp/jane.kubeconfig auth can-i get pods -n dev
   
   # Test actual access
   kubectl --kubeconfig /tmp/jane.kubeconfig get pods -n dev
   ```

## ⚙️ Configuration

### Environment Variables

The operator supports the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KUBERNETES_API_SERVER` | `https://kubernetes.default.svc` | Kubernetes API server address |
| `CLUSTER_DOMAIN` | `cluster.local` | Kubernetes cluster DNS domain (change if your cluster uses a custom domain) |

## 🔧 Troubleshooting

### Common Issues

#### Controller Pod Not Starting

```bash
# Check pod status
kubectl get pods -n kubeuser

# Check pod logs
kubectl logs -n kubeuser deployment/kubeuser-controller-manager

# Check events
kubectl get events -n kubeuser --sort-by=.lastTimestamp
```

**Common causes:**
- Missing cert-manager installation
- Webhook certificate not ready
- Image pull issues (for local development)

#### Webhook Certificate Issues

```bash
# Check certificate status
kubectl get certificates -n kubeuser
kubectl describe certificate kubeuser-webhook-cert -n kubeuser

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Force certificate recreation
kubectl delete certificate kubeuser-webhook-cert -n kubeuser
kubectl apply -k config/default
```

#### User Creation Fails

```bash
# Check user status
kubectl describe user <username>

# Check controller logs
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -i error

# Check webhook validation
kubectl get validatingwebhookconfiguration kubeuser-validating-webhook-configuration -o yaml
```

**Common causes:**
- Referenced roles don't exist
- Target namespace doesn't exist (controller no longer auto-creates namespaces)
- RBAC permission issues
- Webhook validation failures

**Namespace Issues:**
If you see errors about missing namespaces, ensure you:
- Used `--create-namespace` with Helm installation
- Pre-created the namespace for Kustomize deployments

#### Certificate Generation Issues

```bash
# Check CSR status
kubectl get csr -l auth.openkube.io/user=<username>

# Check CSR details
kubectl describe csr <csr-name>

# Check controller RBAC permissions
kubectl auth can-i create certificatesigningrequests --as=system:serviceaccount:kubeuser:kubeuser-controller-manager
```

### Getting Help

For additional support:
1. Check the comprehensive documentation in `docs/`
2. Review logs for specific error messages
3. Ensure all prerequisites are properly installed
4. Verify RBAC permissions are correctly configured

## 📚 Documentation

- [Certificate Management Guide](docs/certificate-management.md) - Comprehensive certificate management details
- [Webhook Validation](docs/webhook-validation.md) - Webhook validation and troubleshooting
- [Test Script](test-kubeuser.sh) - Automated testing script

## 🚀 Quick Reference

### Essential Commands

```bash
# Deploy KubeUser
kubectl apply -k config/default

# Check deployment status
kubectl get pods -n kubeuser
kubectl get certificates -n kubeuser

# Create a user
kubectl apply -f test/test-user-jane-1.yaml

# Get user kubeconfig
kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > jane.kubeconfig

# Test user access
kubectl --kubeconfig jane.kubeconfig auth can-i get pods -n dev

# Clean up
kubectl delete user jane
kubectl delete -k config/default
```

### Key Resources Created

- **Namespace**: `kubeuser`
- **CRD**: `users.auth.openkube.io`
- **Controller**: `kubeuser-controller-manager`
- **Webhook**: `kubeuser-validating-webhook-configuration`
- **Certificates**: `kubeuser-webhook-cert` (managed by cert-manager)

### User Resource Secrets

For each user, the controller creates:
- `<username>-key`: Private key secret
- `<username>-kubeconfig`: Complete kubeconfig file
- CSR: `<username>-csr` (temporary, cleaned up after use)


## 💻 Development Guide

### Prerequisites

- **Go**: Version 1.24+ (as specified in go.mod)
- **Docker**: For building container images
- **kubectl**: Kubernetes command-line tool
- **Kind**: For local testing (optional but recommended)
- **Kustomize**: For manifest management
- **Kubebuilder**: v3.0+ (for code generation)

### Local Development Setup

1. **Clone the repository**:
```bash
git clone https://github.com/openkube-hub/KubeUser.git
cd KubeUser
```

2. **Install dependencies**:
```bash
go mod tidy
```

3. **Generate code and manifests**:
```bash
make generate
make manifests
```

4. **Run tests**:
```bash
make test
```

### Building and Running Locally

```bash
# Build the manager binary
make build

# Run against a Kubernetes cluster (requires kubeconfig)
make run

# Build and load Docker image (requires Docker)
make docker-build
```

### Testing

#### Unit Tests
```bash
# Run all unit tests
make test

# Run tests with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

#### End-to-End Tests
```bash
# Run e2e tests (creates Kind cluster)
make test-e2e

# Manual e2e testing
make setup-test-e2e  # Creates Kind cluster
# ... run manual tests ...
make cleanup-test-e2e  # Cleanup
```

### Linting and Code Quality

```bash
# Run linter
make lint

# Fix linting issues automatically
make lint-fix

# Verify linting configuration
make lint-config

# Format code
make fmt

# Vet code
make vet
```

### Development Workflow

1. **Make changes** to the code
2. **Generate code**: `make generate manifests`
3. **Run tests**: `make test`
4. **Test locally**: `make run`
5. **Build image**: `make docker-build`
6. **Run e2e tests**: `make test-e2e`


## 🤝 Contributing

We welcome contributions to KubeUser! Please follow these guidelines:


### Submitting Pull Requests

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Follow** the development setup above
4. **Make** your changes with tests
5. **Ensure** all tests pass: `make test lint`
6. **Commit** with conventional commit format:
   ```
   feat: add user group management
   
   - Implement UserGroup CRD
   - Add controller logic for group management
   - Include comprehensive tests
   
   Fixes #123
   ```
7. **Push** to your fork: `git push origin feature/amazing-feature`
8. **Create** a Pull Request

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Pass `golangci-lint` checks
- Write comprehensive tests for new features
- Update documentation for user-facing changes

### Commit Message Format

We use [Conventional Commits](https://conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test-related changes
- `refactor:` Code refactoring
- `ci:` CI/CD changes
- `chore:` Maintenance tasks

---

If you find KubeUser useful, please consider giving it a ⭐ on GitHub!