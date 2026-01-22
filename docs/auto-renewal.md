# Auto-Renewal Feature for KubeUser

## Overview

The Auto-Renewal feature provides production-grade automatic certificate renewal for KubeUser, following cert-manager's proven renewal logic. This feature ensures zero-downtime certificate rotation with forward secrecy and intelligent requeue strategies.

## Key Features

- **Smart Renewal Logic**: Follows cert-manager's 33% rule with customizable `renewBefore` override
- **Forward Secrecy**: Generates new private keys for each renewal
- **Zero-Downtime**: Atomic secret updates ensure continuous access
- **Thundering Herd Prevention**: Jitter-based requeue scheduling
- **Short-lived Certificate Support**: Handles certificates as short as 10 minutes
- **Comprehensive Observability**: Status conditions and Kubernetes events

## Configuration

### Basic Auto-Renewal

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509
    ttl: "24h"
    autoRenew: true  # Enable auto-renewal
```

This configuration uses the default 33% rule: the certificate will be renewed when 33% of its lifetime remains (after 16 hours for a 24-hour certificate).

### Custom Renewal Timing

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob
spec:
  auth:
    type: x509
    ttl: "2h"
    autoRenew: true
    renewBefore: "30m"  # Renew 30 minutes before expiry
```

### Short-lived Certificates

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: charlie
spec:
  auth:
    type: x509
    ttl: "10m"         # Minimum supported duration
    autoRenew: true
    renewBefore: "3m"  # Must be at least 2m for safety
```

## Renewal Logic Hierarchy

The system follows this hierarchy when determining renewal time:

1. **Custom `renewBefore`**: If specified, renew this duration before expiry
2. **33% Rule**: Default cert-manager behavior (renew when 33% of lifetime remains)
3. **Safety Floor**: Never renew less than 2 minutes before expiry (for short-lived certs)

### Examples

| Certificate TTL | renewBefore | Actual Renewal Time | Logic Used |
|----------------|-------------|-------------------|------------|
| 24h | (not set) | After 16h | 33% rule |
| 24h | 6h | After 18h | Custom renewBefore |
| 10m | (not set) | After 6m40s | 33% rule |
| 10m | 1m | After 8m | Safety floor (2m minimum) |

## Status Fields

The User status includes several fields for monitoring renewal:

```yaml
status:
  phase: "Active"
  expiryTime: "2026-01-22T10:30:00Z"
  nextRenewalAt: "2026-01-22T02:30:00Z"
  certificateExpiry: "Certificate"
  conditions:
  - type: Ready
    status: "True"
    reason: CertificateActive
    message: Certificate is valid and active
  - type: Renewing
    status: "False"
    reason: RenewalComplete
    message: Certificate renewal completed
  - type: AutoRenewal
    status: "True"
    reason: AutoRenewalEnabled
    message: Auto-renewal is enabled
  renewalHistory:
  - timestamp: "2026-01-21T10:30:00Z"
    success: true
    message: Certificate rotation completed successfully
    csrName: alice-csr-1737540600
```

## Observability

### Status Conditions

- **Ready**: Indicates if the user's certificate is valid and ready
- **Renewing**: Shows if a renewal is currently in progress
- **AutoRenewal**: Indicates if auto-renewal is enabled and configured correctly

### Kubernetes Events

The controller emits events for key renewal lifecycle events:

- `RenewalStarted`: When certificate renewal begins
- `RenewalCompleted`: When renewal completes successfully
- `RenewalFailed`: When renewal encounters an error
- `RenewalScheduled`: When the next renewal is scheduled
- `CertificateExpiring`: Warning when certificate is approaching expiry
- `AutoRenewalEnabled/Disabled`: When auto-renewal configuration changes

### Monitoring with kubectl

```bash
# Check user status
kubectl get users alice -o wide

# View detailed status
kubectl describe user alice

# Watch renewal events
kubectl get events --field-selector involvedObject.name=alice --watch

# Check renewal history
kubectl get user alice -o jsonpath='{.status.renewalHistory[*]}'
```

## Requeue Strategy

The controller uses intelligent requeue scheduling to minimize API server load:

1. **Smart Calculation**: Uses `nextRenewalTime` from status for efficient scheduling
2. **Jitter**: Adds random jitter (up to 5 minutes) to prevent thundering herd
3. **Bounded Requeue**: Limits requeue intervals between 1 minute and 24 hours
4. **Immediate Renewal**: Requeues immediately when renewal time is reached

## Certificate Rotation Process

The atomic rotation process ensures zero-downtime:

1. **Generate New Key**: Creates new RSA private key for forward secrecy
2. **Create CSR**: Generates deterministic CSR name for idempotency
3. **Auto-Approve**: Controller automatically approves its own CSRs
4. **Wait for Certificate**: Monitors CSR until signed certificate is available
5. **Atomic Update**: Updates both key and kubeconfig secrets simultaneously
6. **Cleanup**: Removes old CSR after successful rotation
7. **Status Update**: Updates user status with new certificate information

## Validation Rules

- `autoRenew` must be boolean
- `renewBefore` must be positive duration if specified
- `renewBefore` must be less than certificate TTL
- For certificates ≤ 10 minutes, `renewBefore` must be ≥ 2 minutes
- Certificate TTL must be ≥ 10 minutes (Kubernetes CSR minimum)

## Error Handling

The system handles various error scenarios gracefully:

- **CSR Creation Failures**: Retries with exponential backoff
- **Approval Failures**: Logs error and retries on next reconcile
- **Certificate Unavailable**: Continues monitoring until available
- **Secret Update Failures**: Rolls back and retries
- **Network Issues**: Uses controller-runtime's built-in retry logic

## Performance Considerations

- **Efficient Status Checking**: Uses `nextRenewalTime` to avoid certificate parsing
- **Jittered Requeues**: Prevents API server overload during mass renewals
- **Deterministic CSR Names**: Ensures idempotency across controller restarts
- **Cleanup**: Removes old CSRs to prevent resource accumulation

## Migration from Manual Renewal

Existing users can be migrated to auto-renewal by simply adding the `autoRenew: true` field. The controller will:

1. Calculate renewal time based on current certificate expiry
2. Schedule the next renewal appropriately
3. Begin automatic renewal cycles

## Troubleshooting

### Common Issues

1. **Renewal Not Triggering**
   - Check `nextRenewalTime` in status
   - Verify `autoRenew: true` is set
   - Check controller logs for errors

2. **Renewal Failures**
   - Check CSR approval permissions
   - Verify controller has certificate signing permissions
   - Review renewal history in status

3. **Performance Issues**
   - Monitor requeue intervals in logs
   - Check for excessive API calls
   - Verify jitter is working correctly

### Debug Commands

```bash
# Check controller logs
kubectl logs -n kubeuser-system deployment/kubeuser-controller-manager

# List all CSRs for a user
kubectl get csr -l auth.openkube.io/user=alice

# Check certificate expiry
kubectl get secret alice-kubeconfig -o jsonpath='{.data.config}' | base64 -d | grep client-certificate-data | base64 -d | openssl x509 -noout -dates

# Monitor renewal events
kubectl get events --field-selector reason=RenewalStarted,reason=RenewalCompleted,reason=RenewalFailed
```

## Security Considerations

- **Forward Secrecy**: New private keys generated for each renewal
- **Atomic Updates**: Prevents exposure of mismatched key/certificate pairs
- **Auto-Approval**: Controller only approves CSRs it created with proper labels
- **Cleanup**: Old CSRs are removed to prevent information leakage
- **Audit Trail**: Complete renewal history maintained in status

## Future Enhancements

- **Certificate Authority Rotation**: Support for CA certificate updates
- **External CA Integration**: Support for external certificate authorities
- **Renewal Webhooks**: Configurable webhooks for renewal notifications
- **Metrics Integration**: Prometheus metrics for renewal monitoring
- **Backup/Restore**: Certificate backup before renewal