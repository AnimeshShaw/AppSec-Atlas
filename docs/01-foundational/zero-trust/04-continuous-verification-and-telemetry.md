# Continuous Verification and Telemetry

Zero Trust is not a one-time check. Trust must be continuously evaluated during a session.

## Continuous Authorization
If risk signals change (e.g., impossible travel detected, device vulnerability discovered), active sessions must be terminated or stepped up (e.g., re-prompt for MFA).

## Telemetry and SIEM Integration
Comprehensive visibility is required to detect anomalous behavior.
Log all access requests, policy evaluations, and network flows.

### Essential Telemetry Sources
- Identity Provider (IdP) logs
- Device Management (MDM) logs
- Service Mesh access logs
- Application-level audit trails
