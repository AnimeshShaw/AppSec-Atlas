# Network Microsegmentation

Microsegmentation divides the network into granular security zones, restricting east-west lateral movement.

## Service Mesh (Istio / Linkerd)
A service mesh provides mutual TLS (mTLS) between microservices by default, ensuring all communication is encrypted and strongly authenticated at the service identity level.

### Istio mTLS Policy Example

```yaml
# peer-authentication.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: my-namespace
spec:
  mtls:
    mode: STRICT
```

### Authorization Policy
Restricting access so only the frontend can call the backend.

```yaml
# authz-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: backend-authz
  namespace: my-namespace
spec:
  selector:
    matchLabels:
      app: backend
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/my-namespace/sa/frontend-sa"]
```

## Software-Defined Perimeter (SDP)
SDP dynamically creates one-to-one network connections between the user and the resources they access.
