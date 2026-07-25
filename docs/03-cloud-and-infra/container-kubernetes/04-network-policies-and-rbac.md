# 04. NetworkPolicies & RBAC Hardening

By default, Kubernetes network traffic between all Pods across all namespaces is **unrestricted**. Furthermore, overly permissive RBAC roles permit compromised Pods to query or modify the Kubernetes API server.

---

## 1. Default Deny NetworkPolicy

Enforcing a **Default Deny All** NetworkPolicy blocks lateral movement if a single Pod is compromised.

```yaml
# default-deny-all.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {} # Applies to ALL pods in namespace
  policyTypes:
    - Ingress
    - Egress
```

### Explicit Allow Rule Example
```yaml
# allow-frontend-to-backend.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      role: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: frontend
      ports:
        - protocol: TCP
          port: 8080
```

---

## 2. Least Privilege RBAC & ServiceAccount Token Controls

Pods by default mount the ServiceAccount JWT token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. If the Pod does not interact with the K8s API server, automounting MUST be disabled.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production
automountServiceAccountToken: false # Blocks token exposure!
```

---

*Next Chapter: [05. Runtime Threat Detection with Falco →](05-runtime-security-and-falco.md)*
