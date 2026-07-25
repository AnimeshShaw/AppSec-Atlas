# 03. Kubernetes SecurityContext & Pod Standards

Kubernetes `securityContext` settings dictate the privilege level, filesystem access, and capabilities granted to a Pod or Container.

---

## 1. Kubernetes Pod Security Standards (PSS)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Pod Security Standards (PSS)                          │
├────────────┬────────────────────────────────────────────────────────────────┤
│ Privileged  │ Unrestricted access (Allows host root, host network/IPC).     │
│ Baseline    │ Minimal restrictions; prevents known privilege escalations.    │
│ Restricted  │ Hardened (Forces non-root, drops ALL capabilities, read-only FS)│
└────────────┴────────────────────────────────────────────────────────────────┘
```

---

## 2. Hardened Kubernetes Pod Manifest (`securityContext`)

```yaml
# secure-pod.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-web-app
  namespace: production
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: web-app
    spec:
      # POD-LEVEL SECURITY CONTEXT
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault # Enforces Seccomp syscall filtering!
      
      containers:
        - name: web-app
          image: myregistry.azurecr.io/appsec-atlas/api:v1.0.0
          
          # CONTAINER-LEVEL SECURITY CONTEXT
          securityContext:
            allowPrivilegeEscalation: false # Prevents setuid binary exploits!
            readOnlyRootFilesystem: true    # Blocks attackers from writing files to disk!
            capabilities:
              drop:
                - ALL # Drops ALL Linux kernel capabilities!

          # Mount temporary memory volume for required temp writes
          volumeMounts:
            - mountPath: /tmp
              name: tmp-volume

      volumes:
        - name: tmp-volume
          emptyDir:
            medium: Memory
```

---

*Next Chapter: [04. NetworkPolicies & RBAC Hardening →](04-network-policies-and-rbac.md)*
