# 06. Hands-On Vulnerability Lab

In this hands-on lab, you will audit a **vulnerable Kubernetes Deployment manifest**, analyze how a privilege escalation vulnerability permits container escapes, and refactor the manifest into a hardened, production-grade deployment.

---

## 🧪 Lab Scenario

### Step 1: Vulnerable Pod Manifest (`vulnerable-pod.yaml`)

```yaml
# vulnerable-pod.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: ubuntu:22.04
          command: ["sleep", "3600"]
          
          # VULNERABLE SECURITY CONTEXT:
          securityContext:
            privileged: true                  # VULNERABLE: Full host kernel access!
            allowPrivilegeEscalation: true    # VULNERABLE: Can gain root privileges via setuid binaries!
            readOnlyRootFilesystem: false     # VULNERABLE: Can overwrite binaries on disk!
```

### Exploit Analysis:
Because `privileged: true` is set, an attacker inside the container can run:
```bash
# Inside privileged container:
mknod /dev/sda1 b 8 1
mkdir /mnt/host
mount /dev/sda1 /mnt/host
# Attacker now has full READ/WRITE access to the host root filesystem!
```

---

### Step 2: Hardened Secure Manifest (`secure-pod.yaml`)

```yaml
# secure-pod.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 2
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      # POD SECURITY CONTEXT
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: app
          image: gcr.io/distroless/static-debian12:nonroot
          
          # CONTAINER SECURITY CONTEXT
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

---

*Next Chapter: [07. References & Standards →](07-references.md)*
