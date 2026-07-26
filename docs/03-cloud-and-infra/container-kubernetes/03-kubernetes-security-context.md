---
title: 03. Kubernetes SecurityContext & Pod Security Standards
description: Configure Kubernetes SecurityContext settings to enforce non-root execution,
  drop capabilities, enable Seccomp profiles, enforce read-only filesystems, and comply
  with the Restricted Pod Security Standard.
keywords:
- kubernetes
- security
- context
- pod
- security
- standards
- pod
- security
- admission
- seccomp
- apparmor
- readOnlyRootFilesystem
- runAsNonRoot
- k8s
- hardening
- appsec
sidebar_position: 4
slug: /cloud-and-infra/container-kubernetes/kubernetes-security-context
---


# 03. Kubernetes SecurityContext & Pod Security Standards

Kubernetes `securityContext` parameters define privilege, isolation, and access control settings for Pods and individual Containers. Without explicit security context parameters, Kubernetes runs containers with default settings that permit privilege escalation, root execution, unmasked kernel capabilities, and arbitrary filesystem writes.

To protect workloads against container escapes and kernel exploitation, administrators must enforce the official Kubernetes **Pod Security Standards (PSS)** using the **Pod Security Admission (PSA)** controller.

---

## 1. Kubernetes Pod Security Standards (PSS) & Admission Controls

Kubernetes categorizes pod security requirements into three progressive profiles:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    KUBERNETES POD SECURITY STANDARDS (PSS)                  │
├──────────────┬──────────────────────────────────────────────────────────────┤
│ Profile      │ Description & Security Controls Enforced                     │
├──────────────┼──────────────────────────────────────────────────────────────┤
│ **Privileged**│ Unrestricted. Allows host root access, host PID/NET/IPC,     │
│              │ privileged mode, and custom capabilities. (Infrastructure only)│
├──────────────┼──────────────────────────────────────────────────────────────┤
│ **Baseline** │ Minimal restrictions. Blocks known privilege escalation      │
│              │ vectors, host network/PID namespaces, and host path mounts.  │
├──────────────┼──────────────────────────────────────────────────────────────┤
│ **Restricted**│ Production Hardened. Forces non-root execution, drops ALL    │
│              │ Linux capabilities, restricts volume types, enforces Seccomp. │
└──────────────┴──────────────────────────────────────────────────────────────┘
```

### Enforcing Pod Security Admission via Namespace Labels

Enforce the Restricted Pod Security profile at the namespace boundary by setting namespace metadata labels:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Enforces strict compliance; blocks non-compliant pod creation
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    # Generates warnings in kubectl output for soft violations
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

---

## 2. Technical Breakdown of `securityContext` Controls

Security parameters can be applied at the **Pod Level** (applies to all containers in the Pod) or at the **Container Level** (overrides settings for a specific container).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SECURITYCONTEXT FIELD DEEP DIVE                        │
├─────────────────────────────┬──────┬────────────────────────────────────────┤
│ Field Parameter             │ Level│ Security Purpose                       │
├─────────────────────────────┼──────┼────────────────────────────────────────┤
│ `runAsNonRoot: true`        │ Pod  │ Prevents container from starting if    │
│                             │      │ configured to execute as UID 0 (root).  │
├─────────────────────────────┼──────┼────────────────────────────────────────┤
│ `runAsUser: 10001`          │ Pod  │ Explicitly assigns an unprivileged     │
│ `runAsGroup: 10001`         │      │ User ID and Group ID to the process.   │
├─────────────────────────────┼──────┼────────────────────────────────────────┤
│ `allowPrivilegeEscalation`  │ Cont │ Disables `setuid` and `setgid` binary  │
│ `: false`                   │      │ execution to prevent root escalation.  │
├─────────────────────────────┼──────┼────────────────────────────────────────┤
│ `readOnlyRootFilesystem`    │ Cont │ Mounts container root filesystem as    │
│ `: true`                    │      │ read-only; blocks writing malware/logs.│
├─────────────────────────────┼──────┼────────────────────────────────────────┤
│ `capabilities.drop: [ALL]`  │ Cont │ Drops all 41 Linux kernel capabilities │
│                             │      │ from the container process header.     │
├─────────────────────────────┼──────┼────────────────────────────────────────┤
│ `seccompProfile.type`       │ Pod/ │ Applies `RuntimeDefault` Seccomp filter│
│ `: RuntimeDefault`          │ Cont │ to block ~44 dangerous system calls.   │
└─────────────────────────────┴──────┴────────────────────────────────────────┘
```

### Critical Security Parameters Explained:

#### 1. `allowPrivilegeEscalation: false`
Controls whether a process can gain more privileges than its parent process. Setting this to `false` sets the `no_new_privs` flag in the Linux kernel, preventing binaries with the `setuid` or `setgid` bit (e.g. `sudo`, `su`, `chsh`) from elevating privileges.

#### 2. `readOnlyRootFilesystem: true`
Prevents attackers who achieve Remote Code Execution (RCE) from modifying application source files, replacing binaries, installing rootkits, or writing scripts to disk. 

> [!TIP]
> **Handling Temporary File Writes:** If your application requires temporary directories like `/tmp` or `/var/log`, mount an in-memory `emptyDir` volume instead of making the root filesystem writable.

#### 3. `capabilities.drop: ["ALL"]`
Completely strips all default Linux capabilities (`CAP_NET_RAW`, `CAP_SYS_CHROOT`, `CAP_MKNOD`, etc.). If a process strictly requires a specific capability (such as `CAP_NET_BIND_SERVICE` to bind to port 80), explicitly drop `ALL` first and add only the single required capability.

---

## 3. Custom Seccomp & AppArmor Profiles in Kubernetes

### A. Custom Seccomp Profile Configuration

If the `RuntimeDefault` profile is too permissive for high-security workloads, create a custom JSON Seccomp profile on the node host:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_AARCH64"
  ],
  "syscalls": [
    {
      "names": [
        "accept4",
        "epoll_wait",
        "exit_group",
        "futex",
        "read",
        "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

Reference the custom profile in the Pod spec:
```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/strict-seccomp.json
```

---

## 4. Side-by-Side Manifest Comparison

### ❌ Insecure Kubernetes Deployment Manifest

```yaml
# INSECURE: Fails Restricted Pod Security Standard on multiple vectors!
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-web-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure-app
  template:
    metadata:
      labels:
        app: insecure-app
    spec:
      # VULNERABLE: Uses host namespaces!
      hostPID: true
      hostNetwork: true
      
      containers:
        - name: web-app
          image: node:18
          
          # VULNERABLE: Full privileged host access!
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
          
          # VULNERABLE: Mounts host root disk and Docker socket!
          volumeMounts:
            - mountPath: /host-docker.sock
              name: docker-socket
            - mountPath: /host-root
              name: host-fs

      volumes:
        - name: docker-socket
          hostPath:
            path: /var/run/docker.sock
        - name: host-fs
          hostPath:
            path: /
```

---

### ✅ Production-Hardened Kubernetes Deployment Manifest

```yaml
# SECURE: Fully compliant with Kubernetes Restricted Pod Security Standard
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-web-app
  namespace: production
  labels:
    app.kubernetes.io/name: web-app
    app.kubernetes.io/component: backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: hardened-web-app
  template:
    metadata:
      labels:
        app: hardened-web-app
    spec:
      # 1. POD-LEVEL SECURITY CONTEXT
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault # Enforces Seccomp kernel syscall filtering
      
      containers:
        - name: web-app
          image: myregistry.azurecr.io/appsec-atlas/api:v1.0.0
          imagePullPolicy: Always
          
          # 2. CONTAINER-LEVEL SECURITY CONTEXT
          securityContext:
            allowPrivilegeEscalation: false # Disables setuid binaries
            readOnlyRootFilesystem: true    # Blocks writing to container disk
            capabilities:
              drop:
                - ALL # Drops ALL Linux kernel capabilities!

          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"
            requests:
              cpu: "100m"
              memory: "128Mi"

          # 3. EPHEMERAL IN-MEMORY VOLUMES FOR TEMP WRITES
          volumeMounts:
            - mountPath: /tmp
              name: tmp-volume
            - mountPath: /var/log/app
              name: log-volume

      volumes:
        - name: tmp-volume
          emptyDir:
            medium: Memory
            sizeLimit: 64Mi
        - name: log-volume
          emptyDir:
            medium: Memory
            sizeLimit: 128Mi
```

---

*Next Chapter: [04. NetworkPolicies & RBAC Hardening →](04-network-policies-and-rbac.md)*
