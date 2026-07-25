---
title: "01. Linux Isolation Primitives"
description: "Understand the core Linux kernel isolation primitives for container security, including Namespaces, cgroups, Capabilities, and Seccomp filtering."
keywords: [linux namespaces, cgroups, linux capabilities, seccomp, container isolation, kernel security, cap_sys_admin, container primitives]
sidebar_position: 2
---

# 01. Overview & Linux Isolation Primitives

Containers are **not** virtual machines. They are isolated Linux processes sharing the host operating system kernel. Understanding container security requires understanding four core Linux kernel primitives:

> [!IMPORTANT]
> A container breakout occurs when an attacker escapes the namespace isolation and interacts directly with the underlying host kernel.


| Primitive | Description | Security Impact |
|-----------|-------------|-----------------|
| **Namespaces** | Process visibility isolation (PID, NET, MNT, IPC, UTS, User). | Prevents processes from seeing other containers' networks, mounts, or processes. |
| **cgroups** | Hardware resource limits (CPU, Memory, Disk I/O). | Prevents noisy neighbor DoS attacks and resource exhaustion. |
| **Capabilities** | Fine-grained root privilege breakdown (`CAP_SYS_ADMIN`, etc). | Drops dangerous root privileges to limit the impact of container escapes. |
| **Seccomp** | System call filtering (blocks dangerous syscalls). | Shrinks the kernel attack surface by blocking dangerous syscalls like `ptrace`. |

---

## 1. Linux Capabilities (`CAP_SYS_ADMIN` Hazard)

By default, the `root` user inside an unhardened container retains dangerous Linux capabilities.

> [!WARNING]
> Running containers as root with default capabilities is a significant risk. If an attacker compromises the container, they can leverage capabilities like `CAP_SYS_ADMIN` to escape to the host.

```
Attacker in Container (Root) ──► Retains CAP_SYS_ADMIN ──► Mounts host disk /dev/sda1 ──► Host Takeover!
```

### Dangerous Capabilities to Drop:
- `CAP_SYS_ADMIN`: Overly broad root privileges (allows mounting, namespace changes).
- `CAP_NET_ADMIN`: Allows network interface manipulation and packet sniffing.
- `CAP_SYS_PTRACE`: Allows tracing processes outside container boundaries.

---

## 2. Seccomp (Secure Computing Mode)

Seccomp (Secure Computing Mode) restricts the system calls (syscalls) a process can issue to the kernel. Linux has over 350 syscalls; a typical web app container only needs around 40-50.

> [!TIP]
> The default Seccomp profile in Docker and Kubernetes (when enabled via Pod Security Standards) blocks roughly 44 dangerous syscalls.

### Default Seccomp Profile in Docker/K8s
Blocking syscalls like `ptrace`, `reboot`, `kexec_load`, and `sys_module` prevents 80%+ of kernel exploitation vectors and container escapes.

---

*Next Chapter: [02. Hardened Dockerfiles & Image Security →](02-dockerfile-hardening.md)*
