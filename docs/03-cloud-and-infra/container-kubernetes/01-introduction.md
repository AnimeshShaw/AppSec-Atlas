# 01. Overview & Linux Isolation Primitives

Containers are **not** virtual machines. They are isolated Linux processes sharing the host operating system kernel. Understanding container security requires understanding four Linux kernel primitives:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Linux Kernel Isolation Primitives                      │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ Namespaces      │ Process visibility isolation (PID, NET, MNT, IPC, UTS)    │
│ cgroups         │ Hardware resource limits (CPU, Memory, Disk I/O)          │
│ Capabilities    │ Fine-grained root privilege breakdown (CAP_SYS_ADMIN, etc)│
│ Seccomp         │ System call filtering (blocks dangerous syscalls)         │
└─────────────────┴───────────────────────────────────────────────────────────┘
```

---

## 1. Linux Capabilities (`CAP_SYS_ADMIN` Hazard)

By default, root inside an unhardened container retains dangerous Linux capabilities.

```
Attacker in Container (Root) ──► Retains CAP_SYS_ADMIN ──► Mounts host disk /dev/sda1 ──► Host Takeover!
```

### Dangerous Capabilities to Drop:
- `CAP_SYS_ADMIN`: Overly broad root privileges (allows mounting, namespace changes).
- `CAP_NET_ADMIN`: Allows network interface manipulation and packet sniffing.
- `CAP_SYS_PTRACE`: Allows tracing processes outside container boundaries.

---

## 2. Seccomp (Secure Computing Mode)

Seccomp restricts the system calls (syscalls) a process can issue to the kernel. Linux has ~350 syscalls; a typical web app container only needs ~40.

### Default Seccomp Profile in Docker/K8s
Blocking syscalls like `ptrace`, `reboot`, `kexec_load`, and `sys_module` prevents 80%+ of container escape exploits.

---

*Next Chapter: [02. Hardened Dockerfiles & Image Security →](02-dockerfile-hardening.md)*
