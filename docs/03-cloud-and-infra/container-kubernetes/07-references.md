---
title: 07. References, Benchmarks & Security Standards
description: Authoritative benchmarks, security standards, MITRE ATT&CK for Containers
  mapping, CVE history, and recommended AppSec tooling.
keywords:
- cis
- benchmarks
- nist
- sp
- 800-190
- mitre
- att
- ck
- containers
- nsa
- cisa
- k8s
- guidance
- cve-2024-21626
- runc
- breakout
- container
- tools
- appsec
sidebar_position: 8
slug: /cloud-and-infra/container-kubernetes/references
---


# 07. References, Benchmarks & Security Standards

This reference guide provides an authoritative aggregation of industry standards, regulatory frameworks, threat matrix mappings, historical CVE analysis, and recommended security tooling for Container & Kubernetes Security.

---

## 1. Industry Benchmarks & Technical Frameworks

- **[CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)** — Definitive consensus-based hardening guidance for Kubernetes control plane components, worker nodes, ETCD, and RBAC policies.
- **[CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)** — Security recommendations for configuring the Docker daemon, host OS container parameters, container runtime flags, and image creation.
- **[NIST SP 800-190: Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)** — Comprehensive recommendations by NIST covering container image risks, registry risks, orchestrator risks, and host OS risks.
- **[NSA / CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_V1.2.PDF)** — Joint cybersecurity technical report detailing threat mitigations for K8s pod security, network separation, authentication, and log auditing.
- **[Kubernetes Official Security Documentation](https://kubernetes.io/docs/concepts/security/)** — Official documentation covering Pod Security Admission (PSA), SecurityContext specs, NetworkPolicies, and RBAC configuration.
- **[OWASP Docker Top 10](https://owasp.org/www-project-docker-top-10/)** — Community project identifying the top 10 security risks associated with Docker container deployment.

---

## 2. MITRE ATT&CK Framework Matrix for Containers

The **MITRE ATT&CK for Containers** matrix documents real-world adversary tactics, techniques, and procedures (TTPs) targeting containerized environments:

| ATT&CK Tactic | Technique ID | Technique Name | Common Mitigation / Security Control |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1610` | Deploy Container | Restrict registry sources, enforce Cosign image verification. |
| **Execution** | `T1609` | Container Administration Command | Audit `kubectl exec` calls, block shell binaries in distroless images. |
| **Persistence** | `T1613` | Container and Resource Discovery | Enforce `readOnlyRootFilesystem: true`, restrict daemonset creation. |
| **Privilege Escalation**| `T1611` | Escape to Host | Set `privileged: false`, drop `CAP_SYS_ADMIN`, enforce Seccomp filters. |
| **Defense Evasion** | `T1562.001` | Disable or Modify Tools | Protect eBPF probes, restrict root capabilities in containers. |
| **Credential Access** | `T1552.007` | Container API Tokens | Set `automountServiceAccountToken: false`, disable public API server access. |
| **Discovery** | `T1613` | Container and Resource Discovery | Enforce least-privilege RBAC roles, audit API server requests. |
| **Lateral Movement** | `T1557` | Adversary-in-the-Middle | Deploy Default Deny NetworkPolicies, enforce mutual TLS (mTLS). |
| **Impact** | `T1496` | Resource Hijacking (Cryptomining) | Enforce cgroups CPU and Memory resource limits (`limits.cpu/memory`). |

---

## 3. Historical Container Breakout Vulnerabilities (CVE Matrix)

Analyzing major historical container zero-day vulnerabilities highlights the critical importance of defense-in-depth isolation:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 HISTORICAL CONTAINER ESCAPE VULNERABILITIES                 │
├───────────────┬─────────────────────────────────────────────────────────────┤
│ CVE Identifier│ Vulnerability Summary & Escape Vector                       │
├───────────────┼─────────────────────────────────────────────────────────────┤
│ **CVE-2024-21626**│ **runc Process Directory Leak:** Leaked file descriptor     │
│ (runc Leaks)  │ inside `runc` allowed container processes to overwrite host │
│               │ host binaries via `/proc/self/fd/` manipulation.            │
├───────────────┼─────────────────────────────────────────────────────────────┤
│ **CVE-2022-0847**│ **Dirty Pipe Kernel Flaw:** Arbitrary file overwrite flaw   │
│ (Dirty Pipe)  │ in Linux kernel allowed unprivileged container processes to │
│               │ overwrite host root files (e.g. `/etc/passwd`).             │
├───────────────┼─────────────────────────────────────────────────────────────┤
│ **CVE-2019-5736**│ **runc Container Escape:** Allowed malicious container to   │
│ (runc Overwrite)│ overwrite host `runc` binary when an admin executed `exec`. │
├───────────────┼─────────────────────────────────────────────────────────────┤
│ **CVE-2016-5195**│ **Dirty COW:** Race condition in Linux kernel copy-on-write │
│ (Dirty COW)   │ mechanism allowed write access to read-only memory mappings.│
└───────────────┴─────────────────────────────────────────────────────────────┘
```

---

## 4. Open-Source Security Tooling Ecosystem

### Image & Static Code Scanning
- **[Trivy](https://github.com/aquasecurity/trivy)** — Comprehensive vulnerability, secret, license, and IaC misconfiguration scanner for containers.
- **[Hadolint](https://github.com/hadolint/hadolint)** — Haskell-based Dockerfile linter enforcing best practice rules.
- **[Kube-linter](https://github.com/stackrox/kube-linter)** — Static analysis tool for Kubernetes YAML manifests and Helm charts.

### Supply Chain & Image Signing
- **[Cosign / Sigstore](https://github.com/sigstore/cosign)** — Keyless container image signing, verification, and storage in OCI registries.

### Policy Enforcement & Admission Control
- **[Kyverno](https://kyverno.io/)** — Kubernetes-native policy management engine for validating, mutating, and generating configurations.
- **[OPA / Gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/)** — Policy Controller for Kubernetes powered by Open Policy Agent (OPA) and Rego.

### Runtime Security & Compliance
- **[Falco](https://falco.org/)** — Open-source CNCF runtime threat detection engine utilizing eBPF syscall monitoring.
- **[Kube-bench](https://github.com/aquasecurity/kube-bench)** — Automated audit tool that checks whether a Kubernetes cluster meets CIS Benchmark checks.

---

*Return to [Module Overview & Navigation Index →](README.md)*
