---
title: "Container & Kubernetes Security Guide"
description: "Master container lifecycle and Kubernetes security. Learn Dockerfile hardening, K8s SecurityContext, NetworkPolicies, RBAC, and Falco runtime detection."
keywords: [container security, kubernetes security, dockerfile hardening, k8s security context, network policies, rbac, falco, linux isolation, cloud security]
sidebar_position: 1
---

# Container & Kubernetes Security Guide

> [!NOTE]
> **Section:** ☁️ Cloud & Infrastructure Security  
> **Level:** Intermediate to Advanced  
> **Time to Complete:** ~80 minutes  
> **Prerequisites:** Basic knowledge of Docker, Linux command line, and Kubernetes manifests  
> **Status:** ✅ Complete & Production-Ready

---

## 🎯 Overview & Learning Objectives

Container and Kubernetes Security focuses on securing the full container lifecycle — from writing secure Dockerfiles and building minimal distroless images to configuring Kubernetes Pod Security Standards, NetworkPolicies, RBAC, and runtime threat detection with Falco.

By the end of this practical guide, you will be able to:
- [x] **Understand** Linux kernel isolation primitives (Namespaces, cgroups, Capabilities, Seccomp).
- [x] **Write** hardened Dockerfiles using non-root users, multi-stage builds, and distroless base images.
- [x] **Configure** Kubernetes `securityContext` manifests to satisfy the Restricted Pod Security Standard.
- [x] **Enforce** NetworkPolicies (Default Deny) and least-privilege RBAC roles.
- [x] **Detect** container escapes and suspicious runtime activity using eBPF & Falco.
- [x] **Solve** a hands-on lab: Vulnerable Container & K8s Manifest + Exploit Verification + Hardened Remediation.

---

## 📚 Module Navigation

1. **[01. Overview & Linux Isolation Primitives](01-introduction.md)** — Namespaces (PID, NET, MNT), cgroups, Linux Capabilities (`CAP_SYS_ADMIN`), and Seccomp syscall filtering.
2. **[02. Hardened Dockerfiles & Image Security](02-dockerfile-hardening.md)** — Multi-stage builds, distroless images, non-root user execution, read-only root filesystems, and image scanning with Trivy & Hadolint.
3. **[03. Kubernetes SecurityContext & Pod Standards](03-kubernetes-security-context.md)** — Pod Security Admission (PSA), `securityContext` specs, dropping capabilities, and Seccomp profiles.
4. **[04. NetworkPolicies & RBAC Hardening](04-network-policies-and-rbac.md)** — Default Deny ingress/egress NetworkPolicies, Kubernetes RBAC roles, ServiceAccount token automounting controls, and API server auditing.
5. **[05. Runtime Threat Detection with Falco](05-runtime-security-and-falco.md)** — eBPF kernel monitoring, writing custom Falco rules, and container escape threat detection.
6. **[06. Hands-On Vulnerability Lab](06-hands-on-lab.md)** — Self-contained Lab: Vulnerable Pod Manifest + Container Breakout Exploit + Restricted Security Context Fix.
7. **[07. References & Standards](07-references.md)** — CIS Kubernetes Benchmark, NIST SP 800-190, Falco rules, and Hadolint docs.

---

*Begin reading: [01. Overview & Linux Isolation Primitives →](01-introduction.md)*
