---
title: "05. Runtime Threat Detection with Falco"
description: "Falco is an open-source CNCF project that provides real-time threat detection for Linux containers and Kubernetes by parsing Linux kernel system calls..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Container Kubernetes", "05 Runtime Security And Falco.Md"]
---

# 05. Runtime Threat Detection with Falco

Falco is an open-source CNCF project that provides real-time threat detection for Linux containers and Kubernetes by parsing Linux kernel system calls using **eBPF (Extended Berkeley Packet Filter)**.

---

## 1. How Falco Detects Container Intrusions

```
[ Container Process ] ──► System Call (e.g. execve /bin/bash) ──► [ Linux Kernel ]
                                                                       │
                                                                 (eBPF Probe)
                                                                       │
                                                                       ▼
                                                          [ Falco Rules Engine ]
                                                                       │
                                                                       ▼
                                                          🚨 Alert Sent (Slack/SIEM)
```

---

## 2. Custom Falco Rule Example: Detecting Terminal Shell Spawning

```yaml
# custom_falco_rules.yaml
- rule: Terminal Shell Spawned in Container
  desc: Detects interactive bash/sh execution inside production containers
  condition: >
    spawned_process and 
    container and 
    proc.name in (bash, sh, zsh, ksh) and 
    not user_expected_terminal_exec
  output: >
    🚨 ALERT: Interactive shell spawned in container 
    (user=%user.name container_id=%container.id image=%container.image.repository command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, shell, mitre_execution]
```

---

*Next Chapter: [06. Hands-On Vulnerability Lab →](06-hands-on-lab.md)*
