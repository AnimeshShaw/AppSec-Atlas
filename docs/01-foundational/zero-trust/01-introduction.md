---
title: "Introduction to Zero Trust"
description: "Traditional network security relied on the 'castle-and-moat' model, where once an attacker breached the perimeter, they had unfettered lateral movemen..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Zero Trust", "01 Introduction.Md"]
---

# Introduction to Zero Trust

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## The Demise of the Perimeter
Traditional network security relied on the "castle-and-moat" model, where once an attacker breached the perimeter, they had unfettered lateral movement. Zero Trust assumes the network is already hostile.

## Core Principles

1. **"Never Trust, Always Verify"**: Explicitly verify all aspects of a request—identity, endpoint posture, location, and context—regardless of where the request originates.
2. **Assume Breach**: Operate as if the environment is already compromised. Minimize blast radius through microsegmentation and end-to-end encryption.
3. **Least Privilege Access**: Grant only the minimal access necessary, Just-In-Time (JIT) and Just-Enough-Access (JEA), using risk-based adaptive policies.

## Threat Landscape
- Phishing and Credential Stuffing
- Insider Threats
- Ransomware Lateral Movement
