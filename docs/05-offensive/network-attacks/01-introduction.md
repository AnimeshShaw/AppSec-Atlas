---
title: "01 - Introduction & Theory"
description: "The OSI (Open Systems Interconnection) model breaks network communication down into 7 layers. Security must be applied at multiple layers to be effect..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Network Attacks", "01 Introduction.Md"]
---

# 01 - Introduction & Theory

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## OSI Model Security
The OSI (Open Systems Interconnection) model breaks network communication down into 7 layers. Security must be applied at multiple layers to be effective.

| Layer | Name | Security Threats | Defenses |
|-------|------|------------------|----------|
| 7 | Application | XSS, SQLi, Payload injection | WAF, RASP, Input Validation |
| 6 | Presentation| Weak crypto, encoding bypass | TLS, Strong Ciphers |
| 5 | Session | Session hijacking, MiTM | Secure Cookies, Session timeouts |
| 4 | Transport | SYN Flood, UDP Flood | Stateful Firewalls, TLS |
| 3 | Network | IP Spoofing, Route injection | IPSec, ACLs, BCP38 |
| 2 | Data Link | ARP Spoofing, MAC Flooding | Port Security, 802.1X |
| 1 | Physical | Wiretapping, hardware tampering | Physical security, lock-and-key |

## TCP/IP Protocol Vulnerabilities
The TCP/IP suite was designed for connectivity, not security. Many core protocols implicitly trust the sender, leading to inherent vulnerabilities:
- **No inherent authentication:** ARP, IP, and DNS do not authenticate the source by default.
- **Cleartext communication:** HTTP, Telnet, and FTP send data in the clear, allowing passive sniffing.
- **State exhaustion:** TCP's three-way handshake can be abused via SYN floods.

## Network Segmentation Fundamentals
Segmentation involves splitting a large network into smaller, isolated subnetworks. This limits the blast radius if an attacker breaches the perimeter.

- **VLANs (Virtual LANs):** Layer 2 segmentation separating broadcast domains.
- **Subnets:** Layer 3 segmentation grouping IP addresses.
- **Firewalls:** Placed between segments to enforce access control.

## Perimeter vs Zero Trust Networking
### The Old Model: Perimeter Security
"M&M Security" - hard on the outside, soft and chewy on the inside. Once an attacker bypasses the edge firewall, they have unrestricted lateral movement.

### The New Model: Zero Trust
"Never trust, always verify."
- No implicit trust based on network location.
- Microsegmentation limits lateral movement.
- Strong identity authentication for every access request, regardless of where the request originates.
