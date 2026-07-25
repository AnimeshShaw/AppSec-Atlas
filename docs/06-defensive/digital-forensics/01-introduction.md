---
title: "01 - Introduction to Digital Forensics"
description: "Digital Forensics is the process of uncovering and interpreting electronic data. The goal is to preserve any evidence in its most original form while ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Digital Forensics", "01 Introduction.Md"]
---

# 01 - Introduction to Digital Forensics

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## Digital Forensics & Incident Response (DFIR)
Digital Forensics is the process of uncovering and interpreting electronic data. The goal is to preserve any evidence in its most original form while performing a structured investigation by collecting, identifying, and validating the digital information for the purpose of reconstructing past events.

## Core Principles

### Order of Volatility
When collecting evidence, you must gather data starting from the most volatile (easily lost) to the least volatile. 
1. CPU Registers and Cache
2. RAM (Routing tables, ARP cache, process tables, kernel statistics)
3. Temporary File Systems / Swap Space
4. Disk Data (Hard drives, SSDs)
5. Remote Logging and Monitoring Data
6. Physical Configuration and Network Topology
7. Archival Media (Backups, CD-ROMs)

### Chain of Custody
The Chain of Custody is a chronological documentation that records the sequence of custody, control, transfer, analysis, and disposition of physical or electronic evidence. Without a documented chain of custody, evidence may be ruled inadmissible in a court of law.

### Evidence Integrity & Hashes
To prove that evidence hasn't been tampered with, forensic analysts use cryptographic hashes. When an image of a drive is taken, a hash (typically SHA-256) of the original drive is generated. The hash of the copied image is then compared to ensure they match exactly.

```bash
# Generating a SHA-256 hash of an acquired image using built-in Linux tools
sha256sum evidence_drive.dd > evidence_drive_hash.txt
```

```powershell
# Generating a SHA-256 hash in Windows PowerShell
Get-FileHash -Algorithm SHA256 -Path .\evidence_drive.dd
```

Always operate on a **copy** of the evidence, never the original, to avoid accidental modification.
