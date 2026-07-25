---
title: "Security Operations Center (SOC) Operations Guide"
description: "Welcome to the **SOC Operations Guide**. A Security Operations Center (SOC) is the nerve center of an organization's defensive posture, responsible fo..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Soc Operations", "Readme.Md"]
---

# Security Operations Center (SOC) Operations Guide

## Overview
Welcome to the **SOC Operations Guide**. A Security Operations Center (SOC) is the nerve center of an organization's defensive posture, responsible for continuous monitoring, detection, and response to cybersecurity threats. This guide explores the architecture of modern SOC operations, practical incident triage techniques, threat hunting methodologies, and SOC automation (SOAR) principles.

## Prerequisites
Before diving into SOC Operations, you should have:
- Basic understanding of enterprise networking (TCP/IP, DNS, HTTP)
- Familiarity with operating system internals (Windows and Linux)
- Conceptual understanding of common cyber attacks (e.g., Phishing, Malware, Credential Dumping)
- Basic Python scripting skills (for the automation and SOAR labs)

## Learning Objectives
By the end of this module, you will be able to:
1. Understand the tiered structure of a SOC and essential performance metrics (MTTD, MTTR).
2. Execute an alert triage workflow and distinguish true positives from false positives.
3. Leverage MITRE ATT&CK frameworks to contextualize alerts and incidents.
4. Implement automated alert enrichment using Python (SOAR principles).
5. Conduct hypothesis-driven threat hunts using SIEM queries (KQL, Sigma).
6. Deploy and operate open-source SOC tools (Wazuh, MISP, Shuffle).

## Navigation

| Chapter | Description |
|---------|-------------|
| [01 - Introduction](01-introduction.md) | SOC Structure, Tiers (1/2/3), and Core Metrics (MTTD/MTTR) |
| [02 - Alert Triage & Investigation](02-alert-triage-and-investigation.md) | Workflow, Playbooks, True Positives vs. False Positives |
| [03 - SOC Automation & SOAR](03-soc-automation-and-soar.md) | SOAR workflows, Automated Enrichment, Python scripts |
| [04 - Threat Hunting](04-threat-hunting-methodology.md) | Hypothesis-driven hunting, Persistence mechanisms, KQL/Sigma |
| [05 - Tooling & Dashboards](05-soc-tooling-and-dashboards.md) | Wazuh, Shuffle SOAR, MISP, OpenSearch, Dashboarding |
| [06 - Hands-On Lab](06-hands-on-lab.md) | Python SOC Alert Enricher and Automated Triage Pipeline |
| [07 - References](07-references.md) | Frameworks, Documentations, and Reading Materials |
