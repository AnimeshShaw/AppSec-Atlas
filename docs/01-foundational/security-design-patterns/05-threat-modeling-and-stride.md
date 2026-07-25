---
title: "05 - Threat Modeling and STRIDE"
description: "Threat modeling is a systematic process for identifying and mitigating potential security threats in an application's architecture before writing code..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Security Design Patterns", "05 Threat Modeling And Stride.Md"]
---

# 05 - Threat Modeling and STRIDE

Threat modeling is a systematic process for identifying and mitigating potential security threats in an application's architecture before writing code.

## 1. The STRIDE Framework
STRIDE is a mnemonic developed by Microsoft to help identify common threats:

- **S**poofing (Authenticity): Can someone pretend to be someone else?
- **T**ampering (Integrity): Can someone alter data in transit or at rest?
- **R**epudiation (Non-repudiability): Can someone deny performing an action?
- **I**nformation Disclosure (Confidentiality): Can someone access data they shouldn't?
- **D**enial of Service (Availability): Can someone crash or overload the system?
- **E**levation of Privilege (Authorization): Can an unprivileged user gain admin rights?

## 2. PASTA Methodology
Process for Attack Simulation and Threat Analysis (PASTA) is a risk-centric threat modeling framework consisting of seven stages, focusing on business impact and probability.

## 3. Data Flow Diagrams (DFDs)
DFDs are essential for threat modeling. They map out how data moves through a system, identifying trust boundaries, processes, data stores, and external entities. Identifying threats at the intersections of trust boundaries is a primary goal.

## 4. Threat Modeling Tools
- **OWASP Threat Dragon:** An open-source, web-based tool providing system diagramming and a rule engine to auto-generate threats/mitigations.
- **Microsoft Threat Modeling Tool:** A robust desktop application utilizing the STRIDE framework specifically tailored for Azure and standard software architectures.
