# 01 - Introduction

## Software Supply Chain Threat Landscape
The software supply chain encompasses everything that touches your software before it reaches production: source code, dependencies, build tools, CI/CD pipelines, and hosting infrastructure. Attackers increasingly target the supply chain because compromising one widely used component can breach thousands of downstream organizations (e.g., SolarWinds, Log4j).

**Common Attack Vectors:**
1. **Dependency Confusion / Typosquatting:** Tricking developers into downloading malicious packages.
2. **Compromised Build Systems:** Attackers breach CI/CD servers to inject malicious code during the build.
3. **Malicious Maintainers:** An attacker gains control of a popular open-source project and adds malicious code.
4. **Vulnerable Dependencies:** Using outdated libraries with known vulnerabilities (CVEs).

## Software Bill of Materials (SBOM)
An SBOM is a formal, machine-readable inventory of software components and dependencies, information about those components, and their hierarchical relationships.

**Why is it important?**
- **Visibility:** You can't secure what you don't know you have.
- **Vulnerability Management:** Quickly determine if you are affected by a newly announced zero-day vulnerability (like Log4Shell).
- **Compliance:** Mandated by US Executive Order 14028 for vendors supplying software to the federal government.

**Standard Formats:**
- **CycloneDX:** A lightweight SBOM standard designed for use in application security contexts and supply chain component analysis.
- **SPDX:** (Software Package Data Exchange) An open standard for communicating SBOM information, including provenance, license, security, and other related information.

## SLSA Framework
Supply-chain Levels for Software Artifacts (SLSA) is a security framework, a checklist of standards, and controls to prevent tampering, improve integrity, and secure packages and infrastructure.

**SLSA Levels (v1.0):**
- **Build L1:** The build process is fully scripted/automated and generates provenance.
- **Build L2:** Requires a hosted build platform that generates and signs the provenance itself.
- **Build L3:** The build platform implements strong controls to prevent influence between builds and protects the provenance from tampering.

SLSA helps consumers verify the integrity of the software artifacts they consume.
