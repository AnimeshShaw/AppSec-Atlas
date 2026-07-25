# 04 - SOC 2 Policy Templates

Policies form the foundation of your SOC 2 audit. Without written policies, auditors have nothing to measure your controls against.

Below are outlines of the critical policies required.

## 📝 1. Information Security Policy
The master document that dictates your organization's security posture.

**Core Sections:**
- **Purpose:** Protect confidentiality, integrity, and availability of customer data.
- **Scope:** All employees, contractors, and systems.
- **Data Classification:** Define Public, Internal, Confidential, and Restricted data.
- **Endpoint Security:** Requirements for MDM, disk encryption (FileVault/BitLocker), and antivirus.
- **Violations:** Disciplinary action for policy violation.

## 🔐 2. Access Control Policy (CC6.1, CC6.2)
Dictates how access to systems is granted, modified, and revoked.

**Core Sections:**
- **Principle of Least Privilege:** Users receive minimum access necessary.
- **Authentication:** Mandatory MFA for all internal systems (AWS, GitHub, Google Workspace).
- **Provisioning:** Manager approval required via ticketing system (Jira/Linear).
- **Deprovisioning:** Access revoked within 24 hours of termination.
- **Reviews:** User Access Reviews (UAR) conducted quarterly.

## 🚨 3. Incident Response Plan (CC7.2)
How your team reacts when things go wrong.

**Core Sections:**
- **Roles:** Incident Commander, Lead Responder, Communications Lead.
- **Severity Levels:** SEV0 (Critical down), SEV1, SEV2, SEV3.
- **Phases:** 
  1. Preparation
  2. Identification
  3. Containment
  4. Eradication
  5. Recovery
  6. Post-Mortem (Root Cause Analysis within 5 days).
- **Breach Notification:** SLA for notifying customers (e.g., 72 hours).

## 🤝 4. Vendor Management Policy (CC9.2)
Ensures third parties don't compromise your security.

**Core Sections:**
- **Risk Tiers:** Tier 1 (Critical, handles sensitive data), Tier 2, Tier 3.
- **Due Diligence:** Require SOC 2 Type 2 or ISO 27001 reports from Tier 1/2 vendors before procurement.
- **Annual Review:** Re-evaluate critical vendor compliance annually.

> [!TIP]
> Tools like Vanta or Drata come with highly customized, auditor-approved templates for all of these policies. Use them to save time.
