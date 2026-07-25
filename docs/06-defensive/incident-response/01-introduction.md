# 01 - Introduction to Incident Response

## The Incident Response Lifecycle

Effective incident response requires a structured approach. The most widely adopted framework is defined in **NIST Special Publication 800-61 Revision 2**, which outlines a four-phase lifecycle:

```ascii
+-------------+      +-----------------------+
|             |      |                       |
| Preparation |----->| Detection & Analysis  |
|             |      |                       |
+-------------+      +-----------------------+
      ^                         |
      |                         v
+-------------+      +-----------------------+
|             |      |                       |
| Post-Incident|<----| Containment,          |
| Activity    |      | Eradication & Recovery|
+-------------+      +-----------------------+
```

### 1. Preparation
Preparation is the most critical phase. You cannot respond effectively if you aren't prepared.
- **Policies and Procedures:** Establishing an IR plan, communication guidelines, and escalation paths.
- **Tools and Resources:** Ensuring access to endpoint detection and response (EDR) tools, forensic workstations, and jump bags.
- **Training and Exercises:** Conducting tabletop exercises and red team simulations.
- **Baseline Hardening:** Implementing secure configurations and robust logging to ensure evidence is available when needed.

### 2. Detection & Analysis
Identifying that an incident has occurred and understanding its scope.
- **Alerts and Indicators:** Monitoring SIEMs, IDS/IPS, and user reports for Indicators of Compromise (IoCs).
- **Triage:** Prioritizing alerts based on potential impact and confidence.
- **Analysis:** Correlating logs, analyzing network traffic, and investigating endpoint behavior to determine the root cause, timeline, and affected systems.
- **Documentation:** Maintaining a detailed timeline and recording all findings securely.

### 3. Containment, Eradication, and Recovery
Stopping the bleeding, removing the threat, and restoring services.
- **Containment:** Preventing the spread. This may involve network isolation, disabling accounts, or blackholing IPs. *Never power off a machine before collecting memory/evidence if possible.*
- **Eradication:** Removing malware, deleting backdoors, and closing the initial attack vector (e.g., patching a vulnerability).
- **Recovery:** Restoring systems from clean backups, resetting credentials, and monitoring for reinfection.

### 4. Post-Incident Activity (Lessons Learned)
Improving security posture based on the incident.
- **Post-Mortem Reports:** Documenting what happened, how it was handled, and what went wrong.
- **Root Cause Analysis (RCA):** Identifying the fundamental failure that allowed the incident to occur.
- **Process Improvement:** Updating the IR plan, adding new detection rules, and improving preventative controls.

## Threat Landscape Context
Modern incidents move rapidly. Attackers leverage automation, zero-day exploits, and supply chain vulnerabilities. The "dwell time" (time between initial breach and detection) is a critical metric; reducing it is the primary goal of the Detection & Analysis phase.
