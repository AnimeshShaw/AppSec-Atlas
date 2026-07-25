# 02 - Incident Triage and Containment

When an alert fires or an incident is reported, the immediate goals are to determine its validity, scope the impact, and stop the adversary from moving laterally or exfiltrating data.

## 1. Initial Triage

Triage is the process of sorting and prioritizing incidents.
*   **Acknowledge and Assign:** Ensure an analyst claims the alert.
*   **Validate:** Is this a false positive? Cross-reference IoCs (IPs, hashes, domains) with threat intelligence platforms (e.g., VirusTotal, MISP).
*   **Scope:** What user accounts are involved? Which hosts? What data resides on those hosts?
*   **Severity Assessment:** Assign a severity level (e.g., Low, Medium, High, Critical) based on potential business impact.

### Triage Checklist
- [ ] Source IP/User identified.
- [ ] Timeline of events established.
- [ ] Initial attack vector hypothesized.
- [ ] Impact assessed (Data loss? System downtime?).

## 2. Isolating Compromised Hosts and Networks

Once a host is confirmed compromised, it must be contained immediately to prevent lateral movement.

### Network Isolation Strategies
*   **EDR Isolation:** Use tools like CrowdStrike, SentinelOne, or Microsoft Defender for Endpoint to logically isolate the host from the network while maintaining communication with the EDR console for investigation.
*   **VLAN/Subnet Quarantine:** Move the affected host to a restricted VLAN with no outbound internet access and limited internal access.
*   **Cloud Security Groups:** In AWS/Azure, apply a restrictive Security Group (e.g., Deny All Inbound/Outbound) to the affected EC2/VM instance.

**Important Rule:** Do NOT turn off the machine or disconnect the power unless absolutely necessary (e.g., active destructive malware). Powering down destroys volatile memory (RAM) which contains critical forensic evidence like decrypted payloads, active network connections, and running processes.

## 3. Credential Revocation

If user credentials or service accounts are compromised or suspected to be compromised:
1.  **Force Password Resets:** Immediately reset the passwords for the affected accounts.
2.  **Revoke Active Sessions:** Invalidate active session tokens in SSO providers (Okta, Azure AD), web applications, and VPNs.
3.  **Rotate Keys:** Rotate compromised API keys, SSH keys, or cloud access keys.
4.  **Monitor:** Closely monitor the affected accounts for subsequent login attempts.

## 4. Forensic Evidence Preservation

Before making changes to the system for eradication, preserve evidence. This is crucial for root cause analysis and potential legal proceedings.

### Chain of Custody
Maintain a formal log of who collected the evidence, how it was collected, where it was stored, and who has accessed it.

### Order of Volatility (RFC 3227)
Always collect evidence from the most volatile to the least volatile:
1.  Registers, cache
2.  Routing table, ARP cache, process table, kernel statistics, memory (RAM)
3.  Temporary file systems
4.  Disk
5.  Remote logging and monitoring data that is relevant to the system in question
6.  Physical configuration, network topology
7.  Archival media

**Initial Evidence Collection Steps:**
1.  **Memory Dump:** Capture a full RAM dump (using tools like WinPmem or LiME).
2.  **Triage Collection:** Use tools like KAPE or Velociraptor to collect high-value artifacts (Event Logs, Registry Hives, MFT, Prefetch, browser history) without doing a full disk image.
3.  **Disk Image:** If required, perform a bit-for-bit image of the hard drive (using DD or FTK Imager).
