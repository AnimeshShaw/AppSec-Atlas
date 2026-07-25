---
title: "03 - Web and Cloud Incident Playbooks"
description: "This section outlines specific step-by-step procedures for common web and cloud incidents."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Incident Response", "03 Web And Cloud Incident Playbooks.Md"]
---

# 03 - Web and Cloud Incident Playbooks

This section outlines specific step-by-step procedures for common web and cloud incidents.

## Playbook 1: Compromised AWS Access Key

**Scenario:** An AWS IAM Access Key was accidentally committed to a public GitHub repository.

### Detection
*   AWS GuardDuty alert: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
*   GitHub Secret Scanning alert.
*   Unexpected billing spikes.

### Containment & Eradication
1.  **Identify the Key:** Locate the exact `AccessKeyId`.
2.  **Deactivate the Key:** Do not delete it immediately. Deactivating prevents further use while allowing you to investigate what it was used for.
    ```bash
    aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name Alice
    ```
3.  **Determine Impact (CloudTrail):** Analyze AWS CloudTrail logs to see every API call made by that key since it was compromised.
    ```bash
    aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE
    ```
4.  **Revoke Temporary Sessions:** If the key was used to assume roles, revoke active sessions.
    ```bash
    aws iam put-role-policy --role-name CompromisedRole --policy-name RevokeSessions --policy-document file://revoke-policy.json
    ```
5.  **Revert Changes:** Based on the CloudTrail analysis, undo any malicious actions (e.g., terminate unauthorized EC2 instances, delete rogue IAM users, revert security group changes).
6.  **Delete Key & Rotate:** Once the investigation is complete, delete the compromised key and issue a new one to the user.

## Playbook 2: Web Application Compromise (Webshell)

**Scenario:** An attacker exploited an arbitrary file upload vulnerability and uploaded a PHP webshell to the web server.

### Detection
*   EDR alert for a web server process (e.g., `www-data` or `nginx`) spawning an interactive shell (`/bin/sh`, `cmd.exe`).
*   File Integrity Monitoring (FIM) detects a new `.php`, `.jsp`, or `.aspx` file in the webroot.
*   WAF alerts showing malicious commands in HTTP parameters.

### Containment & Eradication
1.  **Isolate the Server:** Isolate the affected web server at the network layer to prevent lateral movement, but keep it running for memory analysis.
2.  **Preserve Evidence:**
    *   Capture memory.
    *   Copy access logs (`/var/log/nginx/access.log`), error logs, and system logs.
    *   Copy the suspected webshell file (hash it immediately).
3.  **Analyze Logs:** Determine how the webshell was uploaded. Look for the first HTTP request that accessed the shell, then trace back to the upload request. Find the source IP and look for other activity from that IP.
4.  **Eradicate:**
    *   Delete the webshell.
    *   Identify and fix the vulnerability (e.g., implement strict file upload validation, patch the CMS).
    *   Check for persistence mechanisms (cron jobs, scheduled tasks, modified startup scripts).
5.  **Rebuild:** Best practice is to consider the server fundamentally compromised. Rebuild the server from a known good image, apply the fix, and redeploy.

## Playbook 3: Ransomware Containment

**Scenario:** Multiple endpoints are reporting encrypted files and displaying ransom notes.

### Detection
*   EDR alerts for mass file modifications or known ransomware signatures.
*   Users reporting inability to access files.
*   Creation of files like `DECRYPT_ME.txt`.

### Containment & Eradication
1.  **Immediate Isolation:** Speed is critical. Immediately isolate ALL suspected infected hosts from the network using EDR or network controls. Disconnect file shares to prevent network encryption.
2.  **Identify Patient Zero:** Review logs to find the first machine infected to determine the initial access vector (e.g., phishing email, RDP brute force, unpatched VPN vulnerability).
3.  **Halt Propagation:** Block identified IoCs (C2 domains, malicious IPs, hashes) on firewalls and EDR.
4.  **Do Not Reboot:** Rebooting can sometimes trigger data destruction or lose the encryption keys stored in memory.
5.  **Assess Backups:** Verify the integrity of offline/immutable backups. Ensure they have not been compromised.
6.  **Eradicate & Recover:** Wipe the infected machines completely. Reinstall the OS from golden images and restore data from verified clean backups. Do NOT pay the ransom unless human life is at risk and all other options are exhausted.
