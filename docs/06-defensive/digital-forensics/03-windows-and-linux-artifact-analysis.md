---
title: "03 - Windows and Linux Artifact Analysis"
description: "A hierarchical database that stores low-level settings."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Digital Forensics", "03 Windows And Linux Artifact Analysis.Md"]
---

# 03 - Windows and Linux Artifact Analysis

## Windows Artifacts

### Windows Registry
A hierarchical database that stores low-level settings.
- **NTUSER.DAT:** Found in user profiles. Tracks user-specific actions (e.g., typed URLs, recently opened files, mapped drives).
- **SYSTEM / SOFTWARE / SAM:** Track system configuration, installed software, and local user hashes.

### Event Logs
Stored in `%SystemRoot%\System32\Winevt\Logs\`.
- **Security.evtx:** Tracks logons (Event ID 4624), logoffs (4634), and privilege escalations.
- **System.evtx:** System service changes and startup errors.

### Execution Evidence
- **Prefetch:** Stores information about executed applications to speed up load times (shows path, run count, last run time). Located at `C:\Windows\Prefetch`.
- **Shimcache (AppCompatCache):** Tracks executables for compatibility purposes. Can prove execution even if the executable is deleted.
- **Amcache:** Similar to Shimcache, tracks executable paths, SHA1 hashes, and execution times.
- **LNK Files (Shortcuts):** Track when users access specific files.

## Linux Artifacts

### Log Files (`/var/log/`)
- `/var/log/syslog` (Debian) or `/var/log/messages` (RHEL): General system activity.
- `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL): Authentication logs. Look here for failed SSH brute force attempts or `sudo` escalations.

### Bash History
- `~/.bash_history`: Contains commands run by the user. Attackers often attempt to clear this (`history -c`, or unsetting `HISTFILE`), which in itself is an indicator of compromise.

### Example CLI Analysis

```bash
# Find failed SSH logins in auth.log
grep "Failed password" /var/log/auth.log | awk '{print $1, $2, $3, $9, $11}'

# Find unique IPs attempting brute force
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```
