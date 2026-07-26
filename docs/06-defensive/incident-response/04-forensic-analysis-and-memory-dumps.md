---
title: 04 - Forensic Analysis and Memory Dumps
description: Forensic analysis involves examining digital media in a forensically
  sound manner to identify, preserve, recover, analyze, and present facts and opini...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '06'
- Defensive
- Incident
- Response
- '04'
- Forensic
- Analysis
- And
- Memory
- Dumps
- Md
slug: /defensive/incident-response/forensic-analysis-and-memory-dumps
---


# 04 - Forensic Analysis and Memory Dumps

Forensic analysis involves examining digital media in a forensically sound manner to identify, preserve, recover, analyze, and present facts and opinions about the digital information.

## 1. Memory Forensics with Volatility 3

Random Access Memory (RAM) contains a wealth of volatile information: running processes, active network connections, loaded DLLs, open files, and sometimes decrypted passwords or malware payloads.

### Capturing Memory
*   **Windows:** Use tools like DumpIt, WinPmem, or FTK Imager.
*   **Linux:** Use LiME (Linux Memory Extractor).

### Analyzing with Volatility 3
Volatility 3 is the standard open-source memory forensics framework.

**Basic Commands:**

1.  **Identify OS/Profile (Info):**
    ```bash
    python3 vol.py -f memdump.raw windows.info
    ```
2.  **List Processes (pslist & psscan):**
    `pslist` reads the process list structure. `psscan` scans memory for EPROCESS blocks (finds hidden/terminated processes).
    ```bash
    python3 vol.py -f memdump.raw windows.pslist
    python3 vol.py -f memdump.raw windows.psscan
    ```
3.  **View Process Tree (pstree):** Identifies parent-child relationships. Look for anomalies (e.g., `cmd.exe` spawned by `notepad.exe`).
    ```bash
    python3 vol.py -f memdump.raw windows.pstree
    ```
4.  **Network Connections (netscan):** Finds active and closed network connections.
    ```bash
    python3 vol.py -f memdump.raw windows.netscan
    ```
5.  **Find Injected Code (malfind):** Scans for hidden or injected code in user-mode memory (e.g., Hollowed processes).
    ```bash
    python3 vol.py -f memdump.raw windows.malfind
    ```

## 2. Disk Imaging and Triage Collection

Full disk imaging is slow. Modern IR relies on "Triage Collection" - grabbing the most important forensic artifacts quickly.

### Triage Collection with KAPE (Kroll Artifact Parser and Extractor)
KAPE is a highly efficient tool for collecting and parsing Windows forensic artifacts.

**Common Targets:**
*   **MFT (Master File Table):** Record of all files on an NTFS volume.
*   **Event Logs (.evtx):** Windows system, security, and application logs.
*   **Registry Hives:** System configuration and user activity (SAM, SYSTEM, SOFTWARE, NTUSER.DAT).
*   **Prefetch (.pf):** Evidence of program execution.
*   **Amcache/Shimcache:** Evidence of program execution and compatibility settings.

**Example KAPE Command (Collect Basic Artifacts to a VHDX):**
```cmd
kape.exe --tsource C: --target BasicCollection --tdest D:\Kape_Out --tvhdx Triage.vhdx
```

### Remote Triage with Velociraptor
Velociraptor is an advanced endpoint visibility tool. It allows you to query endpoints using VQL (Velociraptor Query Language) to hunt for IoCs across thousands of machines simultaneously and collect triage artifacts remotely.

## 3. Log Analysis

Logs provide the historical context of the attack.
*   **Web Server Logs (Apache/Nginx):** Look for SQLi payloads, Directory Traversal (`../`), excessive 404s (scanning), or unusual user-agents.
*   **Windows Event Logs:**
    *   `4624` (Successful Logon), `4625` (Failed Logon)
    *   `4688` (Process Creation) - Crucial for tracking execution (requires command-line logging enabled).
    *   `7045` (Service Installed) - Often used for persistence.
*   **Cloud Logs (AWS CloudTrail, Azure Activity Logs):** Track API calls, resource creation, and identity modifications.
