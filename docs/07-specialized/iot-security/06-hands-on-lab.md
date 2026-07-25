---
title: "06. Hands-On Lab: Firmware Analyzer & Hardcoded Secret Detector"
description: "In this lab, we will build a Python tool that simulates the process of extracting an IoT firmware image and statically analyzing it for hardcoded secr..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Iot Security", "06 Hands On Lab.Md"]
---

# 06. Hands-On Lab: Firmware Analyzer & Hardcoded Secret Detector

In this lab, we will build a Python tool that simulates the process of extracting an IoT firmware image and statically analyzing it for hardcoded secrets, a common flaw in insecure IoT devices. 

## 🛠️ The Scenario
You are a security researcher analyzing a dumped firmware image (`simulated_firmware.bin`). You suspect the developer left hardcoded AWS keys and a default root password inside. 

## 📝 The Code: `iot_firmware_analyzer.py`

This script simulates `binwalk`'s extraction and then performs a static analysis scan across the extracted filesystem.

```python
#!/usr/bin/env python3
import os
import re
import tarfile
import tempfile
import shutil

# --- Lab Setup: Generate a Simulated Firmware Image ---
def create_simulated_firmware(filename):
    """Creates a tar file pretending to be a firmware image with hidden secrets."""
    temp_dir = tempfile.mkdtemp()
    
    # Create an innocent config file
    with open(os.path.join(temp_dir, "network.conf"), "w") as f:
        f.write("SSID=HomeNetwork\nIP_METHOD=DHCP\n")
        
    # Create a vulnerable config file with hardcoded secrets
    with open(os.path.join(temp_dir, "aws_credentials.json"), "w") as f:
        f.write('{"aws_access_key": "AKIAIOSFODNN7EXAMPLE", "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}\n')
        
    # Create a vulnerable shadow file
    os.makedirs(os.path.join(temp_dir, "etc"), exist_ok=True)
    with open(os.path.join(temp_dir, "etc", "shadow"), "w") as f:
        f.write("root:`$6`$`vulnerablehash$`qQ1...:18000:0:99999:7:::\n")
        f.write("admin:Password123:18000:0:99999:7:::\n") # Hardcoded plaintext password!

    # Package it into a "firmware.bin"
    with tarfile.open(filename, "w:gz") as tar:
        tar.add(temp_dir, arcname="squashfs-root")
        
    shutil.rmtree(temp_dir)
    print(f"[+] Simulated firmware created at {filename}")


# --- Vulnerability Scanner ---
def scan_extracted_filesystem(directory):
    """Scans a directory for common hardcoded IoT secrets."""
    print(f"\n[*] Scanning extracted filesystem at {directory}...")
    
    # Regex patterns for common secrets
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Generic Password": r"(?i)(password|passwd)\s*[:=]\s*['\"]?(?!.*?['\"]?\s*$).+",
        "Shadow File Entry": r"^[a-zA-Z0-9_]+:\$.+?:", 
        "Plaintext Shadow Entry": r"^[a-zA-Z0-9_]+:[^\$].+?:" 
    }

    found_vulnerabilities = False

    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    for vuln_name, pattern in patterns.items():
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            found_vulnerabilities = True
                            print(f"[!] VULNERABILITY FOUND: {vuln_name}")
                            print(f"    File: {filepath}")
                            print(f"    Match: {match.group(0).strip()[:50]}...")
            except Exception as e:
                # Skip binary files that can't be decoded as utf-8
                pass
                
    if not found_vulnerabilities:
        print("[+] No hardcoded secrets found. Firmware looks clean.")


# --- Main Execution ---
if __name__ == "__main__":
    FIRMWARE_FILE = "simulated_router_fw.bin"
    EXTRACT_DIR = "extracted_fw_lab"

    # 1. Setup the vulnerable lab environment
    create_simulated_firmware(FIRMWARE_FILE)

    # 2. Extract the firmware (Simulating `binwalk -Me`)
    print(f"\n[*] Extracting {FIRMWARE_FILE}...")
    if os.path.exists(EXTRACT_DIR):
        shutil.rmtree(EXTRACT_DIR)
        
    with tarfile.open(FIRMWARE_FILE, "r:gz") as tar:
        tar.extractall(path=EXTRACT_DIR)
    print(f"[+] Extraction complete to {EXTRACT_DIR}")

    # 3. Analyze the extracted filesystem
    scan_extracted_filesystem(EXTRACT_DIR)
```

## 🚀 Running the Lab

1. Save the script as `iot_firmware_analyzer.py`.
2. Run it using Python 3:
   ```bash
   python3 iot_firmware_analyzer.py
   ```
3. Observe the output. The script successfully extracts the faux firmware and identifies the hardcoded AWS keys and the weak plaintext password stored in the `shadow` file equivalent.

## 🛡️ The Hardened Fix

To secure this firmware, the developer should:
1. **Remove AWS Keys:** Use IAM Roles and device certificates (e.g., AWS IoT Core x.509 certs) provisioned uniquely at manufacturing.
2. **Remove Default Passwords:** Remove the `admin:Password123` entry. Require the user to set a strong password upon first device initialization (e.g., via a local Bluetooth setup phase).
3. **Encrypt the Firmware:** The OTA package itself should be encrypted so an attacker cannot trivially extract the filesystem using `binwalk` or `tar`.
