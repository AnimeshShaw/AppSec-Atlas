---
title: "02. Firmware Analysis & Reverse Engineering"
description: "Firmware is the lifeblood of an IoT device—it contains the operating system, device drivers, web servers, and configuration files. Attackers analyze f..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Iot Security", "02 Firmware Analysis And Reverse Engineering.Md"]
---

# 02. Firmware Analysis & Reverse Engineering

Firmware is the lifeblood of an IoT device—it contains the operating system, device drivers, web servers, and configuration files. Attackers analyze firmware to find zero-day vulnerabilities, hidden backdoors, and hardcoded secrets.

## 📤 Extracting Firmware

Before analyzing firmware, you must obtain it. Common methods include:
1. **Network Interception:** Sniffing OTA updates (if unencrypted).
2. **Vendor Websites:** Downloading update binaries directly from the manufacturer's support page.
3. **Hardware Dumping:** Reading the flash memory chip directly via SPI using tools like a CH341A programmer or Bus Pirate.

## 🕵️‍♂️ Analyzing Firmware with Binwalk

Firmware images are often just concatenated files containing a bootloader, a kernel, and a compressed filesystem. `binwalk` is the industry-standard tool for searching binary images for embedded files and executable code.

### Step 1: Identifying File Signatures

Run `binwalk` to scan the binary for known file signatures, magic numbers, and compression formats.

```bash
# Scan the firmware image
$ binwalk router_firmware.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             U-Boot boot loader, image size: 131072 bytes
131072        0x20000         LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes
1048576       0x100000        Squashfs filesystem, little endian, version 4.0, size: 4521342 bytes
```

### Step 2: Extracting the Filesystem

You can use the `-e` (extract) flag in `binwalk`. For better results (handling recursive extraction and stripping headers), use `-Me`.

```bash
# Extract contents automatically
$ binwalk -Me router_firmware.bin
```

Binwalk will create a directory named `_router_firmware.bin.extracted` containing the unpacked filesystem (e.g., `squashfs-root`).

### Step 3: Manual Extraction with `dd`

Sometimes automatic extraction fails. If you know the exact offset (e.g., Squashfs starts at 1048576), you can extract it manually using `dd`.

```bash
# Extract from offset 1048576
$ dd if=router_firmware.bin bs=1 skip=1048576 of=filesystem.squashfs

# Unpack the squashfs file manually
$ unsquashfs filesystem.squashfs
```

## 📂 Common Embedded Filesystems
- **SquashFS:** A compressed, read-only filesystem for Linux. Highly popular in routers and IoT devices.
- **CramFS:** An older, simpler compressed Linux filesystem.
- **JFFS2 / UBIFS:** Read/write filesystems designed specifically for flash memory (handling wear-leveling).

## 🔑 Hunting for Hardcoded Secrets

Once you have an extracted filesystem, it looks like a standard Linux root tree (`/etc`, `/bin`, `/var`, `/www`). You should look for:

1. **Hardcoded Credentials:** Check `/etc/shadow`, `/etc/passwd`, and custom config files.
2. **Cryptographic Keys:** Private RSA keys, TLS certificates, and API tokens.
3. **Insecure Web Applications:** Look in `/www` or `/var/www` for PHP/CGI scripts prone to command injection.

### Useful CLI Commands for Secret Hunting

**1. Finding Sensitive Files by Name**
```bash
# Search for files related to keys, passwords, or certificates
$ find squashfs-root -type f -name "*.pem" -o -name "*.key" -o -name "*shadow*" -o -name "*.conf"
```

**2. Grepping for Keywords**
Search for common sensitive strings across all files.
```bash
# Search for API keys or hardcoded passwords
$ grep -rnE -i "password|passwd|api_key|secret|token|private key" squashfs-root/
```

**3. Analyzing Binaries**
Sometimes secrets are compiled inside binaries. Use `strings` to extract readable text.
```bash
# Extract strings from an embedded web server binary
$ strings squashfs-root/bin/httpd | grep -i "admin"
```

## 🛑 Real-World Impact
If an attacker finds a hardcoded private MQTT key or a default root password in the firmware, they can potentially compromise **every single device** running that firmware version, leading to massive botnets like Mirai.
