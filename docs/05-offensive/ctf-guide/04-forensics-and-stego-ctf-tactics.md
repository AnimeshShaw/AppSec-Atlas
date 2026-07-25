---
title: "04 - Forensics & Steganography Tactics 🔎🖼️"
description: "Forensics and Steganography focus on extracting hidden, deleted, or obfuscated information from files, network captures, and memory dumps."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Ctf Guide", "04 Forensics And Stego Ctf Tactics.Md"]
---

# 04 - Forensics & Steganography Tactics 🔎🖼️

Forensics and Steganography focus on extracting hidden, deleted, or obfuscated information from files, network captures, and memory dumps.

---

## 🔎 Forensics Tactics

### 1. Network Forensics (PCAP Analysis)
Often, you are given a `.pcap` or `.pcapng` file containing captured network traffic.

**Wireshark Workflow:**
- **Protocol Hierarchy:** Go to `Statistics -> Protocol Hierarchy` to see what kind of traffic exists (HTTP, FTP, DNS).
- **Export Objects:** Go to `File -> Export Objects -> HTTP` to extract downloaded files.
- **Follow TCP Stream:** Right-click a packet -> `Follow -> TCP Stream` to see the conversation in plain text.

**Tshark CLI Tactics:**
Tshark is the command-line version of Wireshark. It is excellent for filtering and extracting specific fields.
```bash
# Extract HTTP hostnames from a pcap
tshark -r capture.pcap -Y "http.request" -T fields -e http.host

# Extract all DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name
```

### 2. Memory Forensics (Volatility)
Memory forensics involves analyzing a RAM dump (usually `.raw` or `.mem`). The standard tool is Volatility (v2 or v3).

**Volatility 3 Workflow:**
```bash
# Get basic OS information
vol -f memory.vmem windows.info

# List running processes
vol -f memory.vmem windows.pslist

# Dump a suspicious process's memory (e.g., PID 1234)
vol -f memory.vmem windows.memmap --dump --pid 1234

# Extract clipboard contents (often contains flags!)
vol -f memory.vmem windows.clipboard
```

---

## 🖼️ Steganography (Stego) Tactics

Steganography hides data in plain sight. In CTFs, this usually means a flag hidden inside an image or audio file.

### 1. Basic File Analysis
Before using advanced stego tools, always perform basic checks.

```bash
# Check file metadata (ExifTool)
exiftool image.jpg

# Search for readable text inside the file (Strings)
strings image.png | grep "flag"

# Extract embedded files or trailing data (Binwalk)
binwalk -e image.png
```

### 2. Image Steganography Tools

- **Zsteg (For PNG/BMP):** Detects LSB (Least Significant Bit) steganography and other hidden data.
  ```bash
  zsteg image.png
  ```
- **Steghide (For JPEG/WAV):** Hides data using a password. If the challenge gives you a passphrase, this is likely the tool.
  ```bash
  steghide extract -sf hidden.jpg -p "password123"
  ```
- **Stegsolve:** A GUI Java tool that lets you flip through color planes and bit planes to reveal hidden QR codes or text.

### 3. Audio Steganography
- **Sonic Visualiser:** Open the `.wav` file and add a "Spectrogram" pane. Flags are often "drawn" in the audio frequencies.
- **DeepSound / SilentEye:** Tools that hide files inside audio tracks.
