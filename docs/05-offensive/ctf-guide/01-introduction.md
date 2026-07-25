---
title: "01 - Introduction to CTFs 🚩"
description: "Capture The Flag (CTF) competitions are educational cybersecurity exercises where participants solve challenges to uncover hidden strings called 'flag..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Ctf Guide", "01 Introduction.Md"]
---

# 01 - Introduction to CTFs 🚩

Capture The Flag (CTF) competitions are educational cybersecurity exercises where participants solve challenges to uncover hidden strings called "flags" (e.g., `flag{h4ckth3pl4n3t}`). They are the training grounds for offensive security professionals.

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## ⚔️ CTF Formats

### 1. Jeopardy-Style
This is the most common format (e.g., PicoCTF, DEF CON Quals).
- **Structure:** A board of challenges divided by category and point value.
- **Scoring:** The harder the challenge, the more points it is worth. Many platforms use "Dynamic Scoring," where the point value decreases as more people solve it.
- **Goal:** Accumulate the most points before time runs out.

### 2. Attack-Defense (A/D)
A highly advanced, real-time format (e.g., DEF CON CTF Finals).
- **Structure:** Each team is given an identical vulnerable server (or "box").
- **Goal:** 
  - **Attack:** Exploit other teams' servers to steal their flags.
  - **Defense:** Patch your own vulnerable services to prevent others from stealing your flags, while keeping the service running (Service Level Agreement - SLA).
- **Scoring:** Points are gained by stealing flags and keeping your services up, and lost if your services go down or get compromised.

---

## 🧩 CTF Categories

### 🕸️ Web Exploitation
Focuses on finding and exploiting vulnerabilities in web applications.
- **Common Vulnerabilities:** SQL Injection (SQLi), Cross-Site Scripting (XSS), Server-Side Template Injection (SSTI), Local File Inclusion (LFI), Command Injection.
- **Goal:** Bypass authentication, leak database contents, or gain Remote Code Execution (RCE) on the web server.

### 🔐 Cryptography (Crypto)
Involves decrypting messages, breaking weak encryption schemes, or exploiting mathematical flaws in cryptographic algorithms.
- **Common Challenges:** RSA (weak keys, Wiener's attack), Padding Oracle attacks, Hash length extension attacks, XOR ciphers, classical ciphers (Caesar, Vigenère).
- **Goal:** Recover the plaintext flag from ciphertext or forge cryptographic signatures.

### 🔄 Reverse Engineering (Rev)
Taking apart compiled programs (binaries, APKs, Java `.class` files) to understand how they work without having the source code.
- **Techniques:** Disassembling (reading assembly code), Decompiling (translating assembly back to pseudo-C), Dynamic analysis (debugging).
- **Goal:** Find hardcoded passwords, bypass license checks, or understand a custom encryption algorithm.

### 💥 Binary Exploitation (Pwn)
Focuses on exploiting memory corruption vulnerabilities in compiled applications (usually C/C++).
- **Common Vulnerabilities:** Buffer Overflows, Format String bugs, Heap Use-After-Free (UAF).
- **Goal:** Manipulate the program's execution flow to spawn a shell (`/bin/sh`) or read a protected flag file.

### 🔎 Forensics
The art of investigating digital artifacts to uncover hidden information or reconstruct an attack.
- **Sub-categories:** 
  - **Memory Forensics:** Analyzing RAM dumps (Volatility).
  - **Network Forensics:** Analyzing packet captures (Wireshark/PCAP).
  - **Disk Forensics:** Recovering deleted files or analyzing file systems.
- **Goal:** Reconstruct what happened or extract a flag from the artifacts.

### 🖼️ Steganography (Stego)
Often grouped with Forensics, this is the practice of hiding secret data within ordinary, non-secret files or messages.
- **Common Challenges:** Hidden text in images (LSB steganography), hidden files inside audio, or trailing data in file formats.

### 🎲 Miscellaneous (Misc)
Anything that doesn't fit neatly into the above categories.
- **Examples:** Programming/scripting puzzles, OSINT (Open Source Intelligence), escape rooms, regex crosswords.
