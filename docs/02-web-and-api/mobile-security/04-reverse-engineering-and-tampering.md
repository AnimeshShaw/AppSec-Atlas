---
title: "04 - Reverse Engineering and Tampering"
description: "Attackers analyze mobile applications to steal intellectual property, bypass premium features, or discover backend API secrets."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Mobile Security", "04 Reverse Engineering And Tampering.Md"]
---

# 04 - Reverse Engineering and Tampering

Attackers analyze mobile applications to steal intellectual property, bypass premium features, or discover backend API secrets.

## Static Analysis (Decompilation)
Attackers can unpack the application binary and revert it to readable source code.

### Android Decompilation
1. **APKTool:** Decodes resources (Manifest, XML layouts) and disassembles classes to Smali bytecode.
   `apktool d app.apk -o output_dir`
2. **JADX:** Decompiles Dalvik bytecode directly back into readable Java source code.
   `jadx-gui app.apk`

### iOS Decompilation
1. iOS apps are encrypted by Apple's FairPlay DRM. An attacker must run the app on a jailbroken device and dump the decrypted memory.
2. Tools like **Ghidra**, **Hopper**, or **IDA Pro** are then used to disassemble the Mach-O binary.

## Dynamic Analysis (Instrumentation)
Attackers monitor and modify the app's behavior while it's running.

### Frida
Frida is a dynamic code instrumentation toolkit. It injects JavaScript into native apps on Android and iOS.
- **Use Case:** Hooking functions to bypass root detection, SSL pinning, or modifying return values (e.g., changing `isPremiumUser()` from `false` to `true`).

## Mitigations & Defenses

### 1. Code Obfuscation & Shrinking
Use R8/ProGuard (Android) to rename classes and methods to meaningless characters (`a.b.c`), making reverse engineering tedious.

### 2. Jailbreak and Root Detection
Check for known indicators of compromise.
- **Android:** Check for `su` binaries, known root manager apps (Magisk), or test tags. Use **Play Integrity API**.
- **iOS:** Check for Cydia/Sileo URLs, attempt to write outside the sandbox.

### 3. Runtime Application Self-Protection (RASP)
Advanced commercial solutions (like Promon, DexGuard, or iXGuard) that actively monitor the app during runtime, terminating it if a debugger is attached, if Frida is detected, or if the environment is compromised.
