---
title: "05 - Mobile Security Tools"
description: "A robust mobile security testing toolkit involves automated scanners and dynamic instrumentation frameworks."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Mobile Security", "05 Mobile Security Tools.Md"]
---

# 05 - Mobile Security Tools

A robust mobile security testing toolkit involves automated scanners and dynamic instrumentation frameworks.

## Mobile Security Framework (MobSF)
MobSF is an automated, all-in-one mobile application (Android/iOS) pen-testing, malware analysis, and security assessment framework.

**Setup & Usage via Docker:**
```bash
# Pull and run MobSF
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```
- Navigate to `http://localhost:8000`.
- Upload an APK or IPA.
- MobSF performs static analysis, highlighting hardcoded secrets, manifest misconfigurations, and vulnerable SDKs.

## Frida
Frida allows injecting snippets of JavaScript into native apps.

**Setup:**
```bash
pip install frida-tools
```
You also need `frida-server` running on a rooted/jailbroken device (or emulator).

**Common CLI Commands:**
```bash
# List processes on the connected USB device
frida-ps -U

# Trace a specific cryptographic API in an app
frida-trace -U -f com.example.app -i "javax.crypto.Cipher.init"
```

## Objection
Objection is a runtime mobile exploration toolkit powered by Frida. It significantly simplifies common dynamic analysis tasks without needing to write custom Frida scripts.

**Setup:**
```bash
pip install objection
```

**Common Workflow:**
```bash
# Launch the app and attach Objection
objection -g com.example.app explore

# Once inside the objection REPL:
# Bypass SSL Pinning
android sslpinning disable

# Bypass basic root detection
android root disable

# Monitor Keystore usage
android keystore watch
```
