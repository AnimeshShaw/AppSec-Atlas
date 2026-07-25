---
title: "07 - References & Resources"
description: "Comprehensive catalog of industry standards, OWASP MASVS 2.0 mapping, official Apple/Android security documentation, open-source tooling, and historical mobile vulnerability case studies."
keywords: ["OWASP MASVS", "MASTG", "Android Security", "Apple Platform Security", "Stagefright", "Pegasus", "XcodeGhost", "AppSec"]
---

# 07 - References & Resources

> [!NOTE]
> Use these foundational frameworks, platform security specifications, and tool repositories to implement enterprise-grade mobile application security controls.

---

## 1. Industry Standards & Verification Frameworks

*   **[OWASP Mobile Application Security Verification Standard (MASVS v2.0)](https://mas.owasp.org/MASVS/)**
    *   The primary industry framework establishing security requirements for mobile applications.
    *   **MASVS-STORAGE:** Secure data storage and key management.
    *   **MASVS-CRYPTO:** Strong cryptographic implementation.
    *   **MASVS-AUTH:** Authentication and session management boundaries.
    *   **MASVS-NETWORK:** Secure network communication and TLS controls.
    *   **MASVS-RESILIENCE:** Reverse engineering and anti-tampering defenses.
    *   **MASVS-CODE:** Code quality and build configuration security.
*   **[OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)**
    *   The technical testing manual containing Frida scripts, reverse engineering steps, and assessment test cases for iOS and Android.
*   **[NIST Special Publication 800-163 Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)**
    *   NIST Guidelines for Assessing the Security of Mobile Applications.

---

## 2. Official Platform Security Documentation

*   **[Android Developer Security Best Practices](https://developer.android.com/topic/security/best-practices)**
    *   Google's official guide to data safety, intent permissions, and Network Security Configuration.
*   **[Google Play Integrity API Documentation](https://developer.android.com/google/play/integrity)**
    *   Technical manual for requesting signed device and app integrity verdicts.
*   **[Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)**
    *   Deep architectural specification of iOS security, Mach-O code signing, Secure Enclave Processor (SEP), and Data Protection API.
*   **[Apple App Attest & DeviceCheck API](https://developer.apple.com/documentation/devicecheck)**
    *   Official guide for hardware attestation and server-side assertion verification.

---

## 3. Notable Historical Mobile Vulnerabilities & Case Studies

Understanding historical mobile exploit chains highlights why defense-in-depth is mandatory:

| Vulnerability / Incident | CVE ID | Vector & Impact | Technical Analysis |
| :--- | :--- | :--- | :--- |
| **Android Stagefright** | CVE-2015-3864 | Remote Code Execution via MMS video parsing | An integer overflow in Android's `libstagefright` media library allowed attackers to achieve RCE by sending a crafted MMS video message without user interaction. |
| **Pegasus FORCEDENTRY** | CVE-2021-30860 | Zero-Click RCE via iMessage JBIG2 stream | NSO Group exploited an integer overflow in Apple's CoreGraphics PDF parsing engine, constructing a Turing-complete virtual machine out of JBIG2 image decoder logic to escape the iOS sandbox. |
| **XcodeGhost** | N/A (Supply Chain) | Compiler SDK compromise | Attackers distributed modified versions of Apple's Xcode IDE on file-sharing sites. iOS apps compiled with infected Xcode binaries uploaded device metadata and executed remote command payloads. |
| **WhatsApp VoIP Overflow** | CVE-2019-3568 | Zero-Touch Remote Code Execution | A buffer overflow in the WhatsApp VoIP stack enabled attackers to inject spyware by sending specially crafted SRTCP packets to a target phone number. |

---

## 4. Primary Tool Repositories

*   **[MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** - Automated All-in-One Mobile Security Scanner.
*   **[Frida Dynamic Instrumentation Toolkit](https://frida.re/)** - Scriptable dynamic inspection and API hooking engine.
*   **[Objection Toolkit by SensePost](https://github.com/sensepost/objection)** - Runtime mobile exploration REPL interface powered by Frida.
*   **[JADX Decompiler](https://github.com/skylot/jadx)** - Command-line and GUI decompiler for Android DEX to Java source code.
*   **[APKTool](https://ibotpeaches.github.io/Apktool/)** - Reverse engineering tool for decoding 3rd-party, closed, binary Android apps.
*   **[Ghidra Software Reverse Engineering Framework](https://ghidra-sre.org/)** - NSA open-source reverse engineering framework for binary disassembly.
