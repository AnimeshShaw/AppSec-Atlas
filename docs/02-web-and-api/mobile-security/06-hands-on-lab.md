---
title: "06 - Hands-On Lab: Dynamic Instrumentation with Frida"
description: "In this lab, we will simulate a scenario where a vulnerable Android app has implemented flawed root detection and lacks SSL pinning. We will use Frida..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Mobile Security", "06 Hands On Lab.Md"]
---

# 06 - Hands-On Lab: Dynamic Instrumentation with Frida

In this lab, we will simulate a scenario where a vulnerable Android app has implemented flawed root detection and lacks SSL pinning. We will use Frida to bypass the root detection and intercept its traffic.

## The Vulnerable Code Target

The application has a class `SecurityUtils` with a method `isDeviceRooted()`. If it returns true, the app exits.

```java
package com.vuln.app;

public class SecurityUtils {
    public static boolean isDeviceRooted() {
        // Simple check for su binary
        return new java.io.File("/system/xbin/su").exists();
    }
}
```

## The Exploit: Frida Bypass Script

We will write a Frida JavaScript file (`bypass.js`) to hook into this method and force it to always return `false`.

```javascript
// bypass.js
Java.perform(function () {
    console.log("[*] Starting Root Bypass...");

    // Find the class
    var SecurityUtils = Java.use("com.vuln.app.SecurityUtils");

    // Hook the method
    SecurityUtils.isDeviceRooted.implementation = function () {
        console.log("[+] isDeviceRooted() called. Forcing return value to false.");
        return false; // Bypass the check
    };
});
```

## Execution

1. Ensure the app is installed and `frida-server` is running on the emulator.
2. Run the Frida script:
```bash
frida -U -f com.vuln.app -l bypass.js --no-pause
```
3. The app launches, the hook is applied, and the app continues running even on a rooted emulator.

## Remediation (The Secure Fix)

To prevent simple hooking and improve security:
1. **Obfuscation:** Run R8/ProGuard. The class `SecurityUtils` becomes `a.b.c`, and `isDeviceRooted` becomes `a()`, breaking the hardcoded Frida script.
2. **Server-Side Validation:** Use Android Play Integrity API. Instead of the client checking its own integrity, the device requests a signed cryptographic token from Google servers, which is sent to *your* backend server for verification.
3. **RASP Implementation:** Integrate a Runtime Application Self-Protection SDK that detects Frida/Ptrace attachment and terminates the app natively.
