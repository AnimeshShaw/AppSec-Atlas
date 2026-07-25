# 01 - Introduction to Mobile Security

## The Mobile Threat Landscape

Mobile applications exist in an inherently hostile environment: the user's device. Unlike web applications where the backend infrastructure is protected by corporate firewalls, mobile applications are shipped as compiled binaries directly to potentially compromised or malicious devices. 

Attackers can:
- Decompile and analyze the application code.
- Intercept network traffic.
- Tamper with the runtime memory.
- Modify the local file system.

## OWASP Mobile Top 10 (2024)

The OWASP Mobile Top 10 highlights the most critical security risks for mobile apps:

1. **Improper Credential Usage:** Hardcoded credentials, insecure token storage.
2. **Inadequate Supply Chain Security:** Vulnerable third-party libraries, compromised SDKs.
3. **Insecure Authentication/Authorization:** Bypassing local auth, session mismanagement.
4. **Insufficient Input/Output Validation:** SQLi, XSS (in WebViews), path traversal.
5. **Insecure Communication:** Lack of certificate pinning, sensitive data over HTTP.
6. **Inadequate Privacy Controls:** Leaking PII, excessive permissions.
7. **Insufficient Binary Protection:** Lack of obfuscation, vulnerable to reverse engineering.
8. **Security Misconfiguration:** Debug flags enabled, insecure intent filters.
9. **Insecure Data Storage:** Storing sensitive data in plain text (SharedPrefs/NSUserDefaults).
10. **Insufficient Cryptography:** Weak algorithms, hardcoded keys.

## Mobile Architecture Basics

### Android Architecture
Android uses a sandbox model based on Security-Enhanced Linux (SELinux). Each application runs in its own Dalvik/ART virtual machine with a unique UID. 
- **APK (Android Package):** A ZIP archive containing `.dex` (Dalvik Executable) files, resources, and the `AndroidManifest.xml`.
- **Inter-Process Communication (IPC):** Apps communicate via Intents. Insecurely exported components (Activities, Services, Broadcast Receivers, Content Providers) are a major attack vector.

### iOS Architecture
iOS is built on a highly restrictive XNU kernel. All third-party apps run in a strict sandbox ("container").
- **IPA (iOS App Store Package):** An archive containing the compiled Mach-O binary, resources, and the `Info.plist`.
- **Code Signing:** iOS strictly enforces code signing; only Apple-approved code can run on non-jailbroken devices.
- **IPC:** Handled via URL Schemes, Universal Links, and App Extensions, which must be carefully validated to prevent malicious input.

## Root Causes of Mobile Vulnerabilities
1. **Trusting the Client:** Assuming the app cannot be tampered with.
2. **Lack of Defense-in-Depth:** Relying solely on OS-level sandboxing.
3. **Developer Misunderstanding:** Misusing complex platform-specific security APIs.
