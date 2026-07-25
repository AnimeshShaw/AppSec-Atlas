---
title: "03 - Network Security & SSL Pinning"
description: "Mobile apps communicate extensively with backend APIs. If an attacker controls the Wi-Fi network (or the device itself), they can perform Man-in-the-M..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Mobile Security", "03 Network Security And Ssl Pinning.Md"]
---

# 03 - Network Security & SSL Pinning

Mobile apps communicate extensively with backend APIs. If an attacker controls the Wi-Fi network (or the device itself), they can perform Man-in-the-Middle (MitM) attacks by installing a rogue root CA certificate on the device.

## Network Security Configuration

Both OS platforms provide declarative ways to enforce network security.

### Android: Network Security Config (`network_security_config.xml`)
Prevents the app from trusting user-installed CAs (which attackers use for MitM via tools like Burp Suite) and enforces HTTPS.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <!-- Trust only system CAs, NOT user-installed CAs -->
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

### iOS: App Transport Security (ATS)
Enforced in `Info.plist`, ATS requires strong TLS (1.2+) and blocks cleartext HTTP.

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/> <!-- Blocks all HTTP traffic -->
</dict>
```

## Certificate / Public Key Pinning

Pinning ensures the app only communicates with servers presenting a specific, predefined TLS certificate or public key. This prevents MitM attacks even if a root CA is compromised or a user installs a malicious CA.

### Android implementation with OkHttp
```kotlin
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

val certificatePinner = CertificatePinner.Builder()
    // Pin the Subject Public Key Info (SPKI) hash of the server's cert
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    // Always provide a backup pin!
    .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=") 
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

### iOS implementation with Alamofire
```swift
import Alamofire

let manager: Session = {
    let evaluators: [String: ServerTrustEvaluating] = [
        "api.example.com": PublicKeysTrustEvaluator(
            keys: [/* Array of SecKey extracted from bundle certs */],
            performDefaultValidation: true,
            validateHost: true
        )
    ]
    
    let serverTrustManager = ServerTrustManager(evaluators: evaluators)
    return Session(serverTrustManager: serverTrustManager)
}()
```
