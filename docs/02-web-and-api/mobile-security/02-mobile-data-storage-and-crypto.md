# 02 - Mobile Data Storage and Cryptography

One of the most common vulnerabilities is storing sensitive data (tokens, PII, passwords) unencrypted in locations accessible to other apps or physical extraction (e.g., rooted/jailbroken devices).

## Attack Vectors
- **Insecure Storage:** `SharedPreferences` (Android), `NSUserDefaults` (iOS), SQLite databases.
- **Log Leaks:** Logging sensitive data which can be read via `logcat` or device consoles.
- **Insecure Cryptography:** Hardcoded symmetric keys in the binary.

## Secure Storage on Android

**Vulnerable Code:**
```kotlin
// INSECURE: Data saved in plaintext XML file
val sharedPref = context.getSharedPreferences("MyAppPrefs", Context.MODE_PRIVATE)
with (sharedPref.edit()) {
    putString("auth_token", "super_secret_token")
    apply()
}
```

**Secure Code (EncryptedSharedPreferences):**
Uses Android Keystore to securely generate and store encryption keys backed by hardware (TEE/StrongBox).
```kotlin
// SECURE: Encrypted SharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "secret_shared_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

sharedPreferences.edit().putString("auth_token", "super_secret_token").apply()
```

## Secure Storage on iOS

**Vulnerable Code:**
```swift
// INSECURE: Data saved in plaintext plist
UserDefaults.standard.set("super_secret_token", forKey: "auth_token")
```

**Secure Code (Keychain API):**
Uses the iOS Keychain, protected by the Secure Enclave processor.
```swift
// SECURE: Writing to iOS Keychain
import Security

let token = "super_secret_token".data(using: .utf8)!
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: token,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly // Strict access control
]

SecItemDelete(query as CFDictionary) // Delete existing
let status = SecItemAdd(query as CFDictionary, nil)
if status != errSecSuccess {
    print("Keychain save failed: \(status)")
}
```

## Preventing Log Leaks
Never use standard `Log.d` (Android) or `print()` (iOS) for sensitive data in production.

**Android ProGuard/R8 Rule to strip logs:**
```proguard
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
}
```
