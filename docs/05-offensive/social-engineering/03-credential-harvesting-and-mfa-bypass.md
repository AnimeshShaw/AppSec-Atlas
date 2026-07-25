---
title: "03 - Credential Harvesting and MFA Bypass"
description: "While Multi-Factor Authentication (MFA) was once considered the silver bullet against credential theft, modern attackers have developed sophisticated ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Social Engineering", "03 Credential Harvesting And Mfa Bypass.Md"]
---

# 03 - Credential Harvesting and MFA Bypass

While Multi-Factor Authentication (MFA) was once considered the silver bullet against credential theft, modern attackers have developed sophisticated methods to bypass legacy MFA solutions (SMS, Voice, TOTP apps).

## Adversary-in-the-Middle (AiTM) Phishing

AiTM phishing is the current gold standard for credential harvesting and MFA bypass. Instead of presenting a fake login page, the attacker sets up a reverse proxy server between the victim and the legitimate service.

### AiTM Architecture and Mechanics

1.  **The Proxy Setup:** Attackers use tools like **Evilginx2** or **Modlishka**. The tool acts as a transparent proxy.
2.  **The Lure:** The victim clicks a phishing link and is directed to the attacker's proxy server (e.g., `login.microsoftonline-secure.com`).
3.  **The Relay:** The proxy forwards the victim's HTTP requests to the real login page (e.g., `login.microsoftonline.com`) and relays the responses back to the victim.
4.  **Credential Capture:** The victim enters their username and password. The proxy intercepts these in transit.
5.  **MFA Challenge:** The real service prompts for MFA (e.g., an SMS code or Authenticator app prompt). The proxy relays this prompt to the victim.
6.  **Token Interception:** The victim enters the MFA code or approves the prompt. The real service validates the MFA and issues a **Session Cookie**.
7.  **Session Hijacking:** The proxy intercepts the valid session cookie, logs it for the attacker, and then redirects the victim to a legitimate page (like their inbox) so they remain unaware.

The attacker now has a valid session cookie and can access the account without needing the password or interacting with MFA again.

### Interception Risks of Legacy MFA

*   **SMS/Voice OTP:** Susceptible to SIM swapping (porting a victim's number to an attacker-controlled SIM), SS7 protocol vulnerabilities, and AiTM proxies.
*   **TOTP (Authenticator Apps):** While immune to SIM swapping, the 6-digit codes can still be intercepted and relayed by AiTM proxies in real-time.
*   **Push Notifications:** Vulnerable to "MFA Fatigue" or "Prompt Bombing," where attackers repeatedly trigger push notifications until the frustrated user accidentally approves one. They are also vulnerable to AiTM.

## FIDO2 and WebAuthn: Defense Against AiTM

The only robust defense against AiTM phishing is **phishing-resistant MFA**, specifically FIDO2 (Fast Identity Online) and WebAuthn (Web Authentication API).

### How FIDO2/Passkeys Prevent AiTM

FIDO2 relies on public key cryptography and binds the authentication process to the **origin** (the specific domain name) and the **authenticator device** (e.g., YubiKey, Apple FaceID, Windows Hello).

1.  **Domain Binding:** When a user registers a Passkey/Security Key on `github.com`, the cryptographic key pair is intrinsically linked to `github.com`.
2.  **The AiTM Scenario:** If a user visits an AiTM proxy at `github-secure-login.com`, the WebAuthn API will attempt to authenticate using credentials bound to `github-secure-login.com`.
3.  **The Block:** The authenticator will not find a credential for the fake domain. It will refuse to release the authentication assertion. The proxy cannot trick the authenticator into providing a signature for the real domain because the browser enforces the origin check.

**Defense Architecture:**
*   **Deploy Hardware Security Keys (YubiKeys) or Platform Authenticators (Passkeys/Windows Hello).**
*   **Disable Legacy MFA:** Phase out SMS, Voice, and eventually TOTP.
*   **Conditional Access Policies:** Require phishing-resistant MFA for accessing sensitive applications or when logging in from unmanaged devices.
