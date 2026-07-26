---
title: 07 - References, Standards, & CVE Case Studies
description: Authoritative references, RFC specifications, NIST SP 800-63B guidelines,
  OWASP standards, CVE case studies, and tool documentation for Authentication and
  Authorization.
keywords:
- AppSec
- References
- RFC
- '6749'
- RFC
- '7519'
- RFC
- '7636'
- NIST
- SP
- 800-63B
- OWASP
- ASVS
- CVE
- Case
- Studies
- Keycloak
- Docs
- OPA
- Docs
slug: /foundational/auth-and-authz/references
---


# 07 - References, Standards, & CVE Case Studies

This index contains authoritative technical specifications, NIST guidelines, OWASP verification standards, real-world CVE case studies, and tooling documentation for deep technical reference.

---

## 1. Official Standards & RFC Specifications

- **RFC 6749 - The OAuth 2.0 Authorization Framework:** [https://datatracker.ietf.org/doc/html/rfc6749](https://datatracker.ietf.org/doc/html/rfc6749)
- **RFC 6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage:** [https://datatracker.ietf.org/doc/html/rfc6750](https://datatracker.ietf.org/doc/html/rfc6750)
- **RFC 7519 - JSON Web Token (JWT):** [https://datatracker.ietf.org/doc/html/rfc7519](https://datatracker.ietf.org/doc/html/rfc7519)
- **RFC 7515 - JSON Web Signature (JWS):** [https://datatracker.ietf.org/doc/html/rfc7515](https://datatracker.ietf.org/doc/html/rfc7515)
- **RFC 7516 - JSON Web Encryption (JWE):** [https://datatracker.ietf.org/doc/html/rfc7516](https://datatracker.ietf.org/doc/html/rfc7516)
- **RFC 7517 - JSON Web Key (JWK):** [https://datatracker.ietf.org/doc/html/rfc7517](https://datatracker.ietf.org/doc/html/rfc7517)
- **RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients (PKCE):** [https://datatracker.ietf.org/doc/html/rfc7636](https://datatracker.ietf.org/doc/html/rfc7636)
- **RFC 6238 - TOTP: Time-Based One-Time Password Algorithm:** [https://datatracker.ietf.org/doc/html/rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)
- **OpenID Connect Core 1.0 Specification:** [https://openid.net/specs/openid-connect-core-1_0.html](https://openid.net/specs/openid-connect-core-1_0.html)
- **W3C Web Authentication (WebAuthn Level 3):** [https://www.w3.org/TR/webauthn-3/](https://www.w3.org/TR/webauthn-3/)

---

## 2. Security Guidelines & Industry Frameworks

- **NIST SP 800-63B - Digital Identity Guidelines (Authentication & Lifecycle Management):** [https://pages.nist.gov/800-63-3/sp800-63b.html](https://pages.nist.gov/800-63-3/sp800-63b.html)
- **OWASP Application Security Verification Standard (ASVS 4.0):** [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
- **OWASP Top 10:2021 - A01 Broken Access Control:** [https://owasp.org/Top10/A01_2021-Broken_Access_Control/](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **OWASP Top 10:2021 - A07 Identification and Authentication Failures:** [https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- **OWASP API Security Top 10:2023:** [https://owasp.org/www-project-api-security/](https://owasp.org/www-project-api-security/)
- **OWASP Authentication Cheat Sheet:** [https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- **OWASP Authorization Cheat Sheet:** [https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- **OWASP JSON Web Token (JWT) Cheat Sheet:** [https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)

---

## 3. Notable CVE Case Studies in Identity Security

| CVE Identifier | Vulnerability Summary | Impact & Root Cause |
| :--- | :--- | :--- |
| **CVE-2022-21449** | Java "Psychic Signatures" | Flaw in Java 15-18 ECDSA signature verification where `r=0` and `s=0` passed validation, allowing complete signature forgery. |
| **CVE-2018-1000531** | PyJWT Key Confusion / Verification Bypass | Flaw where asymmetric tokens could be verified as symmetric tokens if algorithm checks were missing. |
| **CVE-2022-23529** | `jsonwebtoken` Remote Code Execution | Arbitrary file read and code execution via insecure parameter parsing in `jwt.verify()`. |
| **CVE-2021-22569** | Auth0 / JWT Verification Bypass | Missing algorithm restriction check allowed signature verification bypass under specific header combinations. |

---

## 4. Tooling & Technology Documentation

- **Keycloak Documentation:** [https://www.keycloak.org/documentation](https://www.keycloak.org/documentation)
- **Open Policy Agent (OPA) & Rego Reference:** [https://www.openpolicyagent.org/docs/latest/](https://www.openpolicyagent.org/docs/latest/)
- **ORY Hydra (OAuth2/OIDC Engine):** [https://www.ory.sh/hydra/docs/](https://www.ory.sh/hydra/docs/)
- **OAuth2-Proxy Gatekeeper:** [https://oauth2-proxy.github.io/oauth2-proxy/](https://oauth2-proxy.github.io/oauth2-proxy/)
- **jwt_tool (JWT Security Testing):** [https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)
- **Semgrep Registry:** [https://semgrep.dev/explore](https://semgrep.dev/explore)
- **JWT.io Debugger:** [https://jwt.io/](https://jwt.io/)

