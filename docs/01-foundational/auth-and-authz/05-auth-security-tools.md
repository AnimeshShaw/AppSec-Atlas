---
title: "05 - Authentication & Authorization Security Tools & Automation"
description: "Master identity infrastructure tools (Keycloak, ORY Hydra, OAuth2-Proxy), Policy engines (OPA), CLI security scanners (jwt_tool, Hashcat), and Semgrep SAST rules for automated identity auditing."
keywords: ["Keycloak", "ORY Hydra", "OPA", "OAuth2-Proxy", "jwt_tool", "Hashcat", "Semgrep", "AppSec Tools", "SAST", "DAST"]
---

# 05 - Authentication & Authorization Security Tools & Automation

Production-grade identity security requires robust identity providers, policy enforcement engines, and automated security auditing tooling. Do not invent custom cryptography or authentication frameworks; leverage battle-tested open-source solutions.

---

## 1. Enterprise Identity Providers (IdP)

### A. Keycloak (Full-Featured Open Source IdP)

Keycloak provides enterprise Single Sign-On (SSO), Identity Federation (LDAP/Active Directory), multi-tenant realms, and FIDO2/WebAuthn support out of the box.

#### Production Docker Compose Stack (`docker-compose.yml`)

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: DB_Secure_Password_2026!
    volumes:
      - postgres_data:/var/lib/postgresql/data

  keycloak:
    image: quay.io/keycloak/keycloak:24.0.0
    command: start --optimized --http-enabled=false --hostname=auth.example.com
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: DB_Secure_Password_2026!
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: Admin_Complex_Password_2026!
    ports:
      - "8443:8443"
    depends_on:
      - postgres

volumes:
  postgres_data:
```

> [!TIP]
> **Keycloak Brute-Force Detection:** In the Keycloak Admin Console, navigate to `Realm Settings -> Security Defenses -> Brute Force Detection` and enable "Max Login Failures" (e.g., 5 failures = temporary lockout for 15 minutes).

---

### B. ORY Hydra (Headless API-First OAuth2/OIDC Engine)

ORY Hydra is a lightweight, cloud-native OAuth 2.0 and OpenID Connect provider designed for microservices. It delegates user interface and password handling to your own identity app while managing cryptographic token issuing and PKCE validation.

```bash
# Launch ORY Hydra in dev mode
docker run -d --name ory-hydra \
  -p 4444:4444 -p 4445:4445 \
  -e DSN=memory \
  oryd/hydra:v2.2.0 serve all --dev
```

---

## 2. Policy & Reverse Proxy Enforcers

### A. Open Policy Agent (OPA)

#### Running OPA as a Daemon / Sidecar
```bash
docker run -d -p 8181:8181 \
  --name opa-server \
  openpolicyagent/opa:latest \
  run --server --log-level=info
```

#### CLI Policy Evaluation & Testing Commands

```bash
# Evaluate a policy locally against an input JSON file
opa eval --bundle ./policies --input input.json "data.app.authz.allow"

# Execute unit tests for Rego policies
opa test ./policies -v
```

---

### B. OAuth2-Proxy (Reverse Proxy Auth Gatekeeper)

OAuth2-Proxy protects upstream microservices that lack native authentication by terminating requests, handling OAuth2/OIDC redirects, and enforcing session cookies.

#### Production Configuration (`oauth2-proxy.cfg`)

```ini
provider = "oidc"
oidc_issuer_url = "https://auth.example.com/realms/production"
client_id = "internal-service-proxy"
client_secret = "Proxy_Client_Secret_Value"

# Cookie Security Settings
cookie_secret = "32-byte-random-base64-secret-key-12345="
cookie_name = "__Host-oauth2_proxy"
cookie_secure = true
cookie_httponly = true
cookie_samesite = "strict"
cookie_expire = "4h"
cookie_refresh = "1h"

# Scope and Domain Enforcement
email_domains = [ "example.com" ]
upstreams = [ "http://127.0.0.1:8080/" ]
pass_access_token = true
pass_authorization_header = true
```

---

## 3. Automated Audit Tooling & SAST/DAST

### A. `jwt_tool` CLI (Offensive Audit & Exploitation)

`jwt_tool` is the industry-standard toolkit for testing JWT security implementations.

```bash
# 1. Analyze and decode token structure
python3 jwt_tool.py <JWT_TOKEN>

# 2. Test for 'alg: none' vulnerability
python3 jwt_tool.py <JWT_TOKEN> -X a

# 3. Test for RSA-to-HMAC Key Confusion Attack using public key file
python3 jwt_tool.py <JWT_TOKEN> -X k -pk public.pem

# 4. Dictionary brute-force attack against HMAC secret key
python3 jwt_tool.py <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt
```

---

### B. Hashcat (High-Performance HMAC Secret Cracking)

If a JWT utilizes `HS256` with a weak secret key, Hashcat can crack the secret signature offline using GPU acceleration.

```bash
# Hashcat Mode 16500 = JWT (Signature verification)
hashcat -m 16500 -a 0 jwt_hash.txt /usr/share/wordlists/rockyou.txt
```

---

### C. Custom Semgrep SAST Rules for Auth Flaws

Use Semgrep in your CI/CD pipeline to catch broken authentication code patterns before deployment.

#### Rule 1: Detect Disabled JWT Verification (`jwt-disabled-verification.yaml`)

```yaml
rules:
  - id: python-jwt-disabled-verification
    patterns:
      - pattern-either:
          - pattern: jwt.decode(..., verify_signature=False, ...)
          - pattern: jwt.decode(..., options={"verify_signature": False}, ...)
    message: "CRITICAL: JWT signature verification is explicitly disabled! This allows algorithm substitution and token forgery."
    severity: ERROR
    languages: [python]
```

#### Rule 2: Detect Missing JWT Algorithm Restrictions (`jwt-missing-algorithms.yaml`)

```yaml
rules:
  - id: python-jwt-missing-algorithms
    pattern: jwt.decode(`$TOKEN, $`KEY)
    message: "WARNING: PyJWT decode called without specifying allowed 'algorithms'. This may expose the application to algorithm confusion attacks."
    severity: WARNING
    languages: [python]
```

#### Rule 3: Detect Insecure Session Cookie Flags (`express-insecure-cookie.yaml`)

```yaml
rules:
  - id: express-insecure-session-cookie
    pattern: |
      app.use(session({
        ...,
        cookie: {
          httpOnly: false
        }
      }))
    message: "ERROR: Express session cookie has httpOnly set to false. JavaScript can access session cookies, exposing them to XSS theft."
    severity: ERROR
    languages: [javascript, typescript]
```

