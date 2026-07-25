---
title: "05 - Authentication & Authorization Security Tools"
description: "Production-grade authorization requires robust tooling. Avoid writing custom crypto and auth servers; leverage established tools."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Auth And Authz", "05 Auth Security Tools.Md"]
---

# 05 - Authentication & Authorization Security Tools

Production-grade authorization requires robust tooling. Avoid writing custom crypto and auth servers; leverage established tools.

## 1. Keycloak (Identity and Access Management)
Keycloak is an open-source Identity Provider (IdP) supporting OIDC, SAML, and OAuth 2.0.

**Quick Start via Docker:**
```bash
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
```
- Provides out-of-the-box user federation, MFA, and SSO.

## 2. ORY Hydra (OAuth 2.0 and OIDC Server)
Hydra is an API-first OAuth2 and OIDC provider. It does NOT manage users (no login UI); it delegates authentication to your custom identity provider.

**Quick Start:**
```bash
docker run -d --name ory-hydra -p 4444:4444 -p 4445:4445 oryd/hydra:v2.1.1 serve all --dev
```

## 3. Open Policy Agent (OPA)
OPA is a general-purpose policy engine.

**Running OPA Server:**
```bash
docker run -p 8181:8181 openpolicyagent/opa run --server --log-level debug
```
**Evaluating Policies via CLI:**
You can test policies locally.
```bash
opa eval -i input.json -d policy.rego "data.app.authz.allow"
```

## 4. OAuth2 Proxy
A reverse proxy that provides authentication with Google, GitHub, or other IdPs, protecting internal services that lack native authentication.

**Configuration Example (`oauth2-proxy.cfg`):**
```ini
provider = "github"
client_id = "<your-client-id>"
client_secret = "<your-client-secret>"
cookie_secret = "O6-abcdefghijklmnopqrstuvwx..."
cookie_secure = true
cookie_httponly = true
email_domains = [ "*" ]
upstream = "http://internal-service:8080/"
```
