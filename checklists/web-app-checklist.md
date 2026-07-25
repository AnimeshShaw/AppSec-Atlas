# Web Application Security Checklist

Use this checklist during development, code review, or security assessments.

## Authentication & Session Management
- [ ] Passwords hashed with bcrypt, scrypt, or Argon2 (min cost factor 12)
- [ ] No passwords stored in plaintext or with weak hashing (MD5, SHA1)
- [ ] Multi-factor authentication available for sensitive accounts
- [ ] Account lockout after repeated failed login attempts (with exponential backoff)
- [ ] Secure password reset flow (time-limited tokens, single-use)
- [ ] Session IDs are cryptographically random (min 128 bits)
- [ ] Session invalidated on logout
- [ ] Session fixation prevented (regenerate session ID on login)
- [ ] Cookies set with: `HttpOnly`, `Secure`, `SameSite=Strict` (or `Lax`)

## Access Control
- [ ] Authentication required before accessing all protected resources
- [ ] Authorization checked server-side (not just client-side)
- [ ] Principle of least privilege applied to all roles
- [ ] Direct object references validated against user's permissions (IDOR prevention)
- [ ] Admin functions not accessible by regular users
- [ ] Sensitive operations require re-authentication

## Input Validation & Output Encoding
- [ ] All input validated on the server side
- [ ] Input allowlisted where possible (not just blocklisted)
- [ ] HTML output encoded to prevent XSS (`&`, `<`, `>`, `"`, `'`)
- [ ] SQL queries use parameterized queries or prepared statements
- [ ] File uploads: type validated, stored outside webroot, name sanitized
- [ ] XML input does not allow external entity references (XXE prevention)

## CSRF Protection
- [ ] CSRF tokens required for all state-changing requests
- [ ] CSRF tokens are unique per session
- [ ] SameSite cookie attribute used where appropriate

## Security Headers
- [ ] `Content-Security-Policy` configured
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY` or `SAMEORIGIN`
- [ ] `Strict-Transport-Security` (HSTS) enabled
- [ ] `Referrer-Policy` configured
- [ ] `Permissions-Policy` restricts browser features

## Cryptography
- [ ] All data in transit uses TLS 1.2+ (TLS 1.3 preferred)
- [ ] Sensitive data at rest is encrypted
- [ ] No use of weak algorithms (MD5, SHA1, DES, RC4)
- [ ] Private keys and secrets not hardcoded in source code

## Error Handling & Logging
- [ ] Error messages do not expose stack traces or internal details to users
- [ ] All authentication events logged (success, failure, lockout)
- [ ] Log entries include timestamp, user, IP, action (without sensitive data)
- [ ] Logs stored securely and not accessible to end users

## Dependency Management
- [ ] All dependencies up to date
- [ ] Known vulnerable dependencies checked (Snyk, OWASP Dependency-Check)
- [ ] Software composition analysis (SCA) in CI/CD pipeline

## Infrastructure
- [ ] HTTPS enforced, HTTP redirects to HTTPS
- [ ] Server version headers removed or obscured
- [ ] Unnecessary services and ports disabled
- [ ] Default credentials changed on all systems
