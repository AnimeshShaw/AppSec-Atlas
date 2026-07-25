# Security Code Review Checklist

Use this checklist when reviewing code for security issues.

## Authentication & Access Control
- [ ] Authentication applied to all endpoints that require it
- [ ] Authorization checked on the server side (not just UI-level hiding)
- [ ] No hardcoded credentials, API keys, or secrets in code
- [ ] Privilege escalation paths examined

## Input Handling
- [ ] All user-supplied input validated before use
- [ ] SQL queries use parameterized queries (not string concatenation)
- [ ] HTML output is encoded before rendering
- [ ] File paths sanitized (no directory traversal: `../`)
- [ ] Deserialization of untrusted data avoided
- [ ] XML parsing safe (XXE disabled)

## Cryptography
- [ ] No use of weak algorithms (MD5, SHA1, DES, ECB mode)
- [ ] Random values use cryptographically secure PRNG
- [ ] Secrets not logged
- [ ] Passwords hashed with modern algorithms (bcrypt, Argon2)

## Error Handling
- [ ] Exceptions caught and handled — not exposed to users
- [ ] Error messages generic to users, detailed in logs
- [ ] No stack traces in HTTP responses

## Logging
- [ ] Security-relevant events logged (login, access denied, data changes)
- [ ] No sensitive data in logs (passwords, tokens, PII)

## Dependency & Third-Party Code
- [ ] Dependencies checked against vulnerability databases
- [ ] Third-party scripts loaded from trusted sources with SRI hashes

## Language-Specific: Python
- [ ] `subprocess` calls avoid `shell=True` with user input
- [ ] `pickle` / `yaml.load` not used with untrusted data
- [ ] `eval()` / `exec()` not used with user input

## Language-Specific: JavaScript / Node.js
- [ ] `eval()` and `new Function()` not used with user input
- [ ] `innerHTML` not set with user data (use `textContent`)
- [ ] npm packages checked for known vulnerabilities (`npm audit`)
- [ ] Prototype pollution risks assessed in object merges

## Language-Specific: Java
- [ ] Prepared statements used for all database queries
- [ ] Deserialization of untrusted objects avoided
- [ ] XML parsers configured to disable external entities (XXE)

## Language-Specific: Go
- [ ] `html/template` used instead of `text/template` for HTML output
- [ ] Goroutine leaks checked for (resource exhaustion)
- [ ] `os/exec` calls don't pass user input directly to shell
