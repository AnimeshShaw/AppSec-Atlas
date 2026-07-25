---
title: "05. Frontend Security Scanners"
description: "Automated security tooling is essential for catching vulnerabilities early in the software development lifecycle (SDLC)."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Frontend Security", "05 Frontend Security Scanners.Md"]
---

# 05. Frontend Security Scanners

Automated security tooling is essential for catching vulnerabilities early in the software development lifecycle (SDLC).

## 🔦 Lighthouse Security Audits

Google Lighthouse, built into Chrome DevTools, provides a basic security audit for web pages.
It checks for:
- HTTPS usage
- Vulnerable third-party libraries (via Snyk)
- Secure connections for cross-origin resources

**Usage via CLI:**
```bash
npm install -g lighthouse
lighthouse https://example.com --only-categories=security
```

## 🔍 ESLint Security Plugin

Static Application Security Testing (SAST) can be integrated into your linter. `eslint-plugin-security` helps identify potential security hotspots in JavaScript.

**Installation:**
```bash
npm install eslint-plugin-security --save-dev
```

**Configuration (`.eslintrc.js`):**
```javascript
module.exports = {
  extends: [
    'eslint:recommended',
    'plugin:security/recommended-legacy'
  ],
  plugins: ['security'],
  rules: {
    // Custom rule configurations
    'security/detect-non-literal-fs-filename': 'warn',
    'security/detect-unsafe-regex': 'error'
  }
};
```

## 📦 Retire.js / npm audit for Dependency Auditing

Frontend applications rely heavily on `node_modules`. Many of these packages have known vulnerabilities.

### npm audit
Built into npm, this command scans your project tree against the GitHub Advisory Database.
```bash
npm audit
npm audit fix
```

### Retire.js
Retire.js is specifically designed to detect the use of JavaScript libraries with known vulnerabilities.
**Installation:**
```bash
npm install -g retire
```
**Usage:**
```bash
# Scan the current directory
retire

# Scan a specific file
retire --js js/app.js
```
