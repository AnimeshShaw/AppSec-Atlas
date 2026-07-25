---
title: "05. Frontend Security Scanners & CI/CD Automated Defense"
description: "Implement frontend security automation using SAST linters (eslint-plugin-security, Semgrep), dependency scanners (retire.js, npm audit), DAST analyzers (DOMInvader, Lighthouse), and GitHub Actions CI/CD workflows."
keywords: ["AppSec", "Cybersecurity", "ESLint Security", "Semgrep", "Retire.js", "npm audit", "DOMInvader", "Lighthouse Security", "CI/CD Pipeline", "GitHub Actions", "SAST", "DAST"]
---

# 05. Frontend Security Scanners & CI/CD Automated Defense

Automating security analysis within developer workflows and Continuous Integration / Continuous Deployment (CI/CD) pipelines is essential for identifying frontend vulnerabilities before code reaches production. Security automation should combine **Static Application Security Testing (SAST)**, **Software Composition Analysis (SCA)** dependency auditing, and **Dynamic Application Security Testing (DAST)**.

This chapter details tool configurations, custom rule authoring, CLI execution patterns, and a complete GitHub Actions CI/CD security pipeline.

---

## 1. Static Application Security Testing (SAST) for Frontend

SAST linters inspect JavaScript, TypeScript, and framework templates during local development and build steps to flag vulnerable coding patterns.

### A. ESLint Security Plugins
Key plugins for frontend code bases include:
- `eslint-plugin-security`: Identifies regex Denial of Service (ReDoS) vulnerabilities, unsafe object iterations, and eval executions.
- `eslint-plugin-react-xss`: Flags unsafe React escape hatches and unescaped property bindings.
- `eslint-plugin-no-unsanitized`: Enforces DOMPurify sanitization before writing to DOM sinks.

#### Installation
```bash
npm install --save-dev eslint-plugin-security eslint-plugin-no-unsanitized eslint-plugin-react
```

#### Production ESLint Configuration (`.eslintrc.js`)
```javascript
module.exports = {
  env: {
    browser: true,
    es2022: true
  },
  extends: [
    'eslint:recommended',
    'plugin:security/recommended-legacy',
    'plugin:no-unsanitized/DOM'
  ],
  plugins: ['security', 'no-unsanitized', 'react'],
  rules: {
    // Custom Security Enforcement Rules
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-object-injection': 'warn',
    'no-unsanitized/method': 'error',
    'no-unsanitized/property': 'error',
    'react/no-danger': 'error' // Disallow dangerouslySetInnerHTML without explicit review
  }
};
```

---

### B. Semgrep Custom Rule Authoring for Frontend Sinks
[Semgrep](https://semgrep.dev) is a lightweight, fast SAST scanner that operates on Abstract Syntax Trees (ASTs). Below is a production Semgrep rule file (`frontend-security-rules.yaml`) designed to detect unsafe DOM sinks in React, Vue, Angular, and vanilla JavaScript.

```yaml
rules:
  - id: detect-react-dangerously-set-inner-html
    languages: [typescript, javascript]
    message: "Potential DOM XSS: Unsanitized input passed to dangerouslySetInnerHTML."
    severity: ERROR
    pattern-either:
      - pattern: <$EL dangerouslySetInnerHTML={{__html: $VAR}} />
    pattern-not-inside:
      - pattern: <$EL dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(...)}} />

  - id: detect-angular-dom-sanitizer-bypass
    languages: [typescript, javascript]
    message: "Security Bypass: DomSanitizer bypass method explicitly disables HTML/URL security filters."
    severity: ERROR
    pattern-either:
      - pattern: $SANITIZER.bypassSecurityTrustHtml(...)
      - pattern: $SANITIZER.bypassSecurityTrustScript(...)
      - pattern: $SANITIZER.bypassSecurityTrustUrl(...)

  - id: detect-raw-inner-html-assignment
    languages: [typescript, javascript]
    message: "DOM XSS Sink: Direct assignment to innerHTML without sanitization."
    severity: WARNING
    pattern: $EL.innerHTML = $VAL
    pattern-not: $EL.innerHTML = DOMPurify.sanitize(...)
```

#### Executing Semgrep CLI
```bash
semgrep --config=frontend-security-rules.yaml src/
```

---

## 2. Software Composition Analysis (SCA) & Supply Chain Security

Frontend applications heavily rely on third-party npm libraries. Vulnerabilities in deeply nested dependencies directly compromise the browser environment.

### A. Dependency Vulnerability Audit (`npm audit` & `pnpm audit`)
Integrated natively into package managers, dependency auditing checks `package-lock.json` against known advisory databases.

```bash
# Run non-destructive vulnerability check
npm audit --audit-level=high

# Automated production build check failing on High/Critical flaws
npm audit --production --audit-level=high
```

### B. Retire.js: Scans Client-Side JavaScript Libraries
[Retire.js](https://retirejs.github.io/retire.js/) is a scanner specifically tailored to detect outdated client-side libraries (such as vulnerable versions of jQuery, Bootstrap, or Angular) present in distribution builds.

#### Installation & Execution
```bash
# Global CLI installation
npm install -g retire

# Scan distribution build artifacts folder
retire --path dist/ --severity high
```

---

## 3. Dynamic Application Security Testing (DAST) & Browser Scanners

DAST tools execute against running web applications to evaluate response headers, SSL configurations, and DOM data flow execution paths.

### A. Google Lighthouse CLI Security Audit
Google Lighthouse audits security headers, HTTPS redirection, and vulnerable JavaScript libraries.

```bash
# Install Lighthouse CLI
npm install -g lighthouse

# Execute Security Category Audit in Headless Chrome
lighthouse https://staging.example.com \
  --only-categories=security \
  --chrome-flags="--headless" \
  --output=json \
  --output-path=./lighthouse-security-report.json
```

### B. Burp Suite DOM Invader
**DOM Invader** (integrated into Burp Suite's embedded browser) automates DOM XSS testing by injecting web canary payloads into sources and tracking whether unescaped strings reach dangerous sinks in real time.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       DOM INVADER CANARY DATA FLOW                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Canary Payload Injected into URL: https://target.com/?q=a3k8x9           │
│ 2. DOM Invader attaches runtime hooks to 40+ JavaScript sinks               │
│ 3. Intercepts call to sink: element.innerHTML = "Result: " + location.search│
│ 4. Flags Confirmed DOM XSS Vector with exact stack trace & line number     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. GitHub Actions CI/CD Security Pipeline

Below is a complete, production-grade GitHub Actions workflow (`.github/workflows/frontend-security.yml`) that executes SAST linters, Semgrep analysis, dependency audits, Retire.js, and Lighthouse security checks on every pull request.

```yaml
name: Frontend Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-audit:
    name: Frontend Security Audit
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Setup Node.js Environment
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install Project Dependencies
        run: npm ci

      - name: Run ESLint Security Rules
        run: npx eslint src/ --ext .js,.jsx,.ts,.tsx

      - name: Run Semgrep SAST Scanning
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/security-audit

      - name: Audit npm Dependencies (SCA)
        run: npm audit --audit-level=high

      - name: Scan Client-Side Distribution Assets with Retire.js
        run: |
          npm run build
          npx retire --path dist/ --severity high

      - name: Run Google Lighthouse Security Check
        run: |
          npx lighthouse-ci collect --url=http://localhost:3000 || true
```

---
