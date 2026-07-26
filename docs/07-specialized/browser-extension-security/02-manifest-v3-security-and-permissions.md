---
title: 02 - Manifest V3 Security and Permissions
description: 'MV3 introduces several major security enhancements over MV2:'
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '07'
- Specialized
- Browser
- Extension
- Security
- '02'
- Manifest
- V3
- Security
- And
- Permissions
- Md
slug: /specialized/browser-extension-security/manifest-v3-security-and-permissions
---


# 02 - Manifest V3 Security and Permissions

## Migrating from Manifest V2 to V3: Security Benefits
MV3 introduces several major security enhancements over MV2:
1. **No remote code execution:** `eval()` and fetching remote JavaScript are banned. All code must be bundled within the extension.
2. **Service Workers:** Replacing persistent background pages limits long-running malicious processes.
3. **Declarative Net Request:** Replaces `webRequest` blocking API, preventing extensions from observing all user network traffic just to block ads.

## Content Security Policy (CSP) in Extensions
MV3 enforces a strict, unmodifiable CSP for extension pages and service workers.
Default MV3 CSP: `script-src 'self'; object-src 'self';`
You cannot loosen this to allow `unsafe-eval` or remote scripts.

## The Principle of Least Privilege: Permissions

### Vulnerable Pattern: `<all_urls>`
Requesting `<all_urls>` means the extension can read/modify data on every single site.
```json
{
  "manifest_version": 3,
  "name": "Vulnerable Extension",
  "version": "1.0",
  "permissions": ["storage"],
  "host_permissions": ["<all_urls>"] // DANGEROUS
}
```

### Secure Pattern: `activeTab`
Use `activeTab` to only gain access when the user explicitly interacts with the extension (e.g., clicking the extension icon).
```json
{
  "manifest_version": 3,
  "name": "Secure Extension",
  "version": "1.0",
  "permissions": ["activeTab", "storage"]
}
```

## `declarativeNetRequest`
Instead of intercepting every request (which requires broad host permissions and exposes user data), you define rules for the browser to evaluate.

```json
// rules.json
[
  {
    "id": 1,
    "priority": 1,
    "action": { "type": "block" },
    "condition": { "urlFilter": "||malicious-tracker.com", "resourceTypes": ["script"] }
  }
]
```
```json
// manifest.json
{
  "permissions": ["declarativeNetRequest"],
  "declarative_net_request": {
    "rule_resources": [{
      "id": "ruleset_1",
      "enabled": true,
      "path": "rules.json"
    }]
  }
}
```
