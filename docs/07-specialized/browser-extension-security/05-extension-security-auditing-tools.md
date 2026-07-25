---
title: "05 - Extension Security Auditing Tools"
description: "When analyzing a third-party extension or testing your own, the right tools make a huge difference."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Browser Extension Security", "05 Extension Security Auditing Tools.Md"]
---

# 05 - Extension Security Auditing Tools

When analyzing a third-party extension or testing your own, the right tools make a huge difference.

## 1. CRX Viewer (Extension Source Code Auditing)
Browser extensions are just ZIP files. You can download the `.crx` file and unzip it, but tools like **CRX Viewer** (available as a web app and extension) allow you to easily view the source code of any extension in the Chrome Web Store.
- Look at `manifest.json` for overly broad permissions.
- Audit `content.js` for `.innerHTML` or `eval()` (though `eval` is blocked in MV3).

## 2. Extension-Mind
An automated tool designed to scan Chrome extensions for malicious patterns, overly broad permissions, and known vulnerabilities.
- **Repository:** https://github.com/tarnish-project/tarnish (Tarnish was a popular tool, now often replaced by newer static analysis scripts).

## 3. Semgrep for Extensions
Semgrep is an excellent tool for writing custom rules to find DOM XSS and insecure message passing in extension code.

**Example Semgrep Rule for insecure `onMessage`:**
```yaml
rules:
  - id: insecure-extension-message-listener
    message: "Extension message listener does not verify sender origin."
    languages: [javascript]
    severity: WARNING
    pattern: |
      chrome.runtime.onMessageExternal.addListener(function($REQ, $SENDER, $RES) {
        ...
        // Missing check for $SENDER.origin or $SENDER.url
      })
```

## 4. DAST with Chrome DevTools
Use the built-in Chrome DevTools to debug service workers and content scripts:
1. Go to `chrome://extensions`.
2. Enable "Developer mode".
3. Click on the "service worker" link under your extension to open DevTools directly in the extension's background context.
