# 01 - Introduction to Browser Extension Security

## Threat Landscape
Browser extensions are prime targets for attackers because they can read and modify all data on websites the user visits, capture credentials, and manipulate transactions. A malicious or compromised extension effectively bypasses traditional web security boundaries like the Same-Origin Policy (SOP).

## Extension Architecture (Manifest V3)
Manifest V3 (MV3) is the latest extension architecture, designed to improve security, privacy, and performance. 

### 1. The Manifest (`manifest.json`)
The entry point of the extension. It declares metadata, permissions, and the scripts that make up the extension.

### 2. Service Workers (Background Scripts)
In MV3, background pages are replaced by Service Workers. They are event-driven, run in the background, and have no DOM access. They sleep when idle, reducing memory footprint and limiting the window for persistent malicious activity.

### 3. Content Scripts
Scripts injected into web pages by the extension. They execute in the context of the web page and can read and modify the DOM. 
> **Security Note:** Content scripts run in an "isolated world". They share the DOM with the page but have a separate JavaScript environment. However, DOM-based attacks (like DOM XSS) can bridge this gap.

### 4. Popup and Options Pages
Standard HTML/JS pages hosted within the extension's `chrome-extension://` origin.

## Extension Permissions Model
Extensions must request permissions to use specific APIs or access certain websites (Host Permissions).
- **ActiveTab:** Grants temporary access to the currently active tab when the user invokes the extension. It's a secure alternative to broad host permissions.
- **Host Permissions:** E.g., `*://*.google.com/*` or `<all_urls>`. Overly broad permissions are a major security risk.
