---
title: "04 - Extension Data Storage and Web Requests"
description: "Extensions often need to store user preferences or authentication tokens."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Browser Extension Security", "04 Extension Data Storage And Web Requests.Md"]
---

# 04 - Extension Data Storage and Web Requests

## Secure Data Storage
Extensions often need to store user preferences or authentication tokens.

### `chrome.storage.local` vs `chrome.storage.session`
- **`chrome.storage.local`**: Persists across browser restarts. Stored unencrypted on the disk. *Do not store sensitive secrets (like plaintext passwords or long-lived API keys) here.*
- **`chrome.storage.session`**: (Introduced in MV3) Kept only in memory and cleared when the browser session ends. Ideal for sensitive, temporary data like session tokens.

### Storing a Session Token Securely
```javascript
// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "SAVE_TOKEN") {
        // Use session storage for sensitive tokens
        chrome.storage.session.set({ authToken: request.token }).then(() => {
            console.log("Token stored securely in memory.");
        });
    }
});
```

## Intercepting HTTP Web Requests Securely
If you must read web request headers (and `declarativeNetRequest` is not sufficient), you can use `chrome.webRequest` (though blocking is restricted). 

### Credential Leakage Prevention
Be careful not to log or transmit intercepted credentials.

```javascript
// background.js
chrome.webRequest.onBeforeSendHeaders.addListener(
  function(details) {
    for (let header of details.requestHeaders) {
      if (header.name.toLowerCase() === 'authorization') {
        // Ensure you do not log this header to an external analytics service!
        console.log("Authorization header present for:", details.url);
      }
    }
    return {requestHeaders: details.requestHeaders};
  },
  {urls: ["<all_urls>"]}, // Needs broad permissions; use cautiously
  ["requestHeaders"]
);
```
