# 03 - Content Script and DOM Injection

## DOM XSS in Content Scripts
Content scripts interact directly with the DOM of the web page. If a content script unsafely handles data from the web page (or from background scripts), it can introduce DOM XSS, allowing a malicious webpage to execute code in the context of the extension or other pages.

### Vulnerable Code Example
```javascript
// content.js
// Reads untrusted data from the page and injects it unsafely
let username = document.getElementById("username-field").value;
let banner = document.createElement("div");
banner.innerHTML = "Welcome, " + username + "!"; // DOM XSS!
document.body.prepend(banner);
```

### Secure Code Example
```javascript
// content.js
let username = document.getElementById("username-field").value;
let banner = document.createElement("div");
banner.textContent = "Welcome, " + username + "!"; // SECURE: Uses textContent
document.body.prepend(banner);
```

## Message Passing Risks
Extensions use `chrome.runtime.sendMessage` and `chrome.runtime.onMessage` to communicate between content scripts and service workers.

### Vulnerable Message Listener
If a service worker doesn't verify the sender of a message, a malicious webpage might trigger privileged extension actions.
```javascript
// background.js (Vulnerable)
chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
    if (request.action === "deleteAccount") {
        // Attackers from any website can trigger this!
        deleteUserAccount(request.userId); 
    }
});
```

### Secure Message Listener (Origin Verification)
Always verify the `sender.origin` or `sender.url`.

```javascript
// background.js (Secure)
const ALLOWED_ORIGIN = "https://app.example.com";

chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
    if (sender.origin !== ALLOWED_ORIGIN) {
        console.warn("Blocked message from untrusted origin:", sender.origin);
        return;
    }
    
    if (request.action === "deleteAccount") {
        deleteUserAccount(request.userId); 
    }
});
```
