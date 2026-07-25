# 03. Content Security Policy (CSP) and SRI

Defense-in-depth is crucial for frontend security. CSP and SRI are essential tools to mitigate XSS and supply chain attacks.

## 🛡️ Strict Content Security Policy (CSP v3)

A Content Security Policy (CSP) is an HTTP header that allows site administrators to declare approved sources of content that the browser may load.

A "Strict CSP" moves away from allowlisting domains (which can be bypassed) and instead relies on **Nonces** (Number Used Once) or **Hashes**.

### Nonce-Based Strict CSP

A unique nonce is generated on the server for every request and injected into the CSP header and inline scripts.

**HTTP Response Header:**
```http
Content-Security-Policy: default-src 'none'; script-src 'nonce-R4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none';
```

**HTML:**
```html
<!DOCTYPE html>
<html>
<head>
  <!-- This script will execute because the nonce matches -->
  <script nonce="R4nd0m">
    console.log('Secure inline script');
  </script>
  
  <!-- This script will be blocked by the browser -->
  <script>
    console.log('Injected malicious script');
  </script>
</head>
<body>...</body>
</html>
```

*Note: `'strict-dynamic'` allows scripts that were trusted via nonce or hash to dynamically load other scripts, which is necessary for modern web applications.*

## 🔗 Subresource Integrity (SRI)

SRI ensures that resources (like scripts and stylesheets) hosted on third-party CDNs have not been tampered with. You provide a cryptographic hash of the expected file content.

### Using SRI
Generate a base64-encoded hash of the file (e.g., using `openssl dgst -sha384 -binary file.js | openssl base64 -A`).

```html
<script 
  src="https://code.jquery.com/jquery-3.6.0.min.js"
  integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
  crossorigin="anonymous">
</script>
```
If the CDN is compromised and the script is modified, the hash will change, and the browser will refuse to execute the script.

## 🔗 Trusted Types Integration in CSP

You can enforce Trusted Types via the CSP header:
```http
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default dompurify;
```
This forces the application to use the defined Trusted Type policies (`default`, `dompurify`) before writing to DOM sinks.
