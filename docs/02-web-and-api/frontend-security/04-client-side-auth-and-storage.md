---
title: "04. Client-Side Authentication and Storage"
description: "Securing user sessions in SPAs is challenging. The recommended pattern has shifted from implicit flows to OAuth2 PKCE and secure token handling."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Frontend Security", "04 Client Side Auth And Storage.Md"]
---

# 04. Client-Side Authentication and Storage

Securing user sessions in SPAs is challenging. The recommended pattern has shifted from implicit flows to OAuth2 PKCE and secure token handling.

## 🔑 Secure OAuth2 PKCE in SPA Apps

The OAuth2 Implicit flow (which returned tokens in the URL hash) is deprecated due to security flaws. SPAs should now use the **Authorization Code Flow with PKCE (Proof Key for Code Exchange)**.

1. **Client** generates a cryptographically random `code_verifier` and a `code_challenge`.
2. **Client** redirects user to the Authorization Server with the `code_challenge`.
3. **User** authenticates and grants permission.
4. **Authorization Server** redirects back with an Authorization Code.
5. **Client** exchanges the Code + `code_verifier` for an Access Token.

## 📦 Web Workers for In-Memory Token Storage

To protect tokens from XSS, they should not be stored in `localStorage` or `sessionStorage`. While `HttpOnly` cookies are preferred for first-party APIs, if you must handle tokens in JS (e.g., for third-party APIs), keep them in memory.

For advanced protection, you can use a **Web Worker** to handle API requests. The Web Worker holds the token in its isolated memory space, meaning the main thread (and any XSS on it) cannot access the token directly.

### Architecture
1. Main thread sends request data to Web Worker.
2. Web Worker attaches the Access Token (stored in its memory) to the request headers.
3. Web Worker makes the `fetch` request.
4. Web Worker returns the response to the main thread.

## 🍪 Cookie Attributes for Session Security

When using cookies for session management, specific attributes must be set to ensure security:

- **`HttpOnly`**: Prevents JavaScript (and XSS) from accessing the cookie.
- **`Secure`**: Ensures the cookie is only sent over HTTPS.
- **`SameSite=Lax` or `SameSite=Strict`**: Protects against Cross-Site Request Forgery (CSRF).

### SameSite Explained
- `Strict`: The cookie is only sent in a first-party context. (Best for internal apps).
- `Lax`: The cookie is withheld on cross-site subrequests, but sent when the user navigates to the origin site (e.g., following a link). (Default in modern browsers).
- `None`: Requires `Secure`. Used when the cookie needs to be sent in cross-site contexts (e.g., an iframe or third-party widget).

### Setting Secure Cookies (Node.js/Express Example)
```javascript
res.cookie('sessionId', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 3600000 // 1 hour
});
```
