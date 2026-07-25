# 02 - Modern Authentication

Modern authentication goes beyond simple username and password, relying on standardized protocols and multi-factor verification.

## OAuth 2.0 & OpenID Connect (OIDC)

### OAuth 2.0
OAuth 2.0 is an **Authorization** framework. It allows third-party applications to obtain limited access to an HTTP service.
**Key flow: Authorization Code with PKCE (Proof Key for Code Exchange)**
PKCE protects against authorization code interception attacks, especially in mobile and single-page applications.

### OpenID Connect (OIDC)
OIDC is an **Authentication** layer built on top of OAuth 2.0. It provides an `id_token` (a JWT) representing the user's identity.

### Authorization Code Flow with PKCE
1. Client generates a `code_verifier` and a `code_challenge`.
2. Client redirects user to Authorization Server with the `code_challenge`.
3. User authenticates and grants consent.
4. Authorization Server returns an `authorization_code`.
5. Client sends `authorization_code` + `code_verifier` to the Token Endpoint.
6. Authorization Server validates the verifier and returns `access_token` (and `id_token`).

## Multi-Factor Authentication (MFA)
Enhance security by requiring multiple factors.
- **TOTP (Time-Based One-Time Password):** Authenticator apps generating 6-digit codes.
- **WebAuthn / Passkeys:** Phishing-resistant authentication using public key cryptography (FIDO2).

## Session Management Security

When using session cookies, specific attributes must be set to prevent attacks.

- `HttpOnly`: Prevents client-side scripts (JavaScript) from accessing the cookie, mitigating XSS token theft.
- `Secure`: Ensures the cookie is only sent over HTTPS.
- `SameSite`: Controls cross-site request behavior (`Strict` or `Lax`) to mitigate CSRF.

### Session Fixation Defense
Always regenerate the Session ID upon successful login to prevent an attacker from forcing a known session ID on a victim.

### Code Example: Secure Session Management (Node.js / Express)

```javascript
// Secure Node.js Session Setup
const express = require('express');
const session = require('express-session');

const app = express();

app.use(session({
  secret: 'complex-random-secret-key', // Use environment variable
  name: 'sessionId', // Change default connect.sid
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,     // Mitigate XSS
    secure: true,       // HTTPS only
    sameSite: 'strict', // Mitigate CSRF
    maxAge: 3600000     // 1 hour expiration
  }
}));

app.post('/login', (req, res) => {
  // Validate credentials...
  // Regenerate session to prevent Session Fixation
  req.session.regenerate((err) => {
    if (err) next(err);
    req.session.user = 'user123';
    res.send('Logged in securely');
  });
});
```

### Code Example: Secure Session Management (Python / Flask)

```python
# Secure Python Flask Session Setup
from flask import Flask, session, request
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'complex-random-secret-key'

# Configure cookie security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

@app.route('/login', methods=['POST'])
def login():
    # Validate credentials...
    # Flask regenerates the session automatically on login/logout usually,
    # but manually clearing is a good practice.
    session.clear()
    session['user'] = 'user123'
    session.permanent = True
    return 'Logged in securely'
```
