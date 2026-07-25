# 04 - Session Management and Authentication

Proper session management is crucial for maintaining state and identity across HTTP requests securely.

## Core Concepts
- **Session Fixation:** Attacker tricks a user into authenticating with a known session ID.
- **Session Hijacking:** Attacker steals an active session ID (via XSS or network sniffing).

## Defense Strategies
1. **Regenerate Session IDs:** Always issue a new session ID upon successful login and privilege changes.
2. **Cookie Security Flags:**
   - `HttpOnly`: Prevents JavaScript access to the cookie (mitigates XSS).
   - `Secure`: Ensures the cookie is only transmitted over HTTPS.
   - `SameSite`: Prevents CSRF.
3. **Session Invalidation:** Properly destroy sessions on the server upon logout.
4. **Multi-Device Revocation:** Allow users to view and revoke active sessions.

## Code Examples

### Python (Flask) - Secure Session Configuration
```python
from flask import Flask, session, redirect, url_for
import os

app = Flask(__name__)
# Cryptographically strong secret key
app.config['SECRET_KEY'] = os.urandom(32)
# Secure cookie configurations
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

@app.route('/login')
def login():
    # ... authentication logic ...
    # Defend against session fixation by clearing old session
    session.clear() 
    session['user_id'] = user.id
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    # Invalidate session on server (Flask default sessions are client-side, 
    # for server-side sessions like Redis, explicitly delete the key here)
    session.clear()
    return redirect(url_for('home'))
```

### Node.js (Express) - express-session
```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    name: 'sessionId', // Rename default 'connect.sid'
    cookie: {
        secure: true, // Requires HTTPS
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 // 1 hour session
    }
}));

app.post('/login', (req, res) => {
    // ... authentication logic ...
    
    // Mitigate session fixation
    req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.user = user.id;
        res.redirect('/dashboard');
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        // Clear the cookie on the client side
        res.clearCookie('sessionId');
        res.redirect('/');
    });
});
```
