---
title: "01. Introduction to Frontend Security"
description: "The browser is a hostile environment. With the rise of Single Page Applications (SPAs), much of the business logic and state management has shifted to..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Frontend Security", "01 Introduction.Md"]
---

# 01. Introduction to Frontend Security

The browser is a hostile environment. With the rise of Single Page Applications (SPAs), much of the business logic and state management has shifted to the client side. This chapter explores the client-side threat model and primary attack vectors.

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## 🕵️ Client-Side Threat Model

In traditional web applications, the server was responsible for rendering HTML. Today, SPAs dynamically update the Document Object Model (DOM) using JavaScript. This introduces new risks:
- **Client-Side Data Exposure:** Sensitive data stored in the browser can be accessed by malicious scripts or local attackers.
- **Client-Side Logic Manipulation:** Attackers can modify JavaScript execution, bypass client-side validation, or manipulate the DOM.
- **Third-Party Script Dependency:** Applications heavily rely on CDNs and external scripts (analytics, ads), which can be compromised.

## 🦠 DOM-based Cross-Site Scripting (DOM XSS)

DOM XSS occurs when an application contains client-side JavaScript that processes data from an untrusted source (source) in an unsafe way, usually by writing that data to the DOM (sink).

### Sources and Sinks
- **Sources:** `location.hash`, `location.search`, `document.referrer`, `window.name`.
- **Sinks:** `element.innerHTML`, `document.write()`, `eval()`, `setTimeout()`.

### Vulnerable Example
```javascript
// The application reads a user's name from the URL query parameter and writes it to the DOM.
const urlParams = new URLSearchParams(window.location.search);
const userName = urlParams.get('name');
// Unsafe Sink
document.getElementById('greeting').innerHTML = `Hello, ${userName}!`;
```
If an attacker crafts a URL like `?name=<img src=x onerror=alert('XSS')>`, the script will execute.

## 🗄️ LocalStorage vs Cookie Storage Hazards

Storing sensitive data like JWTs (JSON Web Tokens) in the browser requires careful consideration.

| Storage Mechanism | Pros | Cons |
| :--- | :--- | :--- |
| **LocalStorage / SessionStorage** | Easy to use, accessible via JS. | Vulnerable to XSS. Any script on the page can read the data. |
| **Cookies** | Can be secured with `HttpOnly` (preventing JS access) and `Secure` flags. | Vulnerable to Cross-Site Request Forgery (CSRF) if `SameSite` is not configured correctly. |

**Rule of Thumb:** Never store sensitive tokens (like Access Tokens or Refresh Tokens) in `LocalStorage`.

## ⚠️ Third-Party Script Risks

Modern web applications include an average of 20+ third-party scripts. If a third-party provider is compromised, the attacker can inject malicious code directly into your application (Supply Chain Attack).

- **Magecart Attacks:** Attackers compromise a third-party script to steal credit card information entered on the site.
- **Mitigation:** Use Subresource Integrity (SRI) and Content Security Policy (CSP) to restrict script execution and verify integrity.
