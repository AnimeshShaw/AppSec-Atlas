# Browser Extension Security Guide

## Overview
Browser extensions have significant access to user data, often more than web applications themselves. This guide covers the security architecture of modern browser extensions, specifically focusing on Chrome's Manifest V3. You'll learn the primary attack vectors, such as DOM XSS in content scripts and insecure message passing, and how to defend against them.

## Prerequisites
- Basic understanding of JavaScript, HTML, and CSS.
- Familiarity with browser security concepts (CSP, CORS).
- Node.js and a Chromium-based browser (Chrome, Edge, or Brave) for labs.

## Learning Objectives
- Understand the Manifest V3 architecture and its security improvements over V2.
- Identify and mitigate DOM XSS vulnerabilities in content scripts.
- Secure extension message passing mechanisms.
- Safely store sensitive data and intercept web requests.
- Audit extensions using open-source tools.

## Navigation
- [01 Introduction](01-introduction.md)
- [02 Manifest V3 Security & Permissions](02-manifest-v3-security-and-permissions.md)
- [03 Content Script & DOM Injection](03-content-script-and-dom-injection.md)
- [04 Data Storage & Web Requests](04-extension-data-storage-and-web-requests.md)
- [05 Security Auditing Tools](05-extension-security-auditing-tools.md)
- [06 Hands-on Lab](06-hands-on-lab.md)
- [07 References](07-references.md)
