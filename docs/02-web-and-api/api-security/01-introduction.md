# 01. Overview & OWASP API Top 10

APIs (Application Programming Interfaces) are the primary attack surface of modern applications. Unlike traditional web applications that render HTML on the server, APIs expose raw data objects and system functions directly to client applications.

---

## 1. OWASP API Security Top 10 Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      OWASP API Security Top 10                              │
├───────┬──────────────────────────────────────┬──────────────────────────────┤
│ Rank  │ Category                             │ Core Vulnerability           │
├───────┼──────────────────────────────────────┼──────────────────────────────┤
│ API1  │ Broken Object Level Authorization    │ BOLA / IDOR on resource IDs  │
│ API2  │ Broken Authentication                │ Weak JWT, missing auth check │
│ API3  │ Broken Property Level Authorization  │ Mass Assignment / Data Leak  │
│ API4  │ Unrestricted Resource Consumption    │ Missing rate limits / DoS    │
│ API5  │ Broken Function Level Authorization  │ Missing admin role checks    │
│ API6  │ Unrestricted Access to Sensitive Flow│ Business logic abuse / bots  │
│ API7  │ Server Side Request Forgery (SSRF)   │ Untrusted URL fetching       │
│ API8  │ Security Misconfiguration            │ Verbose errors, CORS wildcard│
│ API9  │ Improper Inventory Management        │ Shadow / Unversioned APIs    │
│ API10 │ Unsafe Consumption of APIs           │ Trusting third-party API data│
└───────┴──────────────────────────────────────┴──────────────────────────────┘
```

---

## 2. API vs Traditional Web App Attack Surface

```
Traditional Web App:
[ Browser ] ──► HTTP Request ──► [ Server (Renders HTML) ] ──► Renders HTML Page
                                            │ (Enforces UI logic)

Modern API Architecture:
[ Mobile/SPA App ] ──► JSON Request ──► [ API Endpoint ] ──► Exposes Raw JSON Data Objects
                                              │ (Must enforce ALL auth & schema checks!)
```

### Key Differences:
1. **Raw Object Exposure**: APIs pass JSON payloads containing database IDs, internal object properties, and user roles directly to the client.
2. **Stateless Authentication**: APIs rely heavily on Bearer Tokens (JWTs) or API Keys, which can be vulnerable to token manipulation if not validated server-side.
3. **Automated Exploitability**: APIs are easily discoverable and scriptable using `curl`, Postman, or automated security scanners.

---

*Next Chapter: [02. BOLA & BFLA Masterclass →](02-bola-and-bfla.md)*
