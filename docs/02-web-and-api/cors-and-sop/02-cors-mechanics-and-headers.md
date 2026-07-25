---
title: "02 - CORS Mechanics and Headers"
description: "Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to indicate any origins (domain, scheme, or port) other th..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Cors And Sop", "02 Cors Mechanics And Headers.Md"]
---

# 02 - CORS Mechanics and Headers

Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to indicate any origins (domain, scheme, or port) other than its own from which a browser should permit loading resources.

## The CORS Protocol

When a web application makes a cross-origin HTTP request, the browser automatically adds an `Origin` header to the request. The server then responds with `Access-Control-*` headers to indicate whether the request is permitted.

### Simple Requests
Some requests don't trigger a CORS preflight. These are known as "simple requests" and must meet the following criteria:
- Method: `GET`, `HEAD`, or `POST`.
- Headers: Only a few specific headers are allowed (e.g., `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`).
- Content-Type: Must be `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`.

**Flow:**
1. Browser sends the request with the `Origin` header.
2. Server responds with the resource and the `Access-Control-Allow-Origin` header.
3. If the origin matches, the browser allows the frontend code to read the response.

### Preflight Requests (OPTIONS)
For requests that might have side effects on server data (e.g., `PUT`, `DELETE`, `PATCH`, or custom headers like `Authorization` or `Content-Type: application/json`), the browser first sends an `OPTIONS` request. This is the **preflight request**.

**Flow:**
1. Browser sends an `OPTIONS` request with `Origin`, `Access-Control-Request-Method`, and `Access-Control-Request-Headers`.
2. Server responds with `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers`.
3. If approved, the browser sends the actual request.
4. Server responds to the actual request (also including CORS headers).

## Key CORS Headers

### 1. `Access-Control-Allow-Origin` (ACAO)
Specifies which origin(s) are allowed to access the resource.
- `Access-Control-Allow-Origin: *` (Allows any origin. Note: Cannot be used with credentials).
- `Access-Control-Allow-Origin: https://app.example.com` (Allows exactly this origin).

### 2. `Access-Control-Allow-Credentials` (ACAC)
Indicates whether the browser should expose the response to frontend JavaScript code when the request's credentials mode (cookies, authorization headers, or TLS client certificates) is `include`.
- `Access-Control-Allow-Credentials: true`

**Important Security Rule:** If `ACAC` is `true`, `ACAO` **cannot** be the wildcard `*`. It must specify an exact origin.

### 3. `Access-Control-Allow-Methods`
Specifies the method or methods allowed when accessing the resource. This is used in response to a preflight request.
- `Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE`

### 4. `Access-Control-Allow-Headers`
Used in response to a preflight request to indicate which HTTP headers can be used when making the actual request.
- `Access-Control-Allow-Headers: X-Custom-Header, Content-Type`

### 5. `Access-Control-Max-Age`
Indicates how long (in seconds) the results of a preflight request can be cached by the browser, reducing the number of `OPTIONS` requests.
- `Access-Control-Max-Age: 86400`
