# 01 - Introduction to Same-Origin Policy (SOP)

## What is an Origin?
In web security, an **origin** is defined by the combination of three components of a URI:
1. **Scheme** (Protocol): e.g., `http`, `https`
2. **Host** (Domain): e.g., `www.example.com`, `api.example.com`
3. **Port**: e.g., `80`, `443`, `8080`

Two URLs have the same origin if and only if all three components are identical.

### Origin Comparison Examples
Base URL: `http://www.example.com/dir/page.html`

| URL | Result | Reason |
| --- | --- | --- |
| `http://www.example.com/dir2/other.html` | **Same Origin** | Only the path differs |
| `http://www.example.com/dir/inner/page.html` | **Same Origin** | Only the path differs |
| `https://www.example.com/secure.html` | **Failure** | Different scheme (`https`) |
| `http://www.example.com:81/dir/other.html` | **Failure** | Different port (`81`) |
| `http://api.example.com/dir/other.html` | **Failure** | Different host (`api.example.com`) |

## The Same-Origin Policy (SOP)
The Same-Origin Policy is a critical security mechanism built into modern web browsers. It restricts how a document or script loaded by one origin can interact with a resource from another origin.

### Why does SOP exist?
Without SOP, any website you visit could run JavaScript to interact with other websites on your behalf. 
For example, if you are logged into `https://mybank.com` and then visit a malicious site `https://evil.com`, scripts on `evil.com` could make requests to `mybank.com`. Since your browser automatically sends your session cookies with those requests, the malicious script could read your account balance or transfer funds. SOP prevents `evil.com` from reading the response of requests made to `mybank.com`.

### What does SOP allow and restrict?
SOP primarily restricts **reading** data across origins. It generally does not restrict **sending** data or embedding resources.

**Generally Allowed (Cross-Origin Embedding & Sending):**
- Links, redirects, and form submissions.
- Embedding images (`<img>`).
- Embedding media (`<video>`, `<audio>`).
- Embedding scripts (`<script src="...">`). Note: The script executes in the context of the embedding site.
- Embedding documents (`<iframe>`).

**Generally Restricted (Cross-Origin Reading):**
- Reading data via AJAX (fetch, XMLHttpRequest).
- Reading data from an iframe (e.g., accessing `iframe.contentWindow`).
- Reading pixel data from a canvas drawn with a cross-origin image.

To relax these restrictions for legitimate use cases (e.g., a frontend app on `app.example.com` calling an API on `api.example.com`), browsers use **Cross-Origin Resource Sharing (CORS)**.
