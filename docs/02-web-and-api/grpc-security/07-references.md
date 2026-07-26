---
title: 07. gRPC Security References & Standards
description: Comprehensive directory of gRPC security specifications, RFCs, OWASP
  mappings, CVE case studies, and official documentation.
keywords:
- gRPC
- References
- CVE-2023-44487
- RFC
- '7540'
- gRPC
- Security
- Specs
- OWASP
- API
- Security
slug: /web-and-api/grpc-security/references
---


# 07. gRPC Security References & Standards

This chapter provides a curated index of industry security standards, protocol specifications, CVE case studies, OWASP mappings, and official security guides for gRPC and HTTP/2 infrastructure.

---

## 1. Real-World CVE Case Studies

### A. CVE-2023-44487 - HTTP/2 Rapid Reset Vulnerability
* **CVSS Score:** 7.5 (HIGH) / Infrastructure Impact: CRITICAL
* **Description:** Affected virtually all HTTP/2 and gRPC server implementations (Go, Java, Python, C++, Node.js). Attackers repeatedly send `HEADERS` frames followed immediately by `RST_STREAM` frames. This forced servers to process request instantiation and teardown without hitting `SETTINGS_MAX_CONCURRENT_STREAMS` limits, resulting in 100% CPU utilization and crash DoS.
* **Remediation:** Upgrade gRPC runtime dependencies and Envoy/Nginx proxy versions to apply rate limits on HTTP/2 stream resets (`max_concurrent_streams` and reset frame tracking).

### B. CVE-2023-32731 - gRPC-Go TLS Certificate Validation Bypass
* **CVSS Score:** 7.5 (HIGH)
* **Description:** A vulnerability in `grpc-go` allowed clients to bypass custom certificate validation hooks under specific TLS configurations when `InsecureSkipVerify` was set alongside custom verification logic.
* **Remediation:** Upgrade `google.golang.org/grpc` to `v1.55.0` or higher and enforce standard `tls.Config` certificate pools.

### C. CVE-2021-3616 - Envoy Proxy gRPC Filter Bypass
* **CVSS Score:** 8.6 (HIGH)
* **Description:** Specially crafted gRPC request paths with null bytes or unnormalized URI paths allowed attackers to bypass Envoy gRPC authorization filters and access restricted upstream backend services.
* **Remediation:** Enable strict URL path normalization in Envoy `HttpConnectionManager` filters.

---

## 2. OWASP API Security Top 10 (2023) gRPC Mapping Matrix

| OWASP API Top 10 Risk | gRPC Specific Vulnerability Vector | gRPC Mitigation Strategy |
| :--- | :--- | :--- |
| **API1:2023 - Broken Object Level Authorization (BOLA)** | RPC calls like `GetUser(UserRequest)` executing without validating if caller matches `req.user_id`. | Interceptor-based context validation matching authenticated JWT `sub` claim against Protobuf request field IDs. |
| **API2:2023 - Broken Authentication** | Disabling mTLS (`InsecureChannel`) or missing metadata authorization tokens on exposed gRPC ports. | Enforce mTLS with SPIFFE/SPIRE certificates and interceptor-level Bearer token verification. |
| **API3:2023 - Broken Object Property Level Auth** | Proto3 unknown field retention allowing field smuggling or returning hidden fields in message responses. | Use explicit response schemas, strip unknown fields, and enforce field-level OPA policies. |
| **API4:2023 - Unrestricted Resource Consumption** | Unbounded client-streaming RPCs, HTTP/2 Rapid Reset floods, or deeply nested recursive Protobuf payloads. | Configure `max_concurrent_streams`, `max_receive_message_size`, `ghz` rate limiters, and nesting depth rules. |
| **API5:2023 - Broken Function Level Authorization** | Exposing administrative RPC methods (e.g., `/admin.Admin/ResetDB`) without role checks or via Server Reflection. | Disable Server Reflection in production and enforce interceptor-level role check (RBAC/ABAC). |
| **API6:2023 - Unrestricted Access to Sensitive Business Flows** | Unthrottled RPC batch calls executing automated financial or registration flows. | Implement Envoy rate-limiting filters and interceptor-based token buckets. |
| **API7:2023 - Server Side Request Forgery (SSRF)** | gRPC microservices forwarding unvalidated target URLs passed inside Protobuf `string` fields. | Enforce URL allowlists and sanitize all string inputs via `buf validate` rules. |
| **API8:2023 - Security Misconfiguration** | Unconditionally enabling gRPC Server Reflection (`ServerReflection`) in production networks. | Gate reflection registration with environment checks (`os.Getenv("ENV") == "development"`). |
| **API9:2023 - Improper Inventory Management** | Shadow gRPC services running unmonitored ports inside Kubernetes clusters without mesh registration. | Enforce service mesh policy (Istio/Linkerd) requiring explicit mTLS traffic authorization rules. |
| **API10:2023 - Unsafe Consumption of APIs** | Backend gRPC services blindly trusting downstream RPC responses without validating message constraints. | Enforce strict Protobuf schema validation with `buf validate` at both ingress and internal RPC hops. |

---

## 3. RFC Specifications & Technical Standards

* **RFC 9113 (Obsoletes RFC 7540):** [Hypertext Transfer Protocol Version 2 (HTTP/2)](https://datatracker.ietf.org/doc/html/rfc9113)
* **RFC 7541:** [HPACK: Header Compression for HTTP/2](https://datatracker.ietf.org/doc/html/rfc7541)
* **RFC 8446:** [The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
* **SPIFFE Standard:** [SPIFFE Workload API & SVID Specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
* **Protocol Buffers Specification:** [Google Protocol Buffers Language Guide (proto3)](https://protobuf.dev/programming-guides/proto3/)

---

## 4. Official Documentation & Hardening Checklists

* **gRPC Official Authentication Guide:** [https://grpc.io/docs/guides/auth/](https://grpc.io/docs/guides/auth/)
* **Envoy Proxy gRPC Filter Documentation:** [https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/grpc_web_filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/grpc_web_filter)
* **Buf Schema Validation (`buf validate`):** [https://buf.build/docs/validate/rules/](https://buf.build/docs/validate/rules/)
* **CNCF Cloud Native Security Whitepaper:** [https://github.com/cncf/tag-security](https://github.com/cncf/tag-security)
