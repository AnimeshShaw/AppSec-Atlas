# API Security Guide

> **Section:** 🌐 Web & API Security  
> **Level:** Intermediate  
> **Time to Complete:** ~75 minutes  
> **Prerequisites:** Basic understanding of REST APIs, HTTP headers, JSON, and OAuth2/JWT concepts  
> **Status:** ✅ Complete & Production-Ready

---

## 🎯 Overview & Learning Objectives

API Security focuses on securing application programming interfaces (REST, GraphQL, gRPC) against OWASP API Security Top 10 risks. As APIs serve as the backend engine for modern web apps, mobile apps, and microservices, unhardened APIs represent the primary data exfiltration target for adversaries.

By the end of this practical guide, you will be able to:
- [x] **Identify** OWASP API Security Top 10 vulnerabilities (BOLA, BFLA, Mass Assignment, Excessive Data Exposure).
- [x] **Audit & Exploit** REST, GraphQL, and gRPC endpoints safely in local test setups.
- [x] **Implement** robust authorization checks, strict schema validation, and Redis-backed rate limiting.
- [x] **Harden** GraphQL APIs against introspection abuse, query batching, and high-depth DoS attacks.
- [x] **Configure** API Gateway security policies (Kong, Nginx, Envoy) for mTLS and OAuth2 scope validation.
- [x] **Run & Solve** a hands-on Python/Flask API security lab.

---

## 📚 Module Navigation

1. **[01. Overview & OWASP API Top 10](01-introduction.md)** — Overview of API attack surfaces, OWASP API Security Top 10 framework, and API discovery.
2. **[02. BOLA & BFLA Masterclass](02-bola-and-bfla.md)** — Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA) with code fixes in Node.js, Python, and Go.
3. **[03. GraphQL & gRPC Security](03-graphql-and-grpc-security.md)** — Introspection hardening, query depth & cost limiting, GraphQL batching attacks, and gRPC metadata security.
4. **[04. Rate Limiting, Throttling & Auth](04-rate-limiting-and-throttling.md)** — Token bucket algorithm, Redis-backed sliding window rate limiters, JWT algorithm manipulation (`alg: none`), and OAuth2 PKCE.
5. **[05. API Gateway & Defense Patterns](05-defenses-and-gateway-patterns.md)** — Schema validation (OpenAPI/JSON Schema), Nginx/Kong security headers, and mTLS mutual authentication.
6. **[06. Hands-On Vulnerability Lab](06-hands-on-lab.md)** — Self-contained Python Flask API Lab: BOLA + Mass Assignment Exploit + Secure Fix.
7. **[07. References & Testing Tools](07-references.md)** — Postman security collections, Nuclei API vulnerability templates, and OWASP API benchmark.

---

*Begin reading: [01. Overview & OWASP API Top 10 →](01-introduction.md)*
