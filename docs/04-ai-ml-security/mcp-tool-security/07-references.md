---
title: 07 - MCP Security References & Standards
description: Comprehensive references, specifications, OWASP benchmarks, CVE links,
  container sandboxing documentation, and academic research papers on Model Context
  Protocol security.
keywords:
- MCP
- References
- Model
- Context
- Protocol
- Spec
- OWASP
- LLM
- Top
- '10'
- JSON-RPC
- '2'
- '0'
- NIST
- AI
- RMF
- gVisor
- Documentation
- AppSec
slug: /ai-ml-security/mcp-tool-security/references
---


# 07 - MCP Security References & Standards

---

## 📜 Protocol Specifications & Standards

- **Model Context Protocol (MCP) Official Specification:**  
  [https://modelcontextprotocol.io/specification](https://modelcontextprotocol.io/specification)  
  *Defines core protocol structures for initialization, tool capabilities, resource templates, and JSON-RPC 2.0 transports.*

- **JSON-RPC 2.0 Transport Specification:**  
  [https://www.jsonrpc.org/specification](https://www.jsonrpc.org/specification)  
  *Official standard specification for JSON-RPC 2.0 request, response, and notification message payloads.*

- **JSON Schema Specification (Draft 2020-12):**  
  [https://json-schema.org/draft/2020-12/json-schema-core](https://json-schema.org/draft/2020-12/json-schema-core)  
  *Standard for defining tool input parameters and input validation schemas.*

---

## 🛡️ Security Frameworks & Guidelines

- **OWASP Top 10 for Large Language Model Applications:**  
  [https://owasp.org/www-project-top-10-for-large-language-model-applications/](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
  *Key mappings: LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM07 (Insecure Plugin Design), LLM08 (Excessive Agency).*

- **NIST Artificial Intelligence Risk Management Framework (AI RMF 1.0):**  
  [https://www.nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework)  
  *Provides guidelines for managing risks associated with autonomous AI systems and tool-use agents.*

- **MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems):**  
  [https://atlas.mitre.org/](https://atlas.mitre.org/)  
  *Threat matrix for tracking adversarial tactics, techniques, and procedures (TTPs) against agentic AI systems.*

---

## 🐳 Container Sandboxing & Isolation Technologies

- **gVisor Container Runtime (`runsc`):**  
  [https://gvisor.dev/docs/](https://gvisor.dev/docs/)  
  *Google's user-space application kernel for sandboxed container execution.*

- **Docker Security Best Practices & Seccomp:**  
  [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)  
  *Guidelines for dropping Linux capabilities and applying syscall restrictions.*

- **Kata Containers (Lightweight MicroVMs):**  
  [https://katacontainers.io/](https://katacontainers.io/)  
  *Hardware-isolated virtual machine container execution environment.*

---

## 🔬 Academic & Industry Research

- **Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications (Greshake et al.):**  
  *Pioneering research detailing Indirect Prompt Injection vectors in AI plugins and tool callers.*

- **Anthropic Engineering: Building Secure Tool-Use Architectures:**  
  [https://www.anthropic.com/research](https://www.anthropic.com/research)  
  *Technical guidelines on implementing Human-in-the-Loop gates and restricting agent privileges.*

---

## 🧰 Security Audit & Telemetry Tools

- **Semgrep Static Analysis Engine:**  
  [https://semgrep.dev/](https://semgrep.dev/)  
  *SAST engine for scanning MCP tool codebases for command injection and unvalidated file access.*

- **OpenTelemetry Specification:**  
  [https://opentelemetry.io/docs/](https://opentelemetry.io/docs/)  
  *Vendor-neutral telemetry framework for tracing and logging MCP JSON-RPC transactions.*

