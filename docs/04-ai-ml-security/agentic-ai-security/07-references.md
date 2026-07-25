---
title: "07. References, Standards & Frameworks"
description: "Explore industry standards (OWASP, NIST, MITRE ATLAS), CVEs, academic papers, and security tooling documentation for Agentic AI."
keywords: ["AppSec", "Agentic AI References", "OWASP LLM 2025", "NIST AI RMF", "MITRE ATLAS", "Agent CVEs", "AgentDojo"]
---

# 07. References, Standards & Frameworks

This chapter provides a curated list of industry standards, academic research, real-world CVE disclosures, and open-source security tools for engineering secure Agentic AI applications.

---

## 1. Industry Security Standards & Frameworks

- **OWASP Top 10 for LLM Applications (2025 Edition)**  
  The definitive standard for Large Language Model security. Core Agentic AI vulnerabilities map directly to:
  - **LLM01: Prompt Injection** (Direct & Indirect execution vector redirection)
  - **LLM02: Sensitive Information Disclosure** (Exfiltrating keys via tool observations)
  - **LLM05: Supply Chain & Tool Risks** (Vulnerable third-party tools & MCP servers)
  - **LLM06: Excessive Agency** (Over-privileged tools granted to generic agents)
  - **LLM08: Vector & Embedding Weaknesses** (Long-term agent memory state poisoning)
  - *URL*: [https://owasp.org/www-project-top-10-for-large-language-model-applications/](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

- **NIST AI Risk Management Framework (AI RMF 1.0)**  
  National Institute of Standards and Technology guidelines for managing risks associated with artificial intelligence systems, emphasizing governance, mapping, measurement, and management.  
  - *URL*: [https://www.nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework)

- **MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)**  
  A knowledge base of adversary tactics, techniques, and real-world case studies targeting AI-enabled systems. Key tactics for agents include *LLM Plugin/Tool Abuse* and *Memory Poisoning*.  
  - *URL*: [https://atlas.mitre.org/](https://atlas.mitre.org/)

---

## 2. Academic Research Papers & Security Benchmarks

- **AgentDojo: A Benchmark for Evaluating Robustness of AI Agents against Indirect Prompt Injection** (2024)  
  *Authors*: Debenedetti et al.  
  *Key Finding*: Evaluates commercial and open-source agents against realistic environment injections in tool execution pipelines, demonstrating high vulnerability rates across current LLM architectures.

- **Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection** (2023)  
  *Authors*: Greshake et al.  
  *Key Finding*: The foundational paper demonstrating indirect prompt injection in agentic workflows, email processors, and web-scraping pipelines.

- **Formalizing Agency Boundaries in Multi-Agent Autonomous Systems** (2025)  
  *Key Finding*: Demonstrates how privilege escalation loops emerge in multi-agent mesh networks when supervisor agents lack cryptographic message validation.

---

## 3. Real-World CVE Disclosures in Agent Frameworks

| CVE Identifier | Target Framework | Vulnerability Mechanism | Severity |
|---|---|---|---|
| **CVE-2023-36258** | LangChain | Unsandboxed Python code execution in `PythonREPLTool` leading to RCE | **CRITICAL (9.8)** |
| **CVE-2023-39659** | LangChain | Unsanitized SQL string format in `SQLDatabaseChain` leading to SQLi | **HIGH (8.5)** |
| **CVE-2024-5186** | CrewAI | Inter-agent message spoofing allowing task delegation bypass | **HIGH (8.1)** |
| **CVE-2024-28088** | LlamaIndex | Arbitrary file read via un-sanitized document loader tools | **HIGH (7.5)** |

---

## 4. Open-Source Security Tools & Guardrail Libraries

- **Microsoft PyRIT (Python Risk Identification Tool)**: Automated dynamic red-teaming orchestrator for AI models and multi-step agents.  
  - *Repository*: [https://github.com/Azure/PyRIT](https://github.com/Azure/PyRIT)
- **`garak` (Generative AI Redteam & Assessment Kith)**: Vulnerability scanner for LLM inputs, tool calls, and prompt injection vectors.  
  - *Repository*: [https://github.com/leondz/garak](https://github.com/leondz/garak)
- **NeMo Guardrails (NVIDIA)**: Open-source toolkit for adding programmable guardrails and execution bounds to LLM applications.  
  - *Repository*: [https://github.com/NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
- **Open Policy Agent (OPA)**: Open-source general-purpose policy engine for validating agent tool parameters against REGO rules.  
  - *Documentation*: [https://www.openpolicyagent.org/](https://www.openpolicyagent.org/)
- **AgentOps**: Observability platform offering runtime security tracing, cost monitoring, and action step logging for AI Agents.  
  - *Documentation*: [https://www.agentops.ai/](https://www.agentops.ai/)

---

*[Return to Guide Overview ←](README.md)*
