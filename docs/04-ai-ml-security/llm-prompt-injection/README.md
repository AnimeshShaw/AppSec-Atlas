---
title: "LLM Security & Prompt Injection Guide"
description: "Prompt Injection is the **#1 vulnerability in Large Language Model (LLM) applications** (OWASP LLM01:2025). It occurs when an attacker manipulates the..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Llm Prompt Injection", "Readme.Md"]
---

# LLM Security & Prompt Injection Guide

> **Section:** 🤖 AI/ML Security  
> **Level:** Intermediate to Advanced  
> **Time to Complete:** ~60 minutes  
> **Prerequisites:** Basic Python, understanding of REST APIs / OpenAI SDK, basic web security concepts  
> **Status:** ✅ Complete & Production-Ready

---

## 🎯 Overview & Learning Objectives

Prompt Injection is the **#1 vulnerability in Large Language Model (LLM) applications** (OWASP LLM01:2025). It occurs when an attacker manipulates the input prompt to alter the model's intended control flow, bypass safety guardrails, extract system instructions, or trick the model into executing unauthorized actions via function/tool calling.

By the end of this practical guide, you will be able to:
- [x] **Understand** the core mechanics of Direct, Indirect, and Multimodal Prompt Injection.
- [x] **Execute** safe, controlled proof-of-concept attacks against vulnerable LLM implementations.
- [x] **Extract** system prompts and demonstrate data exfiltration via indirect injections.
- [x] **Implement** robust defense-in-depth patterns (Dual-LLM architecture, input/output validation, system prompt hardening, guardrail integration).
- [x] **Automate** LLM security testing using tools like `garak` and Microsoft `PyRIT`.
- [x] **Run & Solve** a hands-on local Python/Docker lab vulnerability challenge.

---

## 📚 Module Navigation

1. **[01. Introduction to Prompt Injection](01-introduction.md)** — Core definitions, attack vector classification (Direct vs. Indirect vs. Multimodal).
2. **[02. Core Mechanics & Architecture](02-core-concepts.md)** — Tokenizer mechanics, attention hijacking, prompt framing, and system/user message boundary breakdown.
3. **[03. Practical Attack Scenarios](03-attack-scenarios.md)** — Step-by-step PoCs with code: Direct Injection, Indirect Injection via RAG/Web, System Prompt Extraction, and Data Exfiltration.
4. **[04. Defense-in-Depth & Mitigations](04-defenses.md)** — Practical defenses with full code: Dual-LLM pattern, Input/Output Guardrails, System Prompt Hardening, and Tool-Calling Sandboxing.
5. **[05. Security Testing & Red Teaming Tools](05-tools.md)** — Hands-on guide to testing LLM apps with `garak`, `PyRIT`, `Llama-Guard`, and `NeMo Guardrails`.
6. **[06. Hands-On Vulnerability Lab](06-labs.md)** — Self-contained Python lab: Vulnerable App + Exploit Script + Secure Remediation code.
7. **[07. References & Standards](07-references.md)** — Real-world CVEs, OWASP Top 10 for LLMs, academic research papers.

---

*Begin reading: [01. Introduction to Prompt Injection →](01-introduction.md)*
