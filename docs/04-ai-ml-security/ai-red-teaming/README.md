---
title: "AI Red Teaming & Safety Evaluation Playbook"
description: "Comprehensive guide to AI Red Teaming: methodology, threat modeling with NIST AI 100-2 and MITRE ATLAS, automated evaluation with PyRIT & Garak, multi-turn Crescendo attacks, guardrail stress testing, and defensive engineering."
keywords: ["AI Red Teaming", "LLM Security", "PyRIT", "Garak", "MITRE ATLAS", "NIST AI 100-2", "Guardrail Stress Testing", "Prompt Injection", "Crescendo Attack", "AppSec Atlas"]
---

# AI Red Teaming & Safety Evaluation Playbook

> **Section:** 🤖 AI/ML Security  
> **Level:** Advanced  
> **Time to Complete:** ~90 minutes  
> **Prerequisites:** Python 3.10+, basic LLM architecture knowledge (Transformers, REST APIs), familiarity with security assessment methodologies  
> **Status:** ✅ Production-Ready & Verified

---

## 🎯 Overview & Learning Objectives

**AI Red Teaming** is the discipline of systematically probing, evaluating, and stress-testing Generative AI models, Retrieval-Augmented Generation (RAG) pipelines, and Autonomous Agent systems to discover safety failures, security vulnerabilities, prompt injection flaws, and guardrail bypasses before deployment.

Unlike traditional application penetration testing—which searches for deterministic code execution flaws (e.g., SQL injection, buffer overflows)—AI Red Teaming targets **probabilistic, semi-autonomous neural systems** where behavior is non-deterministic, inputs are natural language, and threat vectors emerge from latent space geometry and context manipulation.

By completing this practical playbook, you will be able to:

- [x] **Formalize** AI Red Teaming methodologies using industry frameworks (**NIST AI 100-2 / AI RMF 1.0**, **MITRE ATLAS™**, and **ISO/IEC 42001**).
- [x] **Analyze** complex attack mechanics including **Crescendo multi-turn attacks**, **PAIR (Prompt Automatic Iterative Refinement)**, **Tree of Attacks (TAP)**, and **Indirect Visual/RAG Prompt Injections**.
- [x] **Execute** automated vulnerability discovery using leading open-source tools: **Microsoft PyRIT**, **garak**, **UK AISI Inspect AI**, and **Promptfoo**.
- [x] **Stress-Test & Benchmark** production guardrails like Meta **Llama-Guard-3**, NVIDIA **NeMo Guardrails**, and custom LLM-as-a-Judge evaluators under adversarial conditions.
- [x] **Implement** production-grade defense-in-depth patterns, including Dual-LLM architecture, input/output filter chains, XML boundary tags, and tool execution sandboxing.
- [x] **Run & Solve** a complete end-to-end Python vulnerability evaluation lab featuring a vulnerable AI agent, automated exploit harness, and verified secure remediation.

---

## 🗺️ Framework & Taxonomy Mapping

AI Red Teaming aligns across established security standards:

| Framework / Standard | Scope & Focus in AI Red Teaming |
| :--- | :--- |
| **MITRE ATLAS™** | Maps adversarial tactics & techniques (`AML.T0051` Prompt Injection, `AML.T0054` RAG Poisoning, `AML.T0055` Guardrail Evasion). |
| **NIST AI 100-2 / RMF 1.0** | Establishes Map, Measure, Manage, Govern workflows for trustworthiness and risk mitigation. |
| **OWASP Top 10 for LLMs (2025)** | Focuses on top risks: LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM05 (Improper Control Flow / Agent Hijacking), LLM07 (System Prompt Leakage). |
| **ISO/IEC 42001** | Provides requirements for auditing AI Management Systems (AIMS) and operational safety controls. |

---

## 📚 Module Navigation

1. **[01. Overview & AI Red Teaming Methodology](01-introduction.md)** — Core principles, traditional pentesting vs. AI Red Teaming, NIST AI 100-2 / MITRE ATLAS alignment, threat modeling AI architectures, and rules of engagement.
2. **[02. Core Concepts & Attack Mechanics](02-core-concepts.md)** — Technical deep dive into direct/indirect prompt injection, multi-turn Crescendo attacks, PAIR/TAP automated optimization, token smuggling, and attention hijacking.
3. **[03. Attack Scenarios & Multi-Turn PoCs](03-code-examples.md)** — Runnable attack proof-of-concept audit scripts in **Python**, **Node.js/TypeScript**, **Go**, and **Java**, with side-by-side vulnerable vs. secure code comparisons.
4. **[04. Guardrail Architecture & Mitigations](04-defenses.md)** — Defense-in-depth mitigations, Llama-Guard-3 deployment, NeMo Guardrails configuration, Dual-LLM validation pattern, and mathematical guardrail benchmark metrics.
5. **[05. Security Testing & Tooling Automation](05-tools.md)** — Enterprise setup and CLI workflows for Microsoft PyRIT, garak, Inspect AI, Promptfoo, and automated CI/CD security pipelines with GitHub Actions.
6. **[06. Hands-On Red Teaming Lab](06-labs.md)** — Self-contained, runnable local Python lab: Vulnerable Customer Support Agent, Automated Attack Audit Harness, Hardened Guardrail Patch, and Verification Suite.
7. **[07. References & Standards](07-references.md)** — Academic research papers, benchmark datasets, official standard links, CVE index, and tool repositories.

---

*Begin reading: [01. Overview & AI Red Teaming Methodology →](01-introduction.md)*
