# AI Red Teaming Playbook

> **Section:** 🤖 AI/ML Security  
> **Level:** Advanced  
> **Time to Complete:** ~85 minutes  
> **Prerequisites:** Python 3.10+, basic LLM architecture knowledge, PyRIT / Garak installation  
> **Status:** ✅ Complete & Production-Ready

---

## 🎯 Overview & Learning Objectives

AI Red Teaming is the practice of systematically evaluating Generative AI models, RAG pipelines, and Autonomous Agent systems for safety vulnerabilities, prompt injection susceptibility, guardrail bypasses, and unexpected behaviors.

By the end of this practical guide, you will be able to:
- [x] **Understand** the AI Red Teaming lifecycle per NIST AI 100-2 and MITRE ATLAS framework.
- [x] **Deploy** Microsoft `PyRIT` (Python Risk Identification Tool for AI) and `garak` for automated security scanning.
- [x] **Evaluate** multi-turn conversational guardrails against automated probing frameworks.
- [x] **Stress-Test** Llama-Guard-3 and NeMo Guardrails under adversarial conditions.
- [x] **Build** a custom automated AI security evaluation pipeline in Python.

---

## 📚 Module Navigation

1. **[01. Overview & AI Red Teaming Methodology](01-introduction.md)** — AI Red Teaming vs traditional pentesting, MITRE ATLAS framework, and NIST AI 100-2 guidelines.
2. **[02. Automated Security Frameworks (PyRIT & Garak)](02-red-teaming-frameworks.md)** — Setting up Microsoft PyRIT, `garak`, and UK AISI `Inspect AI` for automated vulnerability discovery.
3. **[03. Multi-Turn Conversational Evaluations](03-multi-turn-evaluations.md)** — Multi-turn dialogue evaluation, context accumulation testing, and Crescendo evaluation strategies.
4. **[04. Guardrail Stress Testing & Benchmark Audits](04-guardrail-stress-testing.md)** — Evaluating Llama-Guard-3, NeMo Guardrails, and custom input/output filters under adversarial testing.
5. **[05. Hands-On Evaluation Lab](05-hands-on-lab.md)** — Self-contained Python Lab: Automated AI Security Audit Harness + Target Agent + Guardrail Fix.
6. **[06. References & Standards](06-references.md)** — NIST AI RMF 1.0, MITRE ATLAS taxonomy, Microsoft AI Red Team documentation.

---

*Begin reading: [01. Overview & AI Red Teaming Methodology →](01-introduction.md)*
