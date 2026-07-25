---
title: "07. References, Standards & CVE Index"
description: "Authoritative standards, frameworks, academic papers, MITRE ATLAS techniques, OWASP Top 10 for LLM 2025, and real-world CVE records."
keywords: ["AppSec References", "OWASP LLM01:2025", "NIST AI RMF", "MITRE ATLAS", "LLM CVEs", "Prompt Injection Research"]
---

# 07. References, Standards & CVE Index

This document provides an authoritative catalog of security standards, industry frameworks, seminal academic research papers, MITRE ATLAS techniques, and real-world CVE vulnerability records for LLM Prompt Injection and Generative AI Security.

---

## 1. Industry Standards & Frameworks

### A. OWASP Top 10 for LLM Applications (2025 Edition)
* **[LLM01:2025 - Prompt Injection](https://genai.owasp.org/llm-top-10/)**: Primary vulnerability class covering Direct Prompt Injection (Jailbreaking) and Indirect Prompt Injection (Data Poisoning).
* **[LLM02:2025 - Sensitive Information Disclosure](https://genai.owasp.org/llm-top-10/)**: Disclosing sensitive operational PII, system prompt instructions, or internal infrastructure tokens.
* **[LLM07:2025 - System Prompt Leakage](https://genai.owasp.org/llm-top-10/)**: Unauthorized extraction of proprietary prompt directives and embedded operational rules.

### B. NIST Artificial Intelligence Risk Management Framework (AI RMF 1.0)
* **[NIST AI RMF 1.0 (NIST SP 1270)](https://www.nist.gov/itl/ai-risk-management-framework)**: Standardized guidelines for managing risk, safety, transparency, and trustworthiness across machine learning deployments.

### C. MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)
* **[AML.T0051 - LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)**: Direct and indirect injection payload execution against LLM agents.
* **[AML.T0054 - LLM Data Poisoning](https://atlas.mitre.org/techniques/AML.T0054)**: Injecting malicious instructions into training sets, RAG document vector stores, or fine-tuning datasets.

---

## 2. Key Academic & Research Papers

1. **Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection**
   * *Authors*: Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz (2023).
   * *Contribution*: Introduced the formal threat model and taxonomy for Indirect Prompt Injection, demonstrating real-world attacks against search engines, email assistants, and agent workflows.
   * [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)

2. **Universal and Transferable Adversarial Attacks on Aligned Language Models**
   * *Authors*: Andy Zou, Zifan Wang, J. Zico Kolter, Matt Fredrikson (2023).
   * *Contribution*: Discovered automated Greedy Coordinate Gradient (GCG) suffix generation techniques that reliably break safety alignment across commercial LLMs.
   * [arXiv:2307.15043](https://arxiv.org/abs/2307.15043)

3. **Formalizing Indirect Prompt Injection Attacks in Language Model Integrated Applications**
   * *Authors*: Jingwei Yi et al. (2024).
   * *Contribution*: Detailed mathematical modeling of token attention shifts during prompt injection execution in transformer decoders.

---

## 3. Notable Real-World CVEs & Incidents Catalog

| CVE ID / Incident | Vulnerable Component | Attack Vector | Technical Impact |
|---|---|---|---|
| **CVE-2023-43770** | LangChain SQL Database Chain | Indirect Prompt Injection | Remote Code Execution & Arbitrary SQL Execution |
| **CVE-2023-29374** | LangChain Python Exec Tool | Direct Prompt Injection | Arbitrary Python Code Execution |
| **Microsoft Copilot Data Theft (2024)** | Copilot Web / Email Integration | Indirect Injection in Email Body | Automated data exfiltration via rendered Markdown image requests |
| **ChatGPT Plugin Exploits (2023)** | ChatGPT Third-Party Plugin API | Cross-Plugin Prompt Injection (XPIA) | User Chat Session Hijacking & PII Exfiltration |

---

## 4. Open-Source Security Tools & Repositories

* **[garak](https://github.com/leondz/garak)** — Generative AI Red-Teaming & Assessment Kit (`pip install garak`).
* **[PyRIT](https://github.com/Azure/PyRIT)** — Microsoft Python Risk Identification Tool for AI.
* **[promptfoo](https://github.com/promptfoo/promptfoo)** — CLI framework for testing LLM prompts & guardrail security policies.
* **[NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)** — NVIDIA's toolkit for adding programmable guardrails to conversational AI.
* **[Llama-Guard 3](https://huggingface.co/meta-llama/Llama-Guard-3-8B)** — Open weights safety classification model by Meta.

---

*Return to [Module Overview & Index →](README.md)*

