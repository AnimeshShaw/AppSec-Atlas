---
title: "07. References & Standards"
description: "This document provides authoritative references, standards, academic papers, CVE records, and open-source tooling references for LLM Prompt Injection ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Llm Prompt Injection", "07 References.Md"]
---

# 07. References & Standards

This document provides authoritative references, standards, academic papers, CVE records, and open-source tooling references for LLM Prompt Injection and AI Security.

---

## 1. Industry Standards & Frameworks

- **[OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)**
  - **LLM01:2025 - Prompt Injection**: The primary risk category covering Direct (Jailbreak) and Indirect Prompt Injection.
  - **LLM02:2025 - Sensitive Information Disclosure**: Unintended leakage of secrets or PII via prompts.
  - **LLM07:2025 - System Prompt Leakage**: Extraction of internal system instructions.
- **[NIST Artificial Intelligence Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/itl/ai-risk-management-framework)**
  - Framework for managing risks, trustworthiness, and safety standards in AI systems.
- **[MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)](https://atlas.mitre.org/)**
  - Knowledge base of adversary tactics and techniques against AI systems (analogous to MITRE ATT&CK®).
  - **AML.T0051**: LLM Prompt Injection.
  - **AML.T0054**: LLM Data Poisoning.

---

## 2. Key Academic & Research Papers

1. **Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection**
   - *Authors*: Greshake et al. (2023)
   - *Key Contribution*: Pioneered the formal taxonomy and real-world attack demonstration of Indirect Prompt Injection against Bing Chat and LLM agents.
   - [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)

2. **Universal and Transferable Adversarial Attacks on Aligned Language Models**
   - *Authors*: Zou et al. (2023)
   - *Key Contribution*: Discovered automated suffix search attacks (GCG attack) that reliably bypass safety alignment across open and closed LLMs.
   - [arXiv:2307.15043](https://arxiv.org/abs/2307.15043)

3. **Formalizing Indirect Prompt Injection Attacks in Language Model Integrated Applications**
   - *Authors*: Yi et al. (2024)
   - *Key Contribution*: Mathematical model of attention redirection in transformer architectures during injection payload processing.

---

## 3. Notable CVEs & Real-World Incidents

| CVE / Target | Description | Impact |
|---|---|---|
| **CVE-2023-43770** (LangChain) | Indirect Prompt Injection allowing arbitrary code execution via SQL Chain tool | Remote Code Execution / Data Theft |
| **Microsoft Copilot Exfiltration (2024)** | Indirect injection via email content causing automatic data exfiltration via image rendering | Unauthorized Data Leakage |
| **ChatGPT Plugin Injections (2023)** | Malicious third-party plugins reading chat histories via prompt injection payloads | Session Data Exposure |

---

## 4. Open-Source Tools & Repositories

- **[garak](https://github.com/leondz/garak)** — Generative AI Red-teaming & Assessment Kit.
- **[PyRIT](https://github.com/Azure/PyRIT)** — Microsoft Python Risk Identification Tool for AI.
- **[NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)** — NVIDIA's toolkit for adding programmable guardrails to LLM applications.
- **[Llama-Guard](https://huggingface.co/meta-llama/Llama-Guard-3-8B)** — Open weights safety classification model by Meta.

---

*Return to [Module Overview & Index →](README.md)*
