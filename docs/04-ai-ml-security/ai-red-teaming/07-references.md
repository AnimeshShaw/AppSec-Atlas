---
title: "07. References & Standards"
description: "Authoritative academic research papers, industry standards (NIST AI 100-2, MITRE ATLAS, OWASP Top 10 for LLMs), security frameworks, and open-source AI Red Teaming tools."
keywords: ["NIST AI 100-2", "MITRE ATLAS", "OWASP LLM Top 10", "AI Security Research", "PyRIT", "garak", "AI Red Teaming References", "AppSec Atlas"]
---

# 07. References & Standards

This chapter provides an exhaustive index of academic research papers, technical standards, threat taxonomies, and open-source tooling repositories for **AI Red Teaming** and **Generative AI Safety Evaluation**.

---

## 1. Industry Standards & Frameworks

- **[NIST AI 100-2: Eliciting AI Risk Concepts and Terminology](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)** — National Institute of Standards and Technology official guidelines for AI Red Teaming, risk taxonomies, and model safety evaluations.
- **[NIST AI Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/itl/ai-risk-management-framework)** — Core framework defining the Map, Measure, Manage, and Govern functions for AI system trustworthiness.
- **[MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)](https://atlas.mitre.org/)** — Industry-standard matrix of tactics, techniques, and real-world case studies for attacks on AI systems.
- **[OWASP Top 10 for Large Language Model Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** — Top 10 security risks in LLM applications, including LLM01 (Prompt Injection), LLM02 (Sensitive Info Disclosure), LLM05 (Improper Control Flow), and LLM07 (System Prompt Leakage).
- **[ISO/IEC 42001: Information Technology — Artificial Intelligence — Management System (AIMS)](https://www.iso.org/standard/81230.html)** — International standard providing requirements for establishing, implementing, and maintaining AI management systems.

---

## 2. Landmark Academic Research Papers

- **Zou, A., Wang, Z., Kolter, J. Z., & Fredrikson, M. (2023).** *Universal and Transferable Adversarial Attacks on Aligned Language Models.* arXiv preprint arXiv:2307.15043.
  - *Focus*: Introduces the **Greedy Coordinate Gradient (GCG)** algorithm for generating white-box token suffixes that reliably bypass model alignment.
- **Russinovich, M., et al. (2024).** *Great-Readability Jailbreak: The Crescendo Multi-turn Attack Pattern.* Microsoft Research & Security AI.
  - *Focus*: Documents the **Crescendo Attack** mechanics, illustrating how multi-turn context accumulation shifts model safety alignment across turns.
- **Chao, P., Robey, A., Dobriban, E., Hassani, H., Pappas, G. J., & Wong, E. (2023).** *Jailbreaking Black-Box Large Language Models in Twenty Queries (PAIR).* arXiv preprint arXiv:2310.08419.
  - *Focus*: Proposes **Prompt Automatic Iterative Refinement (PAIR)** using an attacker-model loop to discover jailbreak prompts automatically.
- **Mehrotra, A., Zampaglione, M., Dai, K., et al. (2023).** *Tree of Attacks: Jailbreaking Black-Box LLMs Automatically (TAP).* arXiv preprint arXiv:2312.02119.
  - *Focus*: Introduces **TAP**, combining tree-search prompt variations with automated branch pruning for efficient black-box red teaming.
- **Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023).** *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* ACM Workshop on Privacy in the Electronic Society (WPES).
  - *Focus*: First comprehensive study of **Indirect Prompt Injection** vectors in RAG pipelines, email agents, and search engines.

---

## 3. Open-Source AI Red Teaming & Safety Tools

- **[Microsoft PyRIT (Python Risk Identification Tool for AI)](https://github.com/Azure/PyRIT)** — Enterprise Python framework for orchestrating automated multi-turn AI risk evaluations.
- **[garak: Generative AI Red-teaming & Assessment Kit](https://github.com/leondz/garak)** — High-throughput command-line scanner for detecting prompt injections, system prompt leaks, and hallucination bugs.
- **[UK AISI Inspect AI Framework](https://github.com/UKGovernmentBEIS/inspect_ai)** — Open-source evaluation platform developed by the UK AI Safety Institute for systematic model testing.
- **[Promptfoo CLI & Assertions](https://github.com/promptfoo/promptfoo)** — Developer-first CLI tool for writing automated YAML assertions and matrix tests for LLM security in CI/CD pipelines.
- **[Meta Llama-Guard-3 Repository](https://github.com/meta-llama/llama-models)** — Foundation model guardrail for classifying input/output safety hazards.
- **[NVIDIA NeMo Guardrails Framework](https://github.com/NVIDIA/NeMo-Guardrails)** — Programmatic guardrail toolkit for defining Colang dialogue rails and safety policies.

---

## 4. Adversarial Datasets & Benchmark Suites

- **[HarmBench](https://github.com/centerforaisafety/HarmBench)** — Standardized benchmark suite for automated LLM red teaming and safety evaluation.
- **[AdvGLUE (Adversarial GLUE)](https://advglue.dataset.org/)** — Multi-task adversarial benchmark evaluating model robustness against textual perturbations.
- **[Do-Not-Answer Dataset](https://github.com/LibrAI/do-not-answer)** — Open-source dataset of prompts designed to measure model refusal performance across harmful categories.

---

*Return to [AI Red Teaming Playbook Overview & Navigation →](README.md)*
