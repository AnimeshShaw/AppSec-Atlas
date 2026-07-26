---
title: 07 - References & Further Reading
description: Comprehensive references, academic papers, OWASP standards, MITRE ATLAS
  framework, vendor security guides, and open-source evaluation tools for RAG security.
keywords:
- RAG
- Security
- References
- OWASP
- LLM
- Top
- '10'
- MITRE
- ATLAS
- NIST
- AI
- RMF
- Indirect
- Prompt
- Injection
- Papers
- AppSec
slug: /ai-ml-security/rag-security/references
---


# 07 - References & Further Reading

This chapter provides a curated list of academic literature, security standards, industry frameworks, vendor security guides, and automated red-teaming tools relevant to **Retrieval-Augmented Generation (RAG) Security**.

---

## 1. Academic Papers & Landmark Research

1. **Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection**
   - *Authors:* Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz (2023).
   - *Description:* The foundational research paper introducing indirect prompt injection, demonstrating control flow hijacking and data exfiltration across real-world LLM applications.
   - *Link:* [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)

2. **Poisoning Language Models During Instruction Tuning**
   - *Authors:* Alexander Wan, Eric Wallace, Sheng Shen, Dan Klein (2023).
   - *Description:* Demonstrates how poisoning a tiny fraction of data can introduce backdoors and force model completions under targeted trigger phrases.
   - *Link:* [arXiv:2305.02949](https://arxiv.org/abs/2305.02949)

3. **Abusing Images and Audio for Indirect Prompt Injection Attacks on Multimodal Models**
   - *Authors:* Eugene Bagdasaryan, Vitaly Shmatikov (2023).
   - *Description:* Analyzes how indirect prompt injection extends to multimodal inputs (images, audio transcripts) fed into retrieval pipelines.
   - *Link:* [arXiv:2307.10490](https://arxiv.org/abs/2307.10490)

4. **Prompt Injection Attacks and Defenses in LLM-Integrated Applications: A Survey**
   - *Authors:* Yupei Liu et al. (2024).
   - *Description:* Comprehensive survey of direct/indirect prompt injections, payload obfuscation, and defensive sanitization architectures.
   - *Link:* [arXiv:2402.08316](https://arxiv.org/abs/2402.08316)

---

## 2. Industry Standards & Threat Frameworks

- **OWASP Top 10 for Large Language Model Applications**
  - *OWASP Foundation (2025/2023)*
  - Key Categories: `LLM01: Prompt Injection`, `LLM02: Sensitive Information Disclosure`, `LLM03: Supply Chain Risks & Data Poisoning`, `LLM06: Excessive Agency`, `LLM08: Vector and Embedding Weaknesses`.
  - *Link:* [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

- **MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)**
  - *MITRE Corporation*
  - Key Matrix Techniques: `AML.T0051: LLM Prompt Injection`, `AML.T0054: LLM Data Poisoning`, `AML.T0057: LLM Data Exfiltration`.
  - *Link:* [MITRE ATLAS Framework](https://atlas.mitre.org/)

- **NIST Artificial Intelligence Risk Management Framework (AI RMF 1.0)**
  - *National Institute of Standards and Technology (NIST)*
  - Provides guidelines for managing risks associated with trustworthiness, safety, and security of generative AI systems.
  - *Link:* [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)

- **ISO/IEC 42001:2023 Information Technology — Artificial Intelligence — Management System**
  - *International Organization for Standardization (ISO)*
  - Standard specifying requirements for establishing, implementing, maintaining, and continually improving an Artificial Intelligence Management System (AIMS).
  - *Link:* [ISO/IEC 42001](https://www.iso.org/standard/81230.html)

---

## 3. Vector Database Security & Multi-Tenancy Documentation

- **Pinecone Security & Multi-Tenancy Guide**
  - Best practices for namespace isolation and metadata filtering in Pinecone vector indexes.
  - *Link:* [Pinecone Multi-Tenancy Docs](https://docs.pinecone.io/guides/data/namespaces)

- **Qdrant Filtering & Security Architecture**
  - Setting up tenant payload indexes, ACL rules, and isolated vector collections in Qdrant.
  - *Link:* [Qdrant Security & Filtering](https://qdrant.tech/documentation/concepts/filtering/)

- **PostgreSQL `pgvector` Row-Level Security**
  - Integrating native PostgreSQL RLS policies with vector distance search.
  - *Link:* [pgvector GitHub & Documentation](https://github.com/pgvector/pgvector)

- **Milvus Multi-Tenancy & Authorization Rules**
  - Designing partition-based and role-based multi-tenancy in enterprise Milvus deployments.
  - *Link:* [Milvus Multi-Tenancy Architecture](https://milvus.io/docs/multi_tenancy)

---

## 4. Open-Source Security Tooling & Evaluation Frameworks

- **Garak (LLM Vulnerability Scanner)**
  - Open-source vulnerability scanner probing LLMs for prompt injections, hallucination, and exfiltration.
  - *Link:* [Garak GitHub Repository](https://github.com/leondz/garak)

- **PyRIT (Python Risk Identification Tool for AI)**
  - Microsoft's open-source automated red-teaming framework for AI system security.
  - *Link:* [PyRIT GitHub Repository](https://github.com/Azure/PyRIT)

- **Ragas (RAG Evaluation Framework)**
  - Framework for evaluating RAG pipelines on faithfulness, answer relevance, and context toxicity.
  - *Link:* [Ragas Evaluation Docs](https://docs.ragas.io/)

- **NVIDIA NeMo Guardrails**
  - Open-source toolkit for adding programmable guardrails to LLM conversational systems.
  - *Link:* [NVIDIA NeMo Guardrails GitHub](https://github.com/NVIDIA/NeMo-Guardrails)

- **Promptfoo Security Test Runner**
  - CLI and library for evaluating LLM outputs, red-teaming, and CI/CD prompt assertion testing.
  - *Link:* [Promptfoo Official Documentation](https://www.promptfoo.dev/)
