# 01. Overview & AI Red Teaming Methodology

AI Red Teaming differs fundamentally from traditional web penetration testing. While software pentesting looks for deterministic bugs (e.g., SQL injection, memory corruption), AI Red Teaming evaluates **probabilistic systems** for unexpected behaviors, safety failures, and prompt injection vulnerabilities.

---

## 1. AI Red Teaming Lifecycle (NIST AI 100-2 / MITRE ATLAS)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AI Red Teaming Audit Workflow                         │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ 1. Threat Model │ Map model capabilities, system prompts, vector DBs, tools │
│ 2. Scoping      │ Define safety boundaries, compliance rules, guardrail goals│
│ 3. Automated Probe│ Run Garak / PyRIT scanners against candidate model      │
│ 4. Manual Audit │ Conduct multi-turn contextual dialogue audits             │
│ 5. Remediation  │ Implement Llama-Guard / NeMo Guardrails & fine-tuning     │
└─────────────────┴───────────────────────────────────────────────────────────┘
```

---

## 2. MITRE ATLAS™ Framework Alignment

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) maps tactics used by security researchers and auditors:

- **AML.T0051 (Prompt Injection)**: Testing whether user inputs hijack system behavior.
- **AML.T0054 (LLM Data Poisoning)**: Auditing RAG vector stores for untrusted data contamination.
- **AML.T0055 (Evasion & Guardrail Bypass)**: Testing content moderation filters against encoded inputs.

---

*Next Chapter: [02. Automated Security Frameworks (PyRIT & Garak) →](02-red-teaming-frameworks.md)*
