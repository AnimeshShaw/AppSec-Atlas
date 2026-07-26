---
title: 01. Overview & AI Red Teaming Methodology
description: 'Theoretical foundation of AI Red Teaming: comparing traditional software
  pentesting with probabilistic model auditing, NIST AI 100-2 / MITRE ATLAS framework
  alignment, threat modeling AI architectures, and establishing safe audit scope.'
keywords:
- AI
- Red
- Teaming
- NIST
- AI
- 100-2
- MITRE
- ATLAS
- AI
- Threat
- Modeling
- LLM
- Security
- Probabilistic
- Security
- AppSec
- Atlas
slug: /ai-ml-security/ai-red-teaming/introduction
---


# 01. Overview & AI Red Teaming Methodology

Traditional application security testing relies on **deterministic analysis**. In standard software pentesting, a specific input (such as `' OR '1'='1`) fed to a vulnerable SQL query consistently yields the same outcome. The software state is discrete, traceable through control-flow graphs, and patchable with static sanitization rules.

**AI Red Teaming** breaks this paradigm. Large Language Models (LLMs), Retrieval-Augmented Generation (RAG) pipelines, and Autonomous AI Agents operate on **probabilistic latent spaces**. The output is a stochastic function of input tokens, system instructions, context window state, temperature sampling, and model weights. Consequently, security evaluation of AI systems requires non-deterministic threat modeling, continuous statistical probing, and systematic safety boundary verification.

---

## 1. Traditional Pentesting vs. AI Red Teaming

Understanding the operational differences between software vulnerability assessments and AI red teaming is critical for building effective security audit programs:

| Security Dimension | Traditional Application Pentesting | AI Red Teaming & Safety Evaluation |
| :--- | :--- | :--- |
| **System Behavior** | **Deterministic**: Code paths follow static Boolean logic. | **Probabilistic**: Outputs rely on softmax probabilities and sampling parameters (`temperature`, `top_p`). |
| **Attack Surface** | Fixed API endpoints, SQL queries, memory structures, authentication headers. | High-dimensional token embedding spaces, system prompts, RAG vector stores, dynamic tool-calling interfaces. |
| **Root Cause of Flaws** | Syntax parsing errors, missing input validation, memory allocation bugs. | Alignment drift, context window contamination, semantic instruction conflict, attention hijacking. |
| **Test Methodology** | Fuzzing, static code analysis (SAST), dynamic vulnerability scanning (DAST). | Automated adversarial prompt generation, multi-turn dialogue state probing, guardrail benchmark auditing. |
| **Remediation Model** | Code patches, parameterization, strict schema validation. | Guardrail filtering, fine-tuning (RLHF/DPO), prompt boundary isolation, agent permission scoping. |
| **Failure Modes** | Crashes, unauthorized data access, privilege escalation. | System prompt extraction, jailbreaks, indirect injection via external data, unauthorized function invocation. |

---

## 2. Industry Frameworks & Standards Alignment

AI Red Teaming methodologies must be structured around established industry standards to ensure repeatable, quantifiable, and auditable outcomes.

```
+-----------------------------------------------------------------------------------+
|                        AI Red Teaming Standards Ecosystem                         |
+-----------------------------------------------------------------------------------+
|  NIST AI 100-2 / AI RMF  --> Map, Measure, Manage, Govern AI Vulnerabilities       |
|  MITRE ATLAS              --> Matrix of Tactics, Techniques & Threat Vectors      |
|  OWASP Top 10 for LLMs    --> Categorization of Critical LLM Vulnerabilities       |
|  ISO/IEC 42001 (AIMS)     --> Management System Auditing & Safety Governance      |
+-----------------------------------------------------------------------------------+
```

### 2.1 NIST AI 100-2 & AI Risk Management Framework (RMF 1.0)
The National Institute of Standards and Technology (NIST) defines AI Red Teaming within **NIST AI 100-2** (*Eliciting AI Risk Concepts and Terminology*) and the **NIST AI RMF 1.0**. The framework establishes four core functions:

1. **MAP**: Identify AI system context, underlying foundation models, training data sources, tool integrations, and operational user personas.
2. **MEASURE**: Quantify risk using standardized metrics (e.g., Attack Success Rate `ASR`, False Positive Rate `FPR` of guardrails, token manipulation distance).
3. **MANAGE**: Implement technical controls, guardrail filters, system prompt boundary enforcement, and agent fallback mechanisms.
4. **GOVERN**: Establish organizational policies, audit schedules, ethical boundary definitions, and continuous safety monitoring.

### 2.2 MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)
MITRE ATLAS provides an industry-standard matrix of tactics and techniques derived from real-world AI security research. Key technique mappings evaluated during red teaming include:

```
[Resource Development] --> [Initial Access] ---------> [Execution] -------------> [Exfiltration]
 (Crafting Adversarial)     (Prompt Injection)         (Unauthorized Tool Call)    (Data Extraction via
  Prompts / Datasets)      (AML.T0051 / LLM01)        (AML.T0055 / LLM05)         Indirect Injection)
```

- **`AML.T0051` (LLM Prompt Injection)**: Manipulating user or contextual inputs to overwrite system instructions.
- **`AML.T0054` (LLM Data Poisoning)**: Injecting malicious payloads into RAG repositories or fine-tuning datasets to manipulate future retrieval.
- **`AML.T0055` (LLM Guardrail Evasion)**: Utilizing obfuscation, translation, or multi-turn conversational framing to bypass safety filters.
- **`AML.T0057` (LLM System Prompt Extraction)**: Tricking the model into dumping hidden context, system instructions, or internal API keys.

---

## 3. Threat Modeling AI Architectures

Before conducting audit probes, an AI Red Teamer must construct a comprehensive threat model of the target AI application.

### 3.1 AI System Architecture Topology

```
                                  +---------------------------------------+
                                  |           User Interface              |
                                  +---------------------------------------+
                                                      |
                                           User Input | Direct Probe
                                                      v
                                  +---------------------------------------+
                                  |        Input Guardrail Layer          |
                                  |    (Llama-Guard / Regex / Classifier) |
                                  +---------------------------------------+
                                                      |
                                            Filtered  | Input
                                                      v
                                  +---------------------------------------+
                                  |         Orchestrator / Agent          |
                                  |     (LangChain / AutoGen / Custom)    |
                                  +---------------------------------------+
                                     /                |                \
                     Context Fetch  /                 |                 \ Invocation
                                   v                  v                  v
                 +-------------------+      +------------------+     +-------------------+
                 | RAG Vector DB     |      | Foundation Model |     | External Tools /  |
                 | (Chroma / Pinecone|      | (GPT-4o / Llama) |     | APIs & Databases  |
                 +-------------------+      +------------------+     +-------------------+
                                                      |
                                            Raw Model | Output
                                                      v
                                  +---------------------------------------+
                                  |        Output Guardrail Layer         |
                                  |   (PII Filter / Secret Sanitizer)     |
                                  +---------------------------------------+
                                                      |
                                             Final    | Response
                                                      v
                                  +---------------------------------------+
                                  |             User / Client             |
                                  +---------------------------------------+
```

### 3.2 Vulnerability Entry Points (VEEs)

1. **Direct User Input Channel**: User-facing chat interface or API endpoints where malicious inputs can be injected directly into the LLM context window.
2. **Indirect Retrieval Channel (RAG)**: Ingestion of untrusted web pages, PDF documents, emails, or database records containing hidden adversarial instructions.
3. **System Context & History Channel**: Long-running multi-turn dialogue buffers where context accumulation can drift model alignment.
4. **Tool & Agent Execution Boundaries**: LLM function-calling capabilities that may execute unauthorized database queries, HTTP requests, or shell commands if manipulated.

---

## 4. Operational Rules of Engagement (RoE) for AI Audits

Executing an AI Red Team engagement requires strict operational controls to prevent accidental system degradation, data corruption, or policy violations.

1. **Environment Isolation**: Perform probes against dedicated staging environments with synthetic or anonymized datasets. Never test directly against production vector stores containing real PII.
2. **Rate Limiting & Cost Controls**: Set strict API concurrency limits and budget controls (e.g., maximum daily API spend caps) to avoid denial-of-wallet scenarios during automated fuzzing.
3. **Logging & Tracing**: Capture full request/response pairs, system prompts, guardrail flags, temperature settings, and model versions for complete audit auditability.
4. **Responsible Disclosure**: Standardize scoring using **CVSS for AI** or **OWASP Risk Rating Methodology** to prioritize remediation before public release.

---

*Next Chapter: [02. Core Concepts & Attack Mechanics →](02-core-concepts.md)*
