---
title: 07. References & Standards
description: Authoritative standards, benchmark leaderboards, foundational academic
  research papers, and open-source security toolkits for Machine Learning Security.
keywords:
- ML
- Security
- References
- NIST
- AI
- 100-2
- MITRE
- ATLAS
- Adversarial
- Machine
- Learning
- Papers
- RobustBench
- ART
- Framework
- Safetensors
slug: /ai-ml-security/ml-model-security/references
---


# 07. References & Standards

This directory lists authoritative benchmarks, regulatory frameworks, foundational academic literature, and open-source toolkits for Machine Learning Security and Adversarial AI engineering.

---

## 1. Security Standards & Risk Taxonomies

- **[NIST AI 100-2: Trustworthy and Responsible AI](https://csrc.nist.gov/pubs/ai/100/2/e2023/final)** — Official NIST taxonomy of attacks and mitigations in Artificial Intelligence and Machine Learning.
- **[MITRE ATLAS™ (Adversarial Threat Landscape for Artificial Intelligence Systems)](https://atlas.mitre.org/)** — Globally accessible knowledge base of adversary tactics, techniques, and case studies against AI-enabled systems.
- **[OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)** — Community-driven standard identifying the top security vulnerabilities in machine learning deployments.
- **[ISO/IEC 42001:2023 AI Management System](https://www.iso.org/standard/81230.html)** — International management system standard providing requirements for establishing, implementing, and continually improving AI security governance.

---

## 2. Landmark Academic Research Papers

### Adversarial Evasion & Robustness
- **Goodfellow, I. J., Shlens, J., & Szegedy, C. (2014).** *Explaining and Harnessing Adversarial Examples.* arXiv preprint arXiv:1412.6572.  
  *(Introduced the Fast Gradient Sign Method (FGSM) and linear model hypothesis).*
- **Madry, A., Makelov, A., Schmidt, L., Tsipras, D., & Vladu, A. (2017).** *Towards Deep Learning Models Resistant to Adversarial Attacks.* arXiv preprint arXiv:1706.06083.  
  *(Introduced PGD iterative attack and minimax adversarial training formulation).*
- **Carlini, N., & Wagner, D. (2017).** *Towards Evaluating the Robustness of Neural Networks.* IEEE Symposium on Security and Privacy (SP).  
  *(Formulated C&W L2/L_inf optimization attacks bypassing defensive distillation).*

### Data Poisoning & Trojan Backdoors
- **Gu, T., Dolan-Gavitt, B., & Garg, S. (2017).** *BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain.* IEEE Access.  
  *(First paper demonstrating backdoor Trojan trigger injection in neural network weights).*
- **Shafahi, A., Huang, W. R., Najibi, M., Suciu, O., Studer, C., Dumitras, T., & Goldstein, T. (2018).** *Poison Frogs! Clean-Label Backdoor Attacks on Machine Learning.* NeurIPS.  
  *(Demonstrated targeted clean-label feature collision data poisoning without altering training labels).*
- **Tran, B., Li, J., & Madry, A. (2018).** *Spectral Signatures in Backdoor Attacks.* NeurIPS.  
  *(Introduced SVD feature representation filtering to detect and remove backdoor training samples).*

### Model Intellectual Property Theft & Privacy Leakage
- **Tramèr, F., Zhang, F., Juels, A., Reiter, M. K., & Ristenpart, T. (2016).** *Stealing Machine Learning Models via Prediction APIs.* USENIX Security Symposium.  
  *(Pioneered black-box model extraction attacks against commercial prediction APIs).*
- **Shokri, R., Stronati, M., Song, C., & Shmatikov, V. (2017).** *Membership Inference Attacks Against Machine Learning Models.* IEEE Symposium on Security and Privacy (SP).  
  *(Formulated shadow model techniques to infer individual record membership in training sets).*

---

## 3. Open-Source Security Toolkits & Frameworks

| Tool / Repository | Organization | Link | Purpose |
|---|---|---|---|
| **Adversarial Robustness Toolbox (ART)** | Linux Foundation | [GitHub](https://github.com/Trusted-AI/adversarial-robustness-toolbox) | Comprehensive python library for ML security evaluation and defense. |
| **Microsoft Counterfit** | Microsoft Azure | [GitHub](https://github.com/Azure/counterfit) | Automation tool for black-box penetration testing of ML models. |
| **Safetensors** | Hugging Face | [GitHub](https://github.com/huggingface/safetensors) | Safe, zero-copy tensor serialization format replacing unsafe pickle files. |
| **Picklescan** | Hugging Face | [GitHub](https://github.com/huggingface/picklescan) | Security scanner for detecting dangerous opcodes in Python pickle artifacts. |
| **Modelscan** | Protect AI | [GitHub](https://github.com/protectai/modelscan) | Open-source tool for scanning ML model artifacts for code execution risks. |
| **Fickling** | Trail of Bits | [GitHub](https://github.com/trailofbits/fickling) | Decompiler and static analyzer for inspecting Python pickle bytecode. |
| **PyTorch Opacus** | Meta AI | [GitHub](https://github.com/pytorch/opacus) | High-speed library for training PyTorch models with Differential Privacy (DP-SGD). |
| **RobustBench** | Community | [RobustBench Leaderboard](https://robustbench.github.io/) | Standardized benchmark leaderboard for empirical adversarial robustness evaluation. |

---

*Return to [Module Overview & Index →](README.md)*
