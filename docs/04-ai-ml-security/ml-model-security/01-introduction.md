---
title: "01. Overview & Adversarial ML Threat Landscape"
description: "Machine Learning models operate under different security assumptions than classical software. Rather than exploiting syntax errors, ML threats exploit..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Ml Model Security", "01 Introduction.Md"]
---

# 01. Overview & Adversarial ML Threat Landscape

Machine Learning models operate under different security assumptions than classical software. Rather than exploiting syntax errors, ML threats exploit the continuous mathematical spaces of high-dimensional neural network decision boundaries.

---

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## 1. Adversarial ML Threat Matrix (NIST AI 100-2)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Adversarial ML Threat Matrix                          │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ Data Poisoning  │ Contaminating training datasets to inject backdoors/errors│
│ Model Evasion   │ Crafting imperceptible input perturbations to bypass model│
│ Model Extraction│ Reconstructing model architecture/weights via API queries │
│ Inversion       │ Reconstructing sensitive training set data from outputs   │
└─────────────────┴───────────────────────────────────────────────────────────┘
```

---

## 2. Training Time vs Inference Time Threats

- **Training Time (Poisoning)**: Occurs before model deployment. Attackers control a subset of training samples to insert hidden triggers (Trojan models).
- **Inference Time (Evasion & Inversion)**: Occurs on live deployed models. Attackers manipulate test inputs or analyze prediction probabilities without access to training data.

---

*Next Chapter: [02. Adversarial Input Robustness & Sensitivity →](02-adversarial-robustness-evaluations.md)*
