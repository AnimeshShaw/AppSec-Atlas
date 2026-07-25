---
title: "04. Model Intellectual Property & Extraction Defense"
description: "Model extraction (stealing) occurs when an adversary queries an ML inference API repeatedly to train a surrogate model that mirrors the proprietary mo..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Ml Model Security", "04 Model Intellectual Property Protection.Md"]
---

# 04. Model Intellectual Property & Extraction Defense

Model extraction (stealing) occurs when an adversary queries an ML inference API repeatedly to train a surrogate model that mirrors the proprietary model's behavior.

---

## 1. Defending Against Model Extraction

1. **Prediction Truncation**: Return top-1 class labels or rounded probabilities rather than full floating-point softmax probability vectors.
2. **Query Rate Limiting**: Limit API requests per user/IP using sliding window rate limiters.
3. **Differential Privacy**: Add calibrated noise to output probabilities to prevent exact surrogate reconstruction.

### Python Prediction Truncation Wrapper
```python
# secure_inference.py
import numpy as np

def secure_predict_api(raw_probabilities: np.ndarray) -> dict:
    top_class = int(np.argmax(raw_probabilities))
    top_prob = float(np.max(raw_probabilities))
    
    # Round probability to 2 decimal places to prevent exact loss estimation
    rounded_prob = round(top_prob, 2)
    
    return {
        "class_id": top_class,
        "confidence": rounded_prob
    }
```

---

*Next Chapter: [05. Automated ML Auditing with ART →](05-ml-security-tooling-and-art.md)*
