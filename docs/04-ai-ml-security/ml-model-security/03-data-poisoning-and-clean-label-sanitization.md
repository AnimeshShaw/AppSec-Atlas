---
title: "03. Data Poisoning & Dataset Sanitization"
description: "Data poisoning occurs when an attacker manipulates a fraction of training data to cause the trained model to misclassify specific inputs or behave inc..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Ml Model Security", "03 Data Poisoning And Clean Label Sanitization.Md"]
---

# 03. Data Poisoning & Dataset Sanitization

Data poisoning occurs when an attacker manipulates a fraction of training data to cause the trained model to misclassify specific inputs or behave incorrectly under trigger conditions.

---

## 1. Dataset Outlier Filtering Pipeline (Python)

```python
# dataset_sanitizer.py
import numpy as np
from sklearn.ensemble import IsolationForest

def sanitize_training_data(X_train: np.ndarray, y_train: np.ndarray):
    print(f"Original Dataset Size: {len(X_train)}")
    
    # Use Isolation Forest to detect anomalous training samples
    clf = IsolationForest(contamination=0.05, random_state=42)
    predictions = clf.fit_predict(X_train)
    
    # Keep non-anomalous samples (inliers marked as 1)
    clean_indices = np.where(predictions == 1)[0]
    print(f"Sanitized Dataset Size: {len(clean_indices)} (Removed {len(X_train) - len(clean_indices)} outliers)")
    
    return X_train[clean_indices], y_train[clean_indices]
```

---

*Next Chapter: [04. Model Intellectual Property & Extraction Defense →](04-model-intellectual-property-protection.md)*
