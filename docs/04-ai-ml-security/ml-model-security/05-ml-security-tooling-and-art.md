# 05. Automated ML Auditing with ART

The **Adversarial Robustness Toolbox (ART)** by the Linux Foundation is a Python library for machine learning security evaluation.

---

## 1. Installing & Running ART Classifier Wrap

```bash
pip install adversarial-robustness-toolbox
```

```python
# art_audit.py
from art.estimators.classification import PyTorchClassifier
import torch.nn as nn
import torch.optim as optim

# Wrap PyTorch model with ART Classifier
classifier = PyTorchClassifier(
    model=model,
    loss=nn.CrossEntropyLoss(),
    optimizer=optim.Adam(model.parameters()),
    input_shape=(1, 28, 28),
    nb_classes=10
)

print("✅ Model successfully wrapped with ART Security Evaluator")
```

---

*Next Chapter: [06. Hands-On Audit Lab →](06-hands-on-lab.md)*
