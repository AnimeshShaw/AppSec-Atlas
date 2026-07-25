---
title: "06. Hands-On Audit Lab"
description: "In this lab, you will audit a **PyTorch classifier model**, measure its prediction sensitivity to input noise, and implement a robust Gaussian noise d..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Ml Model Security", "06 Hands On Lab.Md"]
---

# 06. Hands-On Audit Lab

In this lab, you will audit a **PyTorch classifier model**, measure its prediction sensitivity to input noise, and implement a robust Gaussian noise data augmentation fix.

---

## 🧪 Lab Scenario

### Step 1: Target PyTorch Model & Audit (`model_audit.py`)

```python
# model_audit.py
import torch
import torch.nn as nn

class SimpleClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(10, 32),
            nn.ReLU(),
            nn.Linear(32, 2)
        )
    def forward(self, x):
        return self.fc(x)

model = SimpleClassifier()
model.eval()

# Test input vector
sample = torch.randn(1, 10)
orig_pred = torch.argmax(model(sample)).item()

# Add small noise perturbation
noise = torch.randn(1, 10) * 0.5
perturbed_sample = sample + noise
new_pred = torch.argmax(model(perturbed_sample)).item()

print(f"Original Prediction: {orig_pred}")
print(f"Perturbed Prediction: {new_pred}")

if orig_pred != new_pred:
    print("🚨 AUDIT NOTICE: Model prediction changed under input noise! Low noise robustness.")
```

---

### Step 2: Robust Training Fix (`robust_training.py`)

```python
# robust_training.py
import torch
import torch.nn as nn
import torch.optim as optim

def train_robust_model(model: nn.Module, X_train: torch.Tensor, y_train: torch.Tensor):
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    criterion = nn.CrossEntropyLoss()

    model.train()
    for epoch in range(10):
        # Add random Gaussian noise during training (Gaussian Data Augmentation)
        noisy_X = X_train + torch.randn_like(X_train) * 0.1
        
        optimizer.zero_grad()
        outputs = model(noisy_X)
        loss = criterion(outputs, y_train)
        loss.backward()
        optimizer.step()

    print("✅ Model trained with Gaussian Noise Augmentation for improved robustness.")
```

---

*Next Chapter: [07. References & Standards →](07-references.md)*
