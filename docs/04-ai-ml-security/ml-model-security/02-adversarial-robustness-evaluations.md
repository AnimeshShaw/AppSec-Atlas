# 02. Adversarial Input Robustness & Sensitivity

Evaluating how a neural network's loss function changes relative to small input perturbations helps measure model robustness.

---

## 1. PyTorch Input Sensitivity Auditor

```python
# sensitivity_audit.py
import torch
import torch.nn as nn

def measure_input_gradient_norm(model: nn.Module, input_tensor: torch.Tensor, target_class: int) -> float:
    """Calculates L2 norm of model gradients with respect to input tensor."""
    input_tensor.requires_grad = True
    output = model(input_tensor)
    loss = nn.CrossEntropyLoss()(output, torch.tensor([target_class]))
    loss.backward()
    
    grad_norm = input_tensor.grad.norm(2).item()
    return grad_norm
```

If `grad_norm` is extremely high, the model's decision boundary is brittle and susceptible to small input variations.

---

*Next Chapter: [03. Data Poisoning & Dataset Sanitization →](03-data-poisoning-and-clean-label-sanitization.md)*
