# Differential Privacy and Anonymization

Traditional anonymization techniques often fail against modern re-identification attacks. Privacy engineering relies on mathematical frameworks to protect data.

## K-Anonymity, L-Diversity, and T-Closeness
These are formal models for data de-identification.

- **K-Anonymity:** Ensures that any individual in a dataset cannot be distinguished from at least `k-1` other individuals based on quasi-identifiers (e.g., Age, Zip, Gender). Achieved via suppression (removing data) or generalization (e.g., Age 24 -> 20-30).
- **L-Diversity:** An extension of K-Anonymity that ensures each equivalence class has at least `l` distinct values for the sensitive attribute (e.g., Disease), preventing attribute disclosure attacks.
- **T-Closeness:** Ensures the distribution of a sensitive attribute within any equivalence class is close to the overall distribution in the entire dataset.

## Differential Privacy (DP)
Differential Privacy is a mathematically rigorous definition of privacy. It guarantees that the output of a statistical query will not significantly change whether any specific individual's data is included in the dataset or not.

### Epsilon-Delta Bounds
- **Epsilon (ε):** The privacy budget. Smaller ε means more privacy but less utility (more noise).
- **Delta (δ):** The probability that the strict ε-bound is broken (often set to `< 1/N` where N is dataset size).

### Laplace Mechanism Example
The Laplace mechanism adds noise proportional to the sensitivity of the query divided by ε.

```python
import numpy as np

def laplace_mechanism(true_value, sensitivity, epsilon):
    # Scale parameter for the Laplace distribution
    scale = sensitivity / epsilon
    
    # Generate random noise from the Laplace distribution
    noise = np.random.laplace(0, scale)
    
    # Add noise to the true value
    noisy_value = true_value + noise
    return noisy_value

# Example: Counting users with a specific disease
true_count = 1500
sensitivity = 1 # A single user changes the count by at most 1
epsilon = 0.5   # Privacy budget

noisy_count = laplace_mechanism(true_count, sensitivity, epsilon)
print(f"True Count: {true_count}")
print(f"Noisy Count (Released to public): {noisy_count:.2f}")
```

### Gaussian Mechanism
Used for bounded differential privacy, adding noise from a Gaussian distribution. Useful when dealing with vector-valued functions and (ε, δ)-differential privacy.
