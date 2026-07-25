# Hands-On Lab: Implementing Anonymization and Differential Privacy

In this lab, you will start with a raw PII dataset and apply both K-Anonymity and Differential Privacy.

## Setup
Ensure you have Python installed along with `pandas` and `numpy`.
```bash
pip install pandas numpy
```

## 1. The Raw Dataset
Create a file named `raw_data.csv`:
```csv
Name,Age,ZipCode,Disease
Alice,24,10012,Flu
Bob,29,10013,Cancer
Charlie,23,10012,Flu
Dave,55,10015,Heart Disease
Eve,59,10016,Cancer
```

## 2. K-Anonymity Script
We will generalize Age and ZipCode to achieve K-Anonymity.

```python
import pandas as pd

# Load data
df = pd.read_csv('raw_data.csv')

# Drop identifying information
df = df.drop(columns=['Name'])

# Generalize Age (e.g., to decades)
df['Age'] = df['Age'].apply(lambda x: f"{(x // 10) * 10}s")

# Generalize ZipCode (e.g., keep first 4 digits)
df['ZipCode'] = df['ZipCode'].astype(str).str[:4] + '*'

print("Anonymized Dataset:")
print(df)
```

## 3. Differential Privacy Script (Laplace Noise)
Suppose we want to release the count of users with "Cancer".

```python
import pandas as pd
import numpy as np

# True aggregate calculation
df = pd.read_csv('raw_data.csv')
true_count = len(df[df['Disease'] == 'Cancer'])

def get_noisy_count(true_val, epsilon):
    # Sensitivity for a count query is 1
    sensitivity = 1
    noise = np.random.laplace(0, sensitivity / epsilon)
    return max(0, int(round(true_val + noise)))

epsilon = 0.5
noisy_count = get_noisy_count(true_count, epsilon)

print(f"True Cancer Count: {true_count}")
print(f"Differentially Private Count (epsilon={epsilon}): {noisy_count}")
```

## Challenge
Modify the DP script to calculate the average age of the users in the dataset while preserving differential privacy. (Hint: You will need to bound the age range to calculate sensitivity).
