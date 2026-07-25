---
title: "Chapter 2: Input Validation & Sanitization"
description: "Pydantic ensures data validation and settings management using Python type annotations."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Secure Coding", "02 Input Validation Sanitization.Md"]
---

# Chapter 2: Input Validation & Sanitization

## Strict Input Allowlisting vs Blocklisting
- **Blocklisting (Bad):** Attempting to filter out bad characters like `'` or `<script>`. Attackers will find bypasses (e.g., `<ScRiPt>`, url-encoding).
- **Allowlisting (Good):** Defining exactly what *is* allowed. E.g., an age field must be an integer between 1 and 120.

## Schema Validation

### Python (Pydantic)
Pydantic ensures data validation and settings management using Python type annotations.

```python
# secure_validation.py
from pydantic import BaseModel, EmailStr, constr, ValidationError

class UserModel(BaseModel):
    username: constr(min_length=3, max_length=20, regex=r'^[a-zA-Z0-9_]+$')
    email: EmailStr
    age: int

# Good Data
try:
    user = UserModel(username="alice_123", email="alice@example.com", age=25)
    print("Valid:", user)
except ValidationError as e:
    print(e)

# Bad Data (Throws Error)
try:
    bad_user = UserModel(username="admin' OR 1=1--", email="not_an_email", age="twenty")
except ValidationError as e:
    print("Caught Invalid Input:", e.errors())
```

### Node.js (Zod)
Zod is a TypeScript-first schema declaration and validation library.

```javascript
// secure_validation.js
import { z } from "zod";

const UserSchema = z.object({
  username: z.string().min(3).max(20).regex(/^[a-zA-Z0-9_]+$/),
  email: z.string().email(),
  age: z.number().int().min(1).max(120)
});

try {
  // Validates securely
  UserSchema.parse({ username: "bob_99", email: "bob@example.com", age: 30 });
} catch (error) {
  console.error("Validation failed", error);
}
```

### Go (Validator)
```go
package main

import (
	"fmt"
	"github.com/go-playground/validator/v10"
)

type User struct {
	Username string `validate:"required,alphanum,min=3,max=20"`
	Email    string `validate:"required,email"`
	Age      int    `validate:"required,min=1,max=120"`
}

func main() {
	v := validator.New()
	user := User{Username: "charlie123", Email: "charlie@test.com", Age: 28}
	
	err := v.Struct(user)
	if err != nil {
		fmt.Println("Validation Error:", err)
	} else {
		fmt.Println("Valid Input!")
	}
}
```
