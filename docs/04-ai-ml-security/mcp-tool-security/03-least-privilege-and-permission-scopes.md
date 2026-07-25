# 03 - Least Privilege & Permission Scopes

## Defenses and Mitigations
To prevent an LLM from abusing tools, we must apply the Principle of Least Privilege. This involves:
1.  **Scope Isolation:** Restricting tools to specific directories or data segments.
2.  **Human-In-The-Loop (HITL):** Requiring user approval for sensitive actions.

### Scope Isolation
Instead of a generic `read_file` tool, use scoped tools or enforce path constraints.

### Vulnerable Tool (Python)
```python
import os

def delete_file(filepath):
    # VULNERABILITY: Path Traversal and unrestricted deletion
    os.remove(filepath)
    return "File deleted"
```

### Secure Tool with Scope and HITL (Python)
```python
import os
import time

ALLOWED_DIR = "/home/user/sandbox_data/"

def request_user_approval(action_desc):
    # In a real app, this would send an interactive prompt to the user
    print(f"SECURITY ALERT: LLM requested to {action_desc}. Approve? (y/n)")
    # For demo purposes, we simulate denial
    return False 

def delete_file_secure(filepath):
    # 1. Path Sanitization and Scope Check
    abs_path = os.path.abspath(os.path.join(ALLOWED_DIR, filepath))
    if not abs_path.startswith(ALLOWED_DIR):
        return "Error: Path out of bounds"
        
    # 2. HITL Approval
    if not request_user_approval(f"delete {abs_path}"):
        return "Error: User denied permission"
        
    try:
        os.remove(abs_path)
        return "File deleted securely"
    except Exception as e:
        return str(e)
```
