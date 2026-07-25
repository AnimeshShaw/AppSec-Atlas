# 06 - Hands-on Lab: Compliance Assessment Tool

In this lab, you will build a Python tool that acts as a mock Cloud Security Posture Management (CSPM) scanner. It will read a JSON representation of infrastructure, map it to NIST CSF 2.0 controls, report unmapped/non-compliant infrastructure, and provide remediation steps.

## The Lab Code

Save this code as `nist_assessor.py` and run it.

```python
import json

# Mock Infrastructure Data
infra_state = {
    "s3_buckets": [
        {"name": "customer-data-prod", "encrypted": True, "public_access": False},
        {"name": "ml-training-temp", "encrypted": False, "public_access": True}
    ],
    "iam_users": [
        {"username": "admin1", "mfa_enabled": True},
        {"username": "dev_test", "mfa_enabled": False}
    ]
}

# Mapping Rules to NIST CSF 2.0
RULES = [
    {
        "id": "PR.DS-01",
        "description": "Data-at-rest is protected",
        "resource_type": "s3_buckets",
        "check": lambda res: res.get("encrypted") is True,
        "remediation": "Enable Server-Side Encryption (SSE-S3 or SSE-KMS)."
    },
    {
        "id": "PR.DS-02",
        "description": "Data-in-transit is protected (Simulated via public access check)",
        "resource_type": "s3_buckets",
        "check": lambda res: res.get("public_access") is False,
        "remediation": "Block all public access to the bucket."
    },
    {
        "id": "PR.AA-01",
        "description": "Identities and credentials are managed",
        "resource_type": "iam_users",
        "check": lambda res: res.get("mfa_enabled") is True,
        "remediation": "Enforce MFA for the IAM user."
    }
]

def run_assessment(infra, rules):
    results = []
    
    for rule in rules:
        resource_type = rule["resource_type"]
        resources = infra.get(resource_type, [])
        
        for res in resources:
            identifier = res.get("name") or res.get("username")
            is_compliant = rule["check"](res)
            
            results.append({
                "control": rule["id"],
                "control_desc": rule["description"],
                "resource": identifier,
                "compliant": is_compliant,
                "remediation": rule["remediation"] if not is_compliant else "N/A"
            })
            
    return results

if __name__ == "__main__":
    print("--- NIST CSF 2.0 Compliance Assessment ---")
    assessment_results = run_assessment(infra_state, RULES)
    
    for res in assessment_results:
        status = "✅ PASS" if res["compliant"] else "❌ FAIL"
        print(f"{status} | {res['control']} | Resource: {res['resource']}")
        if not res["compliant"]:
            print(f"    -> Remediation: {res['remediation']}")
```

## Execution and Output

Run the script:
```bash
python nist_assessor.py
```

**Expected Output:**
```text
--- NIST CSF 2.0 Compliance Assessment ---
✅ PASS | PR.DS-01 | Resource: customer-data-prod
❌ FAIL | PR.DS-01 | Resource: ml-training-temp
    -> Remediation: Enable Server-Side Encryption (SSE-S3 or SSE-KMS).
✅ PASS | PR.DS-02 | Resource: customer-data-prod
❌ FAIL | PR.DS-02 | Resource: ml-training-temp
    -> Remediation: Block all public access to the bucket.
✅ PASS | PR.AA-01 | Resource: admin1
❌ FAIL | PR.AA-01 | Resource: dev_test
    -> Remediation: Enforce MFA for the IAM user.
```
