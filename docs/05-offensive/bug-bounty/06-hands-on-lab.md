# 06. Hands-On Vulnerability Lab

In this hands-on lab, you will audit a **vulnerable Coupon Redemption API**, run an audit script to detect a Race Condition flaw, and implement an atomic threading lock remediation.

---

## 🧪 Lab Scenario

### Step 1: Vulnerable Coupon API (`vulnerable_coupon.py`)

```python
# vulnerable_coupon.py
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

COUPONS = {"DISCOUNT50": {"discount": 50, "used": False}}
USER_BALANCE = 0

@app.route('/api/v1/redeem', methods=['POST'])
def redeem():
    global USER_BALANCE
    data = request.get_json()
    code = data.get("code")

    coupon = COUPONS.get(code)
    if not coupon or coupon["used"]:
        return jsonify({"error": "Invalid or already used coupon"}), 400

    # VULNERABLE: Artificial delay simulates DB query without mutex lock!
    time.sleep(0.1)
    
    USER_BALANCE += coupon["discount"]
    coupon["used"] = True

    return jsonify({"message": "Coupon redeemed", "new_balance": USER_BALANCE})

if __name__ == '__main__':
    app.run(port=5008)
```

---

### Step 2: Race Condition Audit Script (`audit_race.py`)

```python
# audit_race.py
import threading
import requests

URL = "http://localhost:5008/api/v1/redeem"

def send_request():
    resp = requests.post(URL, json={"code": "DISCOUNT50"})
    print(f"Status: {resp.status_code} | Body: {resp.text}")

print("=== SENDING CONCURRENT REDEMPTION REQUESTS ===")
t1 = threading.Thread(target=send_request)
t2 = threading.Thread(target=send_request)

t1.start()
t2.start()

t1.join()
t2.join()
```

---

### Step 3: Secure Mutex Lock Fix (`secure_coupon.py`)

```python
# secure_coupon.py
import threading
from flask import Flask, request, jsonify

app = Flask(__name__)
lock = threading.Lock() # SECURE: Mutex Lock

COUPONS = {"DISCOUNT50": {"discount": 50, "used": False}}
USER_BALANCE = 0

@app.route('/api/v1/redeem', methods=['POST'])
def redeem_secure():
    global USER_BALANCE
    data = request.get_json()
    code = data.get("code")

    # SECURE FIX: Atomic execution block via Mutex Lock
    with lock:
        coupon = COUPONS.get(code)
        if not coupon or coupon["used"]:
            return jsonify({"error": "Invalid or already used coupon"}), 400

        USER_BALANCE += coupon["discount"]
        coupon["used"] = True

        return jsonify({"message": "Coupon redeemed successfully", "new_balance": USER_BALANCE})

if __name__ == '__main__':
    app.run(port=5008)
```

---

*Next Chapter: [07. References & Taxonomies →](07-references.md)*
