# 04. Rate Limiting, Throttling & Auth

Without rate limiting and secure token handling, APIs fall victim to resource exhaustion, credential stuffing, and token manipulation attacks (OWASP API2 & API4).

---

## 1. Sliding Window Rate Limiting (Redis + Node.js)

Implementing a distributed sliding window rate limiter prevents single clients or botnets from overwhelming API endpoints.

```python
# Redis Sliding Window Algorithm
key = f"rate_limit:{user_ip}"
now = current_timestamp_ms()
window_start = now - (60 * 1000) # 1 minute window

# 1. Remove expired timestamps
redis.zremrangebyscore(key, 0, window_start)
# 2. Count requests in current window
current_requests = redis.zcard(key)

if current_requests >= 100:
    return HTTP 429 Too Many Requests
    
# 3. Add current request timestamp
redis.zadd(key, {now: now})
```

---

## 2. JWT Security Attacks & Mitigations

### Attack 1: `alg: none` Vulnerability
Some vulnerable JWT libraries accept tokens signed with the `"none"` algorithm, effectively bypassing signature validation.

#### ❌ Vulnerable Token Decoding
```python
import jwt

# VULNERABLE: Allows alg="none" without signature verification!
def decode_token_bad(token):
    return jwt.decode(token, options={"verify_signature": False})
```

#### ✅ Secure Token Decoding
```python
import jwt

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

# SECURE: Explicitly enforce HS256 algorithm and signature verification
def decode_token_secure(token):
    return jwt.decode(
        token, 
        SECRET_KEY, 
        algorithms=["HS256"], # Explicit algorithm allowlist!
        options={"verify_signature": True}
    )
```

---

*Next Chapter: [05. API Gateway & Defense Patterns →](05-defenses-and-gateway-patterns.md)*
