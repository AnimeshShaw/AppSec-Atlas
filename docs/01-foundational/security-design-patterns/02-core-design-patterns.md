# 02 - Core Design Patterns

Implementing security requires specific, repeatable patterns. This section covers critical design patterns for resilience, access control, and isolation.

## 1. Circuit Breaker Pattern
The Circuit Breaker pattern prevents a system from repeatedly trying to execute an operation that is likely to fail, thus preventing cascading failures across microservices.

**Implementation Concept:**
- **Closed State:** Requests flow normally. If failures cross a threshold, the breaker trips.
- **Open State:** Requests immediately fail fast without trying the remote service.
- **Half-Open State:** After a timeout, a limited number of requests are allowed through to test if the remote service has recovered.

```python
# Python pseudo-code for a basic circuit breaker
class CircuitBreaker:
    def __init__(self, failure_threshold, recovery_timeout):
        self.failure_count = 0
        self.threshold = failure_threshold
        self.state = "CLOSED"
    
    def call(self, func):
        if self.state == "OPEN":
            raise Exception("Circuit is OPEN. Failing fast.")
        
        try:
            result = func()
            self.failure_count = 0
            return result
        except Exception:
            self.failure_count += 1
            if self.failure_count >= self.threshold:
                self.state = "OPEN"
            raise
```

## 2. Token Bucket Rate Limiting Pattern
Rate limiting is essential to prevent abuse, DoS attacks, and brute force attempts. The Token Bucket algorithm allows for a steady rate of requests with occasional bursts.

**How it works:**
- A "bucket" holds a certain number of tokens.
- Tokens are added to the bucket at a fixed rate.
- Each request removes one token.
- If the bucket is empty, the request is rejected.

## 3. Secure Factory Pattern
Used to ensure that objects (like cryptographic keys, user sessions, or connections) are created in a secure, validated state, abstracting the complex security initialization from the developer.

## 4. Compartmentalization
Dividing a system into isolated compartments to limit the blast radius if one component is compromised.

## 5. Chroot / Container Jails
Restricting a process's view of the file system. In modern architectures, this is typically achieved using Docker containers and Linux namespaces to isolate the application environment from the host OS.
