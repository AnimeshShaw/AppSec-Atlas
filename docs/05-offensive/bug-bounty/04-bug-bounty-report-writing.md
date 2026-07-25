# 04. Report Writing & Triage Communication

Writing clear, professional reports accelerates triaging and resolution times.

---

## 1. High-Impact Report Template

```markdown
## Summary
A Broken Object Level Authorization (BOLA) vulnerability in `/api/v1/orders/{id}` allows authenticated users to access private order details belonging to other accounts.

## Steps to Reproduce
1. Log into Account A and note order ID `101`.
2. Log into Account B and send GET request to `/api/v1/orders/101`.
3. Observe HTTP 200 OK response returning Account A's PII and order details.

## Impact
Exposes user addresses, payment methods, and purchase history.

## Remediation
Enforce ownership check: `WHERE order_id = :id AND owner_id = :user_id`.
```

---

*Next Chapter: [05. Tooling & Burp Suite Extensions →](05-bug-bounty-tooling-and-extensions.md)*
