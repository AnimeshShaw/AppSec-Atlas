# API Security Checklist

## API Design & Authentication
- [ ] All API endpoints require authentication (unless intentionally public)
- [ ] API keys and tokens transmitted in headers (not URL query parameters)
- [ ] JWT signatures validated on every request
- [ ] JWT `alg: none` attack mitigated (algorithm explicitly allowlisted)
- [ ] OAuth 2.0 PKCE used for public clients
- [ ] API tokens scoped to minimum required permissions

## Authorization
- [ ] Object-level authorization checked for every resource access (prevent BOLA/IDOR)
- [ ] Function-level authorization enforced — users cannot access admin endpoints
- [ ] Mass assignment prevented — only explicitly allowlisted fields accepted
- [ ] Sensitive operations require elevated scope or re-authentication

## Input Validation
- [ ] All input validated against a strict schema
- [ ] Request size limits enforced (prevent resource exhaustion)
- [ ] Array/list inputs have maximum length limits
- [ ] Nested object depth limits enforced
- [ ] GraphQL: introspection disabled in production
- [ ] GraphQL: query depth and complexity limits set

## Rate Limiting & Abuse Prevention
- [ ] Rate limiting applied to all endpoints (especially auth and expensive operations)
- [ ] Rate limits applied per user/IP, not just globally
- [ ] Exponential backoff on failed authentication attempts
- [ ] Resource-intensive endpoints (search, export) have stricter limits

## Data Exposure
- [ ] API responses return only fields the user is authorized to see
- [ ] No internal IDs, stack traces, or server details in error responses
- [ ] Sensitive fields (passwords, tokens, secrets) never returned in responses
- [ ] Pagination enforced on list endpoints (prevent mass data extraction)

## Transport Security
- [ ] HTTPS enforced for all API endpoints
- [ ] API versioning in place
- [ ] CORS configured to allow only expected origins

## Logging & Monitoring
- [ ] All API calls logged with: timestamp, endpoint, user, IP, response code
- [ ] Anomaly detection in place (unusual request volumes, unusual parameter values)
- [ ] Alerts configured for authentication failures and authorization errors
