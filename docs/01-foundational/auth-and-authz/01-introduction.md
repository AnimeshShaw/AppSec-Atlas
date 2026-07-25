# 01 - Introduction to Authentication & Authorization

Identity management is central to application security. It is fundamentally split into two distinct processes: **Authentication (AuthN)** and **Authorization (AuthZ)**.

## Authentication (AuthN): Who are you?
Authentication is the process of verifying a user's identity. It asks the question: *Are you who you say you are?*

Common factors of authentication:
- **Knowledge:** Something you know (Passwords, PINs, Security Questions).
- **Possession:** Something you have (Smartcards, OTP Tokens, Security Keys like YubiKey).
- **Inherence:** Something you are (Biometrics, Fingerprints, FaceID).

## Authorization (AuthZ): What can you do?
Once identity is established, Authorization dictates what actions the authenticated entity is allowed to perform. It asks: *Are you allowed to do this?*

Authorization relies on permissions, roles, and attributes. Even if a user is authenticated, they must be explicitly authorized to access specific resources (e.g., an Admin vs. a regular User).

## Session-based vs Token-based Authentication

### Session-based Authentication (Stateful)
In traditional web applications, authentication state is maintained on the server.
1. User logs in with credentials.
2. Server validates and creates a session in memory/database.
3. Server returns a Session ID via a `Set-Cookie` header.
4. Browser automatically sends the Cookie with subsequent requests.
5. Server looks up the Session ID to verify the user.

**Pros:** Easy to revoke, mature, built-in browser cookie security.
**Cons:** Harder to scale (requires distributed caching like Redis for multi-server setups), susceptible to CSRF if not protected.

### Token-based Authentication (Stateless)
Modern APIs and Single Page Applications (SPAs) often use stateless tokens (like JWT).
1. User logs in.
2. Server validates and generates a signed token (e.g., JWT).
3. Server sends the token to the client.
4. Client stores the token and sends it in the `Authorization: Bearer <token>` header for subsequent requests.
5. Server verifies the token signature without looking up a database.

**Pros:** Highly scalable, decoupled, good for microservices.
**Cons:** Hard to revoke before expiration, increased risk if the token is stolen (e.g., via XSS if stored in LocalStorage).

## Defense in Depth
Never rely on a single layer of security.
- Enforce MFA to protect against credential stuffing.
- Use secure, HttpOnly cookies for session storage.
- Implement least privilege authorization models.
- Validate and sanitize all inputs to prevent token theft via XSS.
