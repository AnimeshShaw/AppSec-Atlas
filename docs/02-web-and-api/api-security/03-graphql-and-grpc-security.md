# 03. GraphQL & gRPC Security

Modern applications frequently use **GraphQL** and **gRPC** instead of traditional REST APIs. While they provide high performance, they introduce unique attack vectors if not configured securely.

---

## 1. GraphQL Security

Unlike REST (which has multiple endpoints), GraphQL operates over a single endpoint (usually `/graphql`) accepting queries.

```
Attacker ──► Introspection Query ──► Uncovers complete GraphQL Schema & Hidden Types!
Attacker ──► Deeply Nested Query ──► DoS (Memory / CPU Exhaustion)
Attacker ──► Batch Query Attack  ──► Bypasses Rate Limiting via 1,000 queries in 1 HTTP Request
```

### A. Introspection Abuse & Hardening

By default, GraphQL allows clients to query `__schema` to discover all types, queries, and mutations.

#### ❌ Vulnerable GraphQL Setup (Node.js - Apollo Server)
```javascript
// VULNERABLE: Introspection enabled in production environment!
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true // Dangerous in production!
});
```

#### ✅ Secure GraphQL Setup
```javascript
// SECURE: Introspection disabled in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production'
});
```

---

### B. Query Depth & Complexity Limiting (DoS Defense)

Attackers can submit recursive nested queries causing server-side CPU spikes:

```graphql
# Malicious Deep Query (Recursive DoS Payload)
query {
  user {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}
```

#### ✅ Secure Depth Limiting Implementation (graphql-depth-limit)
```javascript
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5) // Reject queries deeper than 5 levels!
  ]
});
```

---

## 2. gRPC Security

gRPC uses HTTP/2 protocols and Protocol Buffers (protobuf) for high-performance communication.

### Key Security Requirements for gRPC:
1. **mTLS (Mutual TLS)**: Encrypt and authenticate both client and server certificates.
2. **Metadata Authentication Tokens**: Validate JWT or API keys in gRPC metadata interceptors.

### ✅ Secure gRPC Interceptor (Go)
```go
// SECURE: gRPC Server Interceptor for JWT authentication
func UnaryAuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, status.Errorf(codes.Unauthenticated, "Missing metadata")
    }

    tokens := md["authorization"]
    if len(tokens) == 0 {
        return nil, status.Errorf(codes.Unauthenticated, "Missing authorization token")
    }

    tokenString := strings.TrimPrefix(tokens[0], "Bearer ")
    if !validateJWT(tokenString) {
        return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired token")
    }

    return handler(ctx, req)
}
```

---

*Next Chapter: [04. Rate Limiting, Throttling & Auth →](04-rate-limiting-and-throttling.md)*
