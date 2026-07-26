---
title: 05. gRPC Security Tools & Auditing Frameworks
description: Complete guide to gRPC security testing tools, CLI utility usage, load/DoS
  testing, SAST rules, and automated vulnerability scanning.
keywords:
- gRPC
- Tools
- grpcurl
- grpcui
- ghz
- Semgrep
- Buf
- DAST
- Scanning
- Penetration
- Testing
slug: /web-and-api/grpc-security/tools
---


# 05. gRPC Security Tools & Auditing Frameworks

Auditing, penetration testing, and statically analyzing gRPC applications requires specialized security tooling capable of interpreting Protocol Buffer wire formats and HTTP/2 framing.

---

## 1. Reconnaissance & Reflection Auditing (`grpcurl` & `grpcui`)

### A. `grpcurl` - The Command-Line gRPC Audit Workhorse

`grpcurl` is a lightweight CLI utility for interacting with gRPC servers. It supports Reflection-based schema discovery as well as static `.proto` file parsing.

#### 1. Discover Exposed Services (Server Reflection Check)
```bash
# Attempt to list services on target server (Checks if Reflection is vulnerable!)
grpcurl -insecure target.example.com:50051 list

# Expected output on vulnerable server:
# grpc.reflection.v1alpha.ServerReflection
# order.v1.OrderService
# user.v1.UserService
# admin.v1.InternalAdminService  <-- Vulnerable internal service exposed!
```

#### 2. Describe Endpoint & Inspect Protobuf Schema
```bash
# Extract full message definitions and methods from reflection
grpcurl -insecure target.example.com:50051 describe user.v1.UserService.GetUserProfile

# Output:
# user.v1.UserService.GetUserProfile is a method:
# rpc GetUserProfile ( .user.v1.GetUserRequest ) returns ( .user.v1.UserProfile );
```

#### 3. Crafting Custom RPC Exploits with Custom Metadata Headers
```bash
# Invoke RPC method passing custom JSON payload & Authorization metadata header
grpcurl -insecure \
  -H "authorization: Bearer eyJhbGciOi..." \
  -d '{"user_id": "target_user_99"}' \
  target.example.com:50051 \
  user.v1.UserService/GetUserProfile
```

### B. `grpcui` - Interactive Web GUI for gRPC Testing

`grpcui` provides an interactive web interface (built on top of `grpcurl`) for exploring gRPC services in a browser.

```bash
# Launch interactive browser UI connected to target gRPC endpoint
grpcui -insecure -port 8080 target.example.com:50051
```

> [!WARNING]
> If `grpcui` successfully loads service forms without requiring a `.proto` file, **Server Reflection is enabled in production**, exposing all service contracts to unauthenticated attackers.

---

## 2. Performance & DoS Stress Testing (`ghz`)

`ghz` is an open-source gRPC benchmarking and load-testing CLI tool. Security engineers use `ghz` to test rate limiters and detect stream exhaustion DoS vulnerabilities.

### A. Simulating Stream Flooding / High-Concurrency DoS

```bash
# Launch 200 concurrent workers sending 10,000 requests to test stream exhaustion
ghz --insecure \
  --proto=./order.proto \
  --call=order.v1.OrderService.CreateOrder \
  --data='{"order_id": "test-123", "quantity": 5}' \
  --concurrency=200 \
  --total=10000 \
  --cpus=4 \
  target.example.com:50051
```

### Key Metrics to Monitor During Load Testing:
* **Error Code `ResourceExhausted` (Code 8):** Indicates rate limiters or stream quotas are functioning correctly.
* **Error Code `Unavailable` (Code 14) / Server Crash:** Indicates the server lacks stream limits and is vulnerable to DoS.

---

## 3. Protobuf Security & Linting (`buf`)

The **Buf CLI** (`buf`) provides linting, breaking change detection, and formatting for Protocol Buffer definitions.

### A. Auditing Schema Security with `buf lint`

Create a `buf.yaml` configuration:

```yaml
version: v1
lint:
  use:
    - DEFAULT
    - COMMENTS
  except:
    - PACKAGE_DIRECTORY_MATCH
```

Run schema audit:

```bash
# Run lint checks across all proto definitions
buf lint
```

---

## 4. Static Application Security Testing (SAST) with Semgrep

Semgrep can detect hardcoded insecure gRPC transport configurations across codebase repositories.

### Custom Semgrep Rules for gRPC Hardening (`grpc-sast-rules.yaml`):

```yaml
rules:
  - id: insecure-grpc-dial-go
    languages: [go]
    severity: ERROR
    message: "CRITICAL: gRPC client dialing with grpc.WithInsecure(). Traffic will be transmitted in unencrypted plaintext!"
    pattern: grpc.Dial($ADDR, ..., grpc.WithInsecure(), ...)

  - id: insecure-grpc-server-python
    languages: [python]
    severity: ERROR
    message: "CRITICAL: gRPC server using add_insecure_port(). Enable ssl_server_credentials with mTLS!"
    pattern: $SERVER.add_insecure_port(...)

  - id: insecure-grpc-plaintext-java
    languages: [java]
    severity: ERROR
    message: "CRITICAL: Java gRPC ServerBuilder configured with usePlaintext(). Transport encryption disabled!"
    pattern: $BUILDER.usePlaintext()

  - id: grpc-reflection-production
    languages: [go]
    severity: WARNING
    message: "WARNING: Server Reflection registered. Ensure reflection.Register() is guarded by environment checks!"
    pattern: reflection.Register($SERVER)
```

#### Executing Semgrep Audit:
```bash
semgrep --config=grpc-sast-rules.yaml ./src/
```

---

## 5. gRPC Security Tooling Summary

| Tool Name | Type | Key Security Purpose |
| :--- | :--- | :--- |
| **`grpcurl`** | CLI Utility | Reflection inspection, crafting RPC requests, header metadata testing |
| **`grpcui`** | Web GUI | Interactive browser testing of exposed gRPC methods |
| **`ghz`** | Benchmarking / DoS | Load testing, testing stream concurrency limits & rate limiters |
| **`buf`** | Schema Linter | Auditing `.proto` contracts, breaking change detection, validation |
| **`Semgrep`** | SAST Scanner | Automated code detection of `WithInsecure()`, plaintext servers, and reflection leaks |

---

*Next Chapter: [06. Hands-on Vulnerability Lab: Exploiting & Securing gRPC →](06-labs.md)*
