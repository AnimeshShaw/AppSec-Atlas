# 02. Hardened Dockerfiles & Image Security

A secure container image follows the principle of least privilege: minimal packages, no root user, read-only filesystem, and no secrets.

---

## 1. Vulnerable vs Hardened Dockerfile Comparison

### ❌ Vulnerable Dockerfile
```dockerfile
# VULNERABLE: Uses bloated base image, runs as root, includes build tools in runtime!
FROM node:18

WORKDIR /app
COPY . .
RUN npm install

# VULNERABLE: Runs as root (UID 0) by default!
EXPOSE 3000
CMD ["node", "server.js"]
```

---

### ✅ Production-Hardened Multi-Stage Dockerfile
```dockerfile
# STAGE 1: Build Environment
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .

# STAGE 2: Distroless Minimal Production Environment
FROM gcr.io/distroless/nodejs20-debian12:nonroot

WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /app /app

# SECURE: Automatically runs as nonroot user (UID 65532)
USER nonroot

EXPOSE 3000
CMD ["server.js"]
```

---

## 2. Image Vulnerability Scanning with Trivy & Hadolint

### Hadolint (Dockerfile Linter)
```bash
# Lint Dockerfile for security anti-patterns
hadolint Dockerfile
```

### Trivy (Container Image Vulnerability Scanner)
```bash
# Scan container image for OS and package vulnerabilities
trivy image --severity HIGH,CRITICAL myregistry.azurecr.io/appsec-atlas/api:v1.0.0
```

---

*Next Chapter: [03. Kubernetes SecurityContext & Pod Standards →](03-kubernetes-security-context.md)*
