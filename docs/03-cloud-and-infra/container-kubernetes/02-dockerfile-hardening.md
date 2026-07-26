---
title: 02. Hardened Dockerfiles & Image Security
description: 'Master container image security: Multi-stage Dockerfiles, minimal distroless
  base images, non-root user execution, safe build secret handling, Trivy scanning,
  Hadolint linter, and Cosign image signing.'
keywords:
- dockerfile
- hardening
- multi-stage
- builds
- distroless
- non-root
- container
- trivy
- hadolint
- cosign
- container
- image
- security
- appsec
sidebar_position: 3
slug: /cloud-and-infra/container-kubernetes/dockerfile-hardening
---


# 02. Hardened Dockerfiles & Image Security

Container security starts at the build phase. An insecure container image introduces vulnerable system packages, embedded API secrets, build compilers (`gcc`, `make`), shell utilities (`curl`, `nc`), and default root execution (UID 0) directly into production environments.

Building production-grade container images requires enforcing the **Principle of Least Privilege**: minimal footprint, zero unnecessary binaries, non-root user execution, and verifiable image integrity.

---

## 1. Anatomy of an Insecure Container Image

An insecure Dockerfile introduces multiple critical attack vectors:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      INSECURE DOCKERFILE ANTI-PATTERNS                      │
├────────────────────────────────┬────────────────────────────────────────────┤
│ Anti-Pattern                   │ Security Risk & Exploitation Impact        │
├────────────────────────────────┼────────────────────────────────────────────┤
│ **Bloated Base Images**        │ Inherits hundreds of OS vulnerabilities    │
│ (e.g. `ubuntu:latest`, `node`) │ and unnecessary binaries (`curl`, `bash`).  │
├────────────────────────────────┼────────────────────────────────────────────┤
│ **Default Root User (UID 0)**  │ If container is breached, attacker gets    │
│                                │ root permissions inside container namespace│
├────────────────────────────────┼────────────────────────────────────────────┤
│ **Compilers in Production**    │ Build tools (`gcc`, `pip`, `npm`) allow    │
│                                │ attackers to compile exploits on target.   │
├────────────────────────────────┼────────────────────────────────────────────┤
│ **Hardcoded Secrets**          │ `ARG` or `ENV` variables leak credentials  │
│                                │ permanently into image layer metadata.     │
├────────────────────────────────┼────────────────────────────────────────────┤
│ **Unpinned Base Image Tags**   │ `FROM node:latest` leads to non-deterministic│
│                                │ builds and unexpected breaking updates.    │
└────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 2. Core Image Hardening Principles

### A. Multi-Stage Builds
Multi-stage builds separate the **compilation environment** from the **runtime execution environment**. Compilers, build dependencies, header files, and temporary artifacts remain strictly in stage 1, producing a lean, production-ready stage 2 artifact.

### B. Distroless and Scratch Base Images
- **Alpine Linux:** Minimal (~5 MB), but includes `apk` package manager and `sh` shell.
- **Google Distroless:** Minimal (~20 MB), contains **only** the application runtime and its dynamic dependencies. Does **not** include shells (`/bin/sh`, `/bin/bash`), package managers, or standard Unix utilities (`ls`, `cat`, `curl`).
- **Scratch:** Empty base image (0 MB), ideal for statically compiled binaries (Go, Rust).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BASE IMAGE SECURITY COMPARISON MATRIX                    │
├─────────────────┬──────────┬──────────────┬──────────────┬──────────────────┤
│ Base Image      │ Size     │ Package Mgr  │ Shell Access │ Vulnerability    │
│                 │          │ Included     │ (/bin/sh)    │ Surface          │
├─────────────────┼──────────┼──────────────┼──────────────┼──────────────────┤
│ `ubuntu:22.04`  │ ~78 MB   │ `apt`        │ Yes          │ High (100+ CVEs) │
│ `node:20`       │ ~1.1 GB  │ `apt`        │ Yes          │ High (200+ CVEs) │
│ `node:20-alpine`│ ~170 MB  │ `apk`        │ Yes          │ Low (10-20 CVEs) │
│ `distroless`    │ ~25 MB   │ **None**     │ **None**     │ Minimal (0-2 CVEs)│
│ `scratch`       │ 0 MB     │ **None**     │ **None**     │ Zero             │
└─────────────────┴──────────┴──────────────┴──────────────┴──────────────────┘
```

### C. Non-Root Execution (`USER nonroot`)
Always specify an explicit non-root UID and GID (e.g. `USER 65532:65532` or `USER nonroot`). Never rely on the default UID 0.

### D. Secure Secret Handling with Docker BuildKit
Never store API keys or private certificates in `ENV` or `ARG` statements—they are saved in plain text within layer history (`docker history myimage`). Use BuildKit secret mounts:
```dockerfile
# SECURE: Secret is mounted in memory for the RUN command only and never written to image layers!
RUN --mount=type=secret,id=github_token \
    TOKEN=$(cat /run/secrets/github_token) && \
    git clone https://x-access-token:${TOKEN}@github.com/org/private-repo.git
```

---

## 3. Side-by-Side Code Comparisons (Multi-Language)

### Pattern 1: Node.js Express Application

#### ❌ Insecure Dockerfile
```dockerfile
# INSECURE: Bloated base image, runs as root, includes npm build tools in runtime
FROM node:18

WORKDIR /app
COPY . .
RUN npm install

# Hardcoded secret in build argument leaks into image layer history!
ARG API_SECRET=sk_live_9988776655
ENV API_SECRET=${API_SECRET}

EXPOSE 3000
CMD ["node", "server.js"]
```

#### ✅ Production-Hardened Dockerfile (Multi-Stage + Distroless)
```dockerfile
# STAGE 1: Build & Dependency Installation
FROM node:20-alpine AS builder
WORKDIR /app

# Copy dependency manifests first for optimal layer caching
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY . .

# STAGE 2: Minimal Distroless Production Runtime
FROM gcr.io/distroless/nodejs20-debian12:nonroot

WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /app /app

# Explicitly set non-root user (UID 65532)
USER nonroot

EXPOSE 3000
ENV NODE_ENV=production
CMD ["server.js"]
```

---

### Pattern 2: Python FastAPI Application

#### ❌ Insecure Dockerfile
```dockerfile
# INSECURE: Runs as root, installs compilers in runtime layer, includes pip cache
FROM python:3.11

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### ✅ Production-Hardened Dockerfile (Multi-Stage + Non-Root User)
```dockerfile
# STAGE 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# STAGE 2: Hardened Runtime Environment
FROM python:3.11-slim AS runner

# Create dedicated unprivileged system user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appgroup . /app

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

### Pattern 3: Go Microservice (Scratch Base Image)

#### ❌ Insecure Dockerfile
```dockerfile
# INSECURE: Leaves Go compiler and source code in runtime container
FROM golang:1.22
WORKDIR /go/src/app
COPY . .
RUN go build -o /app
CMD ["/app"]
```

#### ✅ Production-Hardened Dockerfile (Static Binary on Scratch)
```dockerfile
# STAGE 1: Build statically compiled binary
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 builds a completely static binary without glibc dependencies
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /bin/server .

# STAGE 2: Scratch Base Image (0 MB Overhead)
FROM scratch

# Import CA certificates for TLS support
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/server /server

# Non-root user ID for scratch containers
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
```

---

### Pattern 4: Java Spring Boot Application

#### ❌ Insecure Dockerfile
```dockerfile
# INSECURE: Full JDK in runtime, runs as root, unoptimized layer cache
FROM maven:3.9-eclipse-temurin-17
WORKDIR /app
COPY . .
RUN mvn package
CMD ["java", "-jar", "target/app.jar"]
```

#### ✅ Production-Hardened Dockerfile (Distroless Java Runtime)
```dockerfile
# STAGE 1: Maven Build
FROM maven:3.9-eclipse-temurin-17-alpine AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src
RUN mvn clean package -DskipTests

# STAGE 2: Distroless JRE 17 Runtime
FROM gcr.io/distroless/java17-debian12:nonroot

WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /build/target/*.jar /app/app.jar

USER nonroot
EXPOSE 8080
CMD ["/app/app.jar"]
```

---

## 4. Automated Image Security Pipeline ( Hadolint + Trivy + Cosign )

Integrate automated security verification gates into your CI/CD workflow:

```mermaid
flowchart LR
    A["Dockerfile"] --> B["Hadolint Linter"]
    B -- Pass --> C["Docker Build"]
    C --> D["Trivy Vulnerability Scan"]
    D -- 0 Critical CVEs --> E["Cosign Image Sign"]
    E --> F["Push to Registry"]

    style B fill:#1e293b,stroke:#3b82f6,color:#fff
    style D fill:#1e293b,stroke:#10b981,color:#fff
    style E fill:#1e293b,stroke:#8b5cf6,color:#fff
```

### A. Dockerfile Linting with Hadolint

Hadolint parses Dockerfiles into an AST and checks them against best-practice rules:

```bash
# Run Hadolint CLI against local Dockerfile
hadolint Dockerfile
```

#### Sample `.hadolint.yaml` Configuration File:
```yaml
# .hadolint.yaml
ignored:
  - DL3018 # Ignore pinning alpine package versions if using strict release tags
trustedRegistries:
  - docker.io
  - gcr.io
  - myregistry.azurecr.io
strict-labels: true
```

---

### B. Image Vulnerability Scanning & SBOM Generation with Trivy

Trivy scans container images for OS package and language dependency vulnerabilities (CVEs):

```bash
# 1. Fail build on HIGH or CRITICAL severity vulnerabilities
trivy image \
  --exit-code 1 \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  myregistry.azurecr.io/appsec-atlas/api:v1.0.0

# 2. Generate Software Bill of Materials (SBOM) in CycloneDX format
trivy image \
  --format cyclonedx \
  --output sbom.json \
  myregistry.azurecr.io/appsec-atlas/api:v1.0.0
```

---

### C. Container Image Signing & Verification with Cosign

Cosign (part of the Linux Foundation Sigstore project) signs container images to ensure supply chain integrity:

```bash
# 1. Keyless signing using OpenID Connect (OIDC) identity in GitHub Actions
cosign sign --yes myregistry.azurecr.io/appsec-atlas/api:v1.0.0

# 2. Verify image signature before deploying to Kubernetes cluster
cosign verify \
  --certificate-identity "https://github.com/my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  myregistry.azurecr.io/appsec-atlas/api:v1.0.0
```

---

*Next Chapter: [03. Kubernetes SecurityContext & Pod Standards →](03-kubernetes-security-context.md)*
