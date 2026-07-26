---
title: "Zero Trust Microservices: Implementing SPIFFE/SPIRE & mTLS for Kubernetes Services"
description: "How to eliminate static API keys and IP-based trust in Kubernetes microservices using SPIFFE/SPIRE cryptographic workload attestation and Envoy mTLS."
slug: zero-trust-microservices-spiffe-spire
authors: [animesh, appsec-team]
tags: [zero-trust, cloud-security, appsec]
hide_table_of_contents: false
---

In modern cloud-native Kubernetes environments, relying on perimeter firewalls, network security groups, or hardcoded API keys for microservice-to-microservice authentication is no longer sufficient. If an attacker compromises a single pod inside a VPC, unauthenticated internal networks allow lateral movement across the entire cluster.

**Zero Trust Architecture (NIST SP 800-207)** dictates a fundamental shift: *Never Trust, Always Verify*. In this article, we explore how to establish cryptographic workload identity using **SPIFFE/SPIRE** and enforce Mutual TLS (mTLS) via Envoy sidecar proxies.

{/* truncate */}

## What is SPIFFE/SPIRE?

- **SPIFFE (Secure Production Identity Framework for Everyone)**: A set of open standards defining how workloads acquire short-lived, cryptographically verifiable identities represented as **SPIFFE IDs** (e.g., `spiffe://example.org/ns/prod/sa/payment-service`) in X.509 certificates (SVIDs).
- **SPIRE (SPIFFE Runtime Environment)**: The production-ready reference implementation that performs node and workload attestation (verifying Kubernetes namespace, service account, pod UID, and binary hash) before issuing SVID certificates.

```mermaid
architecture-beta
    group k8s(cloud)[Kubernetes Cluster]
    
    service agent(server)[SPIRE Agent DaemonSet] in k8s
    service podA(database)[Payment Microservice Pod] in k8s
    service podB(internet)[Order Service Pod] in k8s
    
    podA -- Attests K8s UID --> agent
    agent -- Issues short-lived SVID Cert --> podA
    podB -- Establishes mTLS using SVID --> podA
```

## Step-by-Step Production Architecture

### 1. Workload Attestation
When a pod requests an identity certificate, the local SPIRE Agent queries the Kubernetes API server to verify:
- Pod Namespace (`prod`)
- ServiceAccount Name (`payment-sa`)
- Container Image SHA-256 Digest

### 2. SVID Certificate Rotation
SPIRE automatically issues short-lived X.509 SVIDs (typically valid for 1 hour) directly into container memory via the SPIFFE Workload API, eliminating disk storage of private keys.

### 3. Envoy Sidecar mTLS Verification
Envoy proxies intercept incoming gRPC/REST traffic, validate the client certificate chain against the SPIRE Trust Bundle, and assert the client's SPIFFE ID in SPIFFE SAN URI extensions.

```yaml
# Envoy Proxy Hardened TLS Context Configuration
static_resources:
  listeners:
  - name: ingress_listener
    address:
      socket_address: { address: 0.0.0.0, port_value: 8443 }
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain: { filename: "/spiffe-workload-api/svid.pem" }
              private_key: { filename: "/spiffe-workload-api/svid_key.pem" }
            validation_context:
              trusted_ca: { filename: "/spiffe-workload-api/bundle.pem" }
              match_typed_subject_alt_names:
              - san_type: URI
                matcher:
                  exact: "spiffe://appsecatlas.org/ns/prod/sa/order-service"
```

## Summary & Next Steps

Cryptographic workload identity with SPIFFE/SPIRE eliminates hardcoded credentials, defends against SSRF/lateral movement, and satisfies NIST SP 800-207 Zero Trust requirements.

For complete hands-on Terraform/Kubernetes manifests and Python/Go code samples, check out the [Zero Trust Architecture Guide](/docs/foundational/zero-trust/zero-trust-cloud-architecture) and [Container & K8s Security Guide](/docs/cloud-and-infra/container-kubernetes) in AppSec Atlas.
