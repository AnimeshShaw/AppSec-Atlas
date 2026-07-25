---
title: "04. Kubernetes Secrets Hardening"
description: "By default, Kubernetes `Secret` objects are NOT encrypted; they are merely base64 encoded and stored in plaintext in the `etcd` backend."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Secrets Management", "04 Kubernetes Secrets Hardening.Md"]
---

# 04. Kubernetes Secrets Hardening

By default, Kubernetes `Secret` objects are NOT encrypted; they are merely base64 encoded and stored in plaintext in the `etcd` backend. 

## 1. Encryption at Rest (KMS Provider)
To secure secrets in `etcd`, you must configure a KMS (Key Management Service) provider. This encrypts the secrets before they are written to disk.

**Encryption Configuration (`encryption-config.yaml`):**
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          name: aws-encryption-provider
          endpoint: unix:///var/run/kmsplugin/kmsplugin.sock
          cachesize: 1000
          timeout: 3s
      - identity: {} # Fallback for reading unencrypted secrets
```
Start the kube-apiserver with: `--encryption-provider-config=/etc/kubernetes/encryption-config.yaml`

## 2. The External Secrets Operator (ESO)
Injecting secrets manually into Kubernetes is an anti-pattern. ESO reads information from a 3rd party API (Vault, AWS Secrets Manager) and automatically creates a standard Kubernetes `Secret` to be consumed by pods.

**Example `SecretStore` (Vault):**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "http://vault.default.svc.cluster.local:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "eso-role"
          serviceAccountRef:
            name: "eso-service-account"
```

**Example `ExternalSecret`:**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
spec:
  refreshInterval: "1h"
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: db-secret # Name of the generated k8s Secret
  data:
  - secretKey: db_password
    remoteRef:
      key: "myapp/config"
      property: "db_password"
```

## 3. Sealed Secrets (GitOps Friendly)
If you practice GitOps (e.g., ArgoCD), storing plaintext manifests in Git is insecure. Bitnami Sealed Secrets encrypts your Secret into a `SealedSecret` object, which is safe to store in Git. The Sealed Secrets controller in the cluster decrypts it.

```bash
# Encrypt standard secret into SealedSecret
kubeseal --format=yaml < mysecret.json > mysealedsecret.yaml
```

## 4. Preventing Environment Variable Leaks
Using `envFrom: secretRef` exposes secrets to the environment. Any process in the container, crash dump, or a simple `printenv` command via an RCE vulnerability will leak the secrets.

**Best Practice: Volume Mounts**
Mount secrets as files in memory (`tmpfs`). The application reads the file into memory on startup and the secret never exists in the environment variables.

```yaml
volumes:
  - name: secret-volume
    secret:
      secretName: db-secret
containers:
  - name: myapp
    volumeMounts:
      - name: secret-volume
        mountPath: "/etc/secrets"
        readOnly: true
```
