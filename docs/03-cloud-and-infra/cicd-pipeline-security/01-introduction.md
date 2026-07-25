# 01. Overview & Supply Chain Threat Landscape

CI/CD pipelines have become the primary target for modern cyber attacks. Instead of attacking a heavily defended production server directly, attackers compromise the build system to inject malicious code into software updates that get signed and distributed automatically.

---

## 1. Real-World Case Studies

1. **SolarWinds (2020)**: Attackers compromised the internal Orion build environment, inserting a backdoor into official signed software updates delivered to 18,000+ organizations.
2. **XZ Utils Backdoor (2024)**: A long-term social engineering and supply chain injection in the XZ compression library designed to bypass SSH authentication across Linux distributions.
3. **CircleCI Breach (2023)**: Compromised engineer credentials allowed attackers to extract active customer secrets and cloud API keys stored in pipeline environment variables.

---

## 2. The SLSA Framework (Supply-chain Levels for Software Artifacts)

SLSA (pronounced *salsa*) is a security framework established by Google and the OpenSSF to safeguard software artifacts against tampering.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SLSA Security Levels                               │
├─────────┬───────────────────────────────────────────────────────────────────┤
│ Level 1 │ Build process is fully automated and generates provenance metadata.│
│ Level 2 │ Build runs on a dedicated service; provenance is cryptographically│
│         │ signed by the build platform.                                     │
│ Level 3 │ Build runs in an isolated ephemeral environment (prevents cross-   │
│         │ build contamination).                                             │
└─────────┴───────────────────────────────────────────────────────────────────┘
```

---

*Next Chapter: [02. GitHub Actions Security Hardening →](02-github-actions-hardening.md)*
