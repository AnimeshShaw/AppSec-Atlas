---
title: 03 - Secure Elements and TPM
description: To protect cryptographic material from the physical attacks discussed
  previously, modern devices rely on dedicated, hardened microcontrollers.
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '07'
- Specialized
- Hardware
- Security
- '03'
- Secure
- Elements
- And
- Tpm
- Md
slug: /specialized/hardware-security/secure-elements-and-tpm
---


# 03 - Secure Elements and TPM

To protect cryptographic material from the physical attacks discussed previously, modern devices rely on dedicated, hardened microcontrollers.

## Hardware Root of Trust (RoT)
A Hardware Root of Trust is an unconditionally trusted component inside a system. It provides a foundation upon which all other trust is built, primarily ensuring **Secure Boot** (verifying the firmware signature before executing it).

## Trusted Platform Module (TPM 2.0)
A TPM is an international standard for a secure cryptoprocessor. Usually found on motherboards, it provides:
1.  **Platform Configuration Registers (PCRs):** Used to store cryptographic hashes of the boot sequence (BIOS, bootloader, OS kernel). If the boot chain is altered, the PCRs won't match, and the TPM refuses to unseal encryption keys (e.g., BitLocker).
2.  **Key Storage:** Keys are generated inside the TPM and never leave in plaintext.
3.  **Cryptographic Acceleration:** Offloads RSA/ECC/SHA operations.

### Common TPM CLI Operations (tpm2-tools)
```bash
# Read a PCR value to check the system state
tpm2_pcrread sha256:0,1,2,3

# Generate a primary key inside the TPM
tpm2_createprimary -C o -c primary.ctx

# Create an RSA key pair
tpm2_create -C primary.ctx -u key.pub -r key.priv
```

## Secure Elements (SE)
Unlike TPMs which are designed for PCs/Servers, Secure Elements are smaller, heavily protected chips used in mobile devices, IoT, and smartcards. 
*   **Examples:** Microchip ATECC608A, Apple Secure Enclave, NXP MIFARE.
*   **Features:** They boast advanced physical defenses (mesh shields, glitch detectors, glued packaging). They act as a black box: you send a payload in, it signs it, and returns the signature. The private key cannot be extracted.

## Physically Unclonable Functions (PUF)
A PUF exploits natural, unavoidable manufacturing variations in silicon to generate a unique "digital fingerprint" for each chip. 
*   **How it works:** Because no two transistors are *exactly* identical, a PUF circuit evaluates tiny timing or voltage differences. 
*   **Security Benefit:** Keys are not stored in flash memory! The key is dynamically reconstructed on boot by querying the PUF. If the chip is powered off, the key ceases to exist, making offline memory extraction impossible.
