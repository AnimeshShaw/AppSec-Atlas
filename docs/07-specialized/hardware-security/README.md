# Hardware Security Basics

Welcome to the **Hardware Security Basics** guide. This module dives into the physical layers of security, exploring how hardware architectures can be compromised, and how to defend them against direct physical attacks, side-channels, and supply-chain threats.

## 📖 Overview
Software security often assumes that the underlying hardware executes instructions faithfully and keeps secrets protected. Hardware security shatters this assumption. In this module, you will learn how physical access to a device enables attackers to extract cryptographic keys, bypass secure boot, and hijack execution using techniques like side-channel analysis and fault injection.

## 🎯 Learning Objectives
By the end of this module, you will be able to:
1. Understand the hardware threat model and integrated circuit (IC) architecture.
2. Comprehend the mechanics of Side-Channel Analysis (SPA/DPA) and Fault Injection (Glitching).
3. Utilize hardware Roots of Trust (RoT), TPMs, and Secure Elements.
4. Secure hardware debugging interfaces (JTAG/UART) for production.
5. Identify supply chain threats, counterfeit components, and hardware trojans.
6. Exploit and patch a timing side-channel vulnerability in a software implementation.

## 🛠️ Prerequisites
- Basic understanding of cryptography (Symmetric/Asymmetric, Hashes).
- Familiarity with embedded systems or microcontrollers (MCU) is helpful but not strictly required.
- Basic Python for the side-channel lab.

## 🧭 Navigation
- [01 Introduction](01-introduction.md) - Threat model, architecture, physical attack vectors.
- [02 Physical Tampering & Side Channels](02-physical-tampering-and-side-channel.md) - SPA, DPA, Fault Injection, EMFI.
- [03 Secure Elements & TPM](03-secure-elements-and-tpm.md) - TPM 2.0, Secure Enclaves, RoT, PUFs.
- [04 Hardware Debugging Interfaces](04-hardware-debugging-interfaces.md) - JTAG, UART, Logic Analyzers, OpenOCD.
- [05 Supply Chain Security](05-hardware-supply-chain-security.md) - Counterfeits, hardware trojans, PCB layout security.
- [06 Hands-on Lab](06-hands-on-lab.md) - Timing side-channel exploitation and mitigation.
- [07 References](07-references.md) - Tools, standards, and further reading.
