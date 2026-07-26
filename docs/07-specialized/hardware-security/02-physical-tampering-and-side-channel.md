---
title: 02 - Physical Tampering & Side-Channel Analysis
description: When standard logical attacks fail, attackers turn to physics. Side-channel
  analysis (SCA) and Fault Injection (FI) exploit the physical properties of...
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
- '02'
- Physical
- Tampering
- And
- Side
- Channel
- Md
slug: /specialized/hardware-security/physical-tampering-and-side-channel
---


# 02 - Physical Tampering & Side-Channel Analysis

When standard logical attacks fail, attackers turn to physics. Side-channel analysis (SCA) and Fault Injection (FI) exploit the physical properties of a device while it performs computations.

## Side-Channel Analysis (SCA)

Every time a CPU executes an instruction, it consumes power and emits electromagnetic radiation. These physical emissions correlate with the data being processed.

### Simple Power Analysis (SPA)
SPA involves visually inspecting the power trace on an oscilloscope to identify operations. 
*   **Example:** In a naive RSA implementation, a '1' bit in the private key might trigger a "Square and Multiply" operation, while a '0' bit only triggers a "Square". This creates a visible difference in the power consumption graph, allowing the attacker to literally "read" the key off the screen.

### Differential Power Analysis (DPA)
DPA is much more powerful and relies on statistical analysis across thousands of power traces.
*   **Mechanism:** By capturing power traces during many AES encryptions and grouping them based on guesses for a single byte of the key, statistical spikes will confirm when a guess is correct. It bypasses noise and small variations.

## Fault Injection (Glitching)

Fault Injection intentionally disrupts the operating environment of a chip to cause a controllable error, typically to bypass a security check (like a password validation or Secure Boot signature check).

### Types of Glitching
1.  **Voltage Glitching (Vcc Glitching):** Momentarily dropping the power supply voltage near the threshold of operation. The CPU may fail to load a value from memory or skip an instruction (like a branch instruction `BNE`).
2.  **Clock Glitching:** Inserting an abnormally short clock pulse. The CPU doesn't have enough time to propagate signals through logic gates, resulting in corrupted data or skipped instructions.
3.  **Electromagnetic Fault Injection (EMFI):** Using a high-voltage pulse through a coil near the chip's surface to induce localized currents, corrupting specific registers or memory banks without needing to cut power or desolder the chip.

## Tamper Detection Circuits

To defend against physical attacks, secure hardware employs tamper detection meshes and environmental sensors.

*   **Active Shields:** A fine mesh of conductive wires placed over the silicon die. If an attacker tries to scratch off the packaging to probe the chip, the wire breaks, changing the resistance and triggering an alarm.
*   **Environmental Sensors:** 
    *   *Voltage monitors* detect out-of-bounds power levels (glitch attempts).
    *   *Temperature sensors* detect cooling (cold-boot attacks) or excessive heat.
    *   *Light sensors* detect decapsulation (since silicon is light-sensitive).
*   **Zeroization:** Upon detecting tampering, the hardware instantly erases all volatile and non-volatile keys, rendering the device inert.
