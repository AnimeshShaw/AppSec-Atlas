---
title: "05 - Hardware Supply Chain Security"
description: "Compromise can happen long before the device reaches the consumer. Hardware supply chain security focuses on verifying the integrity and authenticity ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Hardware Security", "05 Hardware Supply Chain Security.Md"]
---

# 05 - Hardware Supply Chain Security

Compromise can happen long before the device reaches the consumer. Hardware supply chain security focuses on verifying the integrity and authenticity of the components and manufacturing process.

## Counterfeit Components
A major threat in hardware manufacturing is the introduction of counterfeit or recycled chips.
*   **Cloned Chips:** Functional clones of legitimate chips, often with inferior silicon that fails under stress or lacks security features.
*   **Recycled Chips:** Desoldered from e-waste, re-marked, and sold as new. They may contain residual data or degraded lifespan.
*   **Mitigation:** Sourcing exclusively from authorized distributors. X-ray analysis and decapsulation sampling can verify die authenticity.

## Hardware Trojans
Hardware Trojans are malicious modifications made to an integrated circuit during the design or fabrication phase (e.g., by a compromised foundry).
*   **Triggers:** A specific combination of inputs or a timer.
*   **Payloads:** Leaking keys over a side-channel, altering RNG output to be predictable, or disabling a security enforcement module.
*   **Detection:** Extremely difficult. Requires advanced optical inspection, side-channel fingerprinting, and logic testing.

## PCB Layout Security
The physical design of the Printed Circuit Board (PCB) impacts security.
*   **Exposed Vias:** Vias (holes that route traces between layers) can be probed by attackers to sniff data. 
*   **Mitigation:** Route sensitive data buses (like the line between a CPU and an external crypto chip) on the inner layers of a multi-layer PCB, surrounded by ground planes (blind and buried vias). Use epoxy potting to encase the circuitry, making physical access destructive.

## ChipWhisperer Testing Platform
To secure the supply chain and validate hardware, engineers use tools like **ChipWhisperer**. It is an open-source toolchain specifically built for side-channel power analysis and voltage glitching evaluation. It allows developers to test their hardware implementations against physical attacks *before* mass production.
