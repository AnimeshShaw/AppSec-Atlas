# 01 - Introduction to Hardware Security

Hardware is the foundation upon which all software security relies. If the hardware can be physically manipulated to extract keys or bypass logic, all higher-level software protections are rendered useless.

## The Hardware Threat Landscape

Unlike network or application security, hardware security assumes the attacker has **physical possession** of the device. The threat landscape includes:
*   **Non-Invasive Attacks:** Observing the device without damaging it (e.g., side-channel analysis, timing attacks).
*   **Semi-Invasive Attacks:** Removing the chip packaging (decapsulation) to access the die surface and inject faults using lasers or UV light.
*   **Invasive Attacks:** Physically modifying the circuitry, probing data buses with microprobes, or using Focused Ion Beams (FIB) to rewire the chip.

## Integrated Circuit (IC) Architecture & Attack Surface

An embedded System-on-Chip (SoC) contains multiple components that can be targeted. 

```ascii
+-------------------------------------------------------------+
|                     System-on-Chip (SoC)                    |
|                                                             |
|  +--------------+  +---------------+  +------------------+  |
|  |     CPU      |  |   RAM/SRAM    |  | Flash / EEPROM   |  |
|  | (Execution)  |  | (Volatile)    |  | (Non-Volatile)   |  |
|  +------+-------+  +-------+-------+  +--------+---------+  |
|         |                  |                   |            |
|  =========================================================  |
|         |                  |                   |            |
|  +------+-------+  +-------+-------+  +--------+---------+  |
|  |  Crypto Co-  |  |   JTAG/UART   |  |  Peripherals     |  |
|  |  processor   |  | (Debug Ports) |  | (USB, SPI, I2C)  |  |
|  +--------------+  +---------------+  +------------------+  |
+-------------------------------------------------------------+
```

### Key Attack Vectors:
1.  **Memory Extraction:** Reading Flash/EEPROM to dump firmware, exposing hardcoded credentials or proprietary algorithms.
2.  **Bus Snooping:** Sniffing data transmitted over SPI, I2C, or UART traces on the PCB.
3.  **Debug Port Abuse:** Utilizing exposed JTAG or SWD interfaces to halt CPU execution, read memory, and manipulate registers.
4.  **Environmental Manipulation:** Dropping the voltage or disrupting the clock to cause instruction skips (Glitching).

## Root Causes of Hardware Vulnerabilities
*   **Lack of Obfuscation:** Storing plaintext keys in non-volatile memory.
*   **Development Leftovers:** Forgetting to disable JTAG or print verbose debug logs over UART in production devices.
*   **Deterministic Execution:** Executing cryptographic algorithms without constant-time properties, leaking timing or power consumption data.
