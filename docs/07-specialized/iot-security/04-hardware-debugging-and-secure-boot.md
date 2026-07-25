# 04. Hardware Debugging & Secure Boot

Physical access to an IoT device is often "game over" if the hardware is not appropriately hardened. Attackers will disassemble the device, locate debugging interfaces on the PCB (Printed Circuit Board), and attempt to take control.

## 🔌 Exposing Hardware Interfaces

### Discovering UART Pinouts
UART typically requires 3 or 4 pins: **TX** (Transmit), **RX** (Receive), **GND** (Ground), and optionally VCC (Power).

**How Attackers Find UART:**
1. Look for a row of 3 to 5 through-hole pads or headers on the PCB.
2. Use a **multimeter** in continuity mode:
   - Find the **GND** pin by testing for continuity between the pad and a known ground (e.g., metallic shielding, USB casing).
   - Find **VCC** (3.3V or 5V) by powering on the device and measuring DC voltage against GND.
   - The **TX** pin will usually fluctuate in voltage (e.g., bouncing between 2.5V and 3.3V) while the device is booting and spitting out logs.
   - The **RX** pin will usually be pulled high (stable 3.3V) or low.
3. Connect a USB-to-TTL adapter (ensure voltages match, usually 3.3V).
4. Use a tool like `minicom` or `screen` to connect, iterating through common baud rates (9600, 115200).

```bash
# Connect to UART via screen at 115200 baud
$ sudo screen /dev/ttyUSB0 115200
```

### JTAG Debugging
JTAG is much more powerful than UART. It allows an attacker to freeze the CPU, dump memory, and step through code.
- **Defeating JTAG:** Attackers use tools like the **JTAGulator** to automatically identify JTAG pinouts (TDI, TDO, TCK, TMS) among dozens of unknown test points on a board.
- Once connected, tools like **OpenOCD** (Open On-Chip Debugger) interface with the CPU to extract firmware directly from flash.

## 🛡️ Hardware Root of Trust (RoT) & Secure Boot

To defend against physical tampering and malicious firmware modification, IoT devices must implement a **Hardware Root of Trust**.

### What is Secure Boot?
Secure Boot is a process ensuring that a device only executes code generated and signed by the trusted manufacturer. It prevents an attacker from flashing a backdoored firmware image or a malicious bootloader.

**The Secure Boot Chain:**
1. **BootROM (Immutable):** Burned into the silicon during manufacturing. Cannot be altered. It contains a public key (or a hash of a public key).
2. **First Stage Bootloader:** The BootROM verifies the digital signature of the First Stage Bootloader using the immutable public key. If the signature is valid, it executes.
3. **OS / Kernel:** The Bootloader verifies the signature of the OS/Kernel before handing over control.
4. **Applications:** The OS verifies the applications.

If any signature check fails, the device halts or boots into a safe recovery mode.

### Hardware Security Modules
Software cryptography is easily bypassed if the keys are stored in readable flash memory. Modern IoT devices use dedicated security hardware:

1. **TPM (Trusted Platform Module):** A dedicated chip that securely stores cryptographic keys, certificates, and passwords. It performs cryptographic operations internally, meaning the private key *never* leaves the TPM.
2. **ARM TrustZone:** A hardware feature that partitions the CPU and memory into a "Secure World" (Trusted Execution Environment - TEE) and a "Normal World" (Rich OS, like Linux). Cryptographic keys and DRM processes run in the Secure World, isolated from potential kernel exploits in the Normal World.
3. **eFuses / OTP (One-Time Programmable) Memory:** Tiny physical fuses inside the SoC that can be blown once. Used to permanently store the hash of the OEM's public key (for Secure Boot) and to permanently disable JTAG/UART interfaces before shipping to customers.

In the next chapter, we will discuss how to properly configure these hardware features and securely update firmware.
