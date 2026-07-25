# 04 - Memory Forensics Masterclass

Memory forensics involves the analysis of a computer's volatile memory (RAM). It is crucial for detecting advanced threats like rootkits, fileless malware, and injected code.

## RAM Capture

### WinPmem (Windows)
```cmd
winpmem.exe -o memdump.raw
```

### LiME (Linux)
LiME (Linux Memory Extractor) is a Loadable Kernel Module (LKM).
```bash
insmod lime.ko "path=memdump.lime format=lime"
```

## Volatility 3
Volatility is the industry standard for memory analysis.

### Common Plugins (Windows)

1. **`windows.info`**: Get profile information and verify the image.
   ```bash
   python3 vol.py -f memdump.raw windows.info
   ```

2. **`windows.pslist`**: List active processes.
   ```bash
   python3 vol.py -f memdump.raw windows.pslist
   ```

3. **`windows.pstree`**: View process hierarchy to spot parent-child anomalies (e.g., `cmd.exe` spawning from `notepad.exe`).
   ```bash
   python3 vol.py -f memdump.raw windows.pstree
   ```

4. **`windows.netscan`**: View active network connections and listening ports at the time of capture.
   ```bash
   python3 vol.py -f memdump.raw windows.netscan
   ```

5. **`windows.malfind`**: Detect hidden and injected code by analyzing memory segments marked with Execute/Read/Write (PAGE_EXECUTE_READWRITE) permissions that are unbacked by files on disk.
   ```bash
   python3 vol.py -f memdump.raw windows.malfind
   ```
