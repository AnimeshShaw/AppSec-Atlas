---
sidebar_position: 3
title: "02. Syscall Tracing with Falco"
---

# 02. Syscall Tracing with Falco

## 1. The Concept (ELI5)
Imagine your house has motion sensors in every room. When you're home, movement in the living room is normal. But if you're on vacation and the living room sensor detects movement, an alarm sounds.

**Falco** is the motion sensor for your Kubernetes clusters. Developed by Sysdig, Falco hooks into the Linux kernel using eBPF to monitor every single action (syscall) happening across all your containers. It compares these actions against a set of rules (the "vacation mode" logic). If a container suddenly starts reading sensitive files like `/etc/shadow` or spawns a reverse shell, Falco detects the anomaly in real-time and sends an alert. It doesn't stop the burglar (it's purely detection), but it ensures you know immediately.

## 2. The Visual

```mermaid
architecture-beta
    group cluster(Node)[Kubernetes Node]
    
    service app(server)[App Container] in cluster
    service kernel(disk)[Linux Kernel] in cluster
    service ebpf(memory)[Falco eBPF Probe] in cluster
    service engine(server)[Falco Engine] in cluster
    service siem(database)[SIEM / Alerts]
    
    app:R --> kernel:L
    kernel:R --> ebpf:L
    ebpf:R --> engine:L
    engine:R --> siem:L
```

## 3. The Code
Often, applications are built in a way that allows them to read arbitrary files from the filesystem. If an attacker exploits a Directory Traversal vulnerability, Falco will see the underlying `openat` syscall accessing `/etc/passwd`.

### Go
**❌ Vulnerable Code (Arbitrary File Read)**
```go
package main
import (
    "io/ioutil"
    "net/http"
)
func handler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    // Attacker can pass "../../../../etc/passwd"
    data, _ := ioutil.ReadFile("/var/www/images/" + filename)
    w.Write(data)
}
```

**✅ Secure Code (Path Sanitization & Scoping)**
```go
package main
import (
    "io/ioutil"
    "net/http"
    "path/filepath"
    "strings"
)
func handler(w http.ResponseWriter, r *http.Request) {
    baseDir := "/var/www/images/"
    filename := filepath.Clean(r.URL.Query().Get("file"))
    target := filepath.Join(baseDir, filename)
    
    // Ensure the resolved path is still inside the base directory
    if !strings.HasPrefix(target, baseDir) {
        http.Error(w, "Forbidden", 403)
        return
    }
    data, _ := ioutil.ReadFile(target)
    w.Write(data)
}
```

### Python
**❌ Vulnerable Code**
```python
from flask import Flask, request, send_file
app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    # Vulnerable to directory traversal
    return send_file(f"/app/data/{filename}")
```

**✅ Secure Code**
```python
from flask import Flask, request, send_from_directory
import os
app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    # send_from_directory automatically prevents directory traversal
    return send_from_directory("/app/data/", filename)
```

### TypeScript / Node.js
**❌ Vulnerable Code**
```typescript
import express from 'express';
import fs from 'fs';
const app = express();

app.get('/file', (req, res) => {
    const file = req.query.file as string;
    // fs.readFileSync will follow traversal paths
    res.send(fs.readFileSync(`/data/${file}`));
});
```

**✅ Secure Code**
```typescript
import express from 'express';
import path from 'path';
import fs from 'fs';
const app = express();

app.get('/file', (req, res) => {
    const baseDir = '/data/';
    const reqPath = req.query.file as string;
    const safePath = path.resolve(baseDir, reqPath);
    
    if (!safePath.startsWith(baseDir)) {
        return res.status(403).send('Forbidden');
    }
    res.send(fs.readFileSync(safePath));
});
```

## 4. The Guardrail
To ensure we catch any application that gets bypassed or compromised, we deploy a **Falco Rule**.

**Falco Rule (YAML): Prevent Access to Sensitive Files**
```yaml
- rule: Read Sensitive File Untrusted
  desc: >
    An attempt to read any sensitive file (e.g. files containing user/password/authentication
    info). Exceptions are made for known trusted programs.
  condition: >
    open_read and sensitive_files and not trusted_containers
  output: >
    Sensitive file opened for reading by non-trusted program (user=%user.name 
    command=%proc.cmdline file=%fd.name container=%container.info)
  priority: WARNING
  tags: [filesystem, mitre_credential_access]
```
