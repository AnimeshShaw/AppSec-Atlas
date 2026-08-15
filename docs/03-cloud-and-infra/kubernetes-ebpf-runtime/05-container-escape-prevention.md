---
sidebar_position: 6
title: "05. Container Escape Prevention"
---

# 05. Container Escape Prevention

## 1. The Concept (ELI5)
A container is not a virtual machine; it is just a set of boundaries (Namespaces) and resource limits (cgroups) applied to normal Linux processes. Imagine a container as a padded room with a locked door inside a larger house (the Host Node). 

A **Container Escape** occurs when an attacker inside the padded room finds a weak spot in the wall—like a loose air vent—and climbs out into the main house. Once in the main house (the Host Node), they have access to *every other padded room* and the house's master keys (Kubelet credentials, Docker socket). We prevent escapes by enforcing strictly locked boundaries and removing dangerous host mounts.

## 2. The Visual

```mermaid
architecture-beta
    group node(Node)[Kubernetes Worker Node]
    
    service container(server)[Compromised Container] in node
    service socket(disk)[/var/run/docker.sock] in node
    service kubelet(database)[Kubelet Credentials] in node
    
    container:R --> socket:L
    container:R --> kubelet:L
    
    %% Escaping via a mounted docker socket gives the container full host control
```

## 3. The Code
Container escapes rarely happen due to application logic alone; they usually require dangerous infrastructure configurations combined with an application vulnerability. However, applications that mismanage file paths or improperly parse symlinks can accidentally expose host files if a mount exists.

### Go
**❌ Vulnerable Code (Following Symlinks to Host Files)**
```go
package main
import (
    "net/http"
    "os"
)
func readFile(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Query().Get("path")
    // If a host filesystem is mounted at /host, an attacker can read it
    data, _ := os.ReadFile("/app/uploads/" + path)
    w.Write(data)
}
```

**✅ Secure Code (Restricting Path Resolution)**
```go
package main
import (
    "net/http"
    "path/filepath"
    "strings"
    "os"
)
func readFile(w http.ResponseWriter, r *http.Request) {
    base := "/app/uploads/"
    path := filepath.Join(base, r.URL.Query().Get("path"))
    
    // Evaluate symlinks and ensure the final path remains in the base directory
    realPath, err := filepath.EvalSymlinks(path)
    if err != nil || !strings.HasPrefix(realPath, base) {
        http.Error(w, "Forbidden", 403)
        return
    }
    data, _ := os.ReadFile(realPath)
    w.Write(data)
}
```

### Python
**❌ Vulnerable Code**
```python
import os
from flask import Flask, request, send_file
app = Flask(__name__)

@app.route('/read')
def read():
    path = request.args.get('path')
    # Blindly opens the path, vulnerable to symlink-based escapes
    return send_file(os.path.join('/data/', path))
```

**✅ Secure Code**
```python
import os
from flask import Flask, request, abort, send_file
app = Flask(__name__)

@app.route('/read')
def read():
    path = request.args.get('path')
    target = os.path.realpath(os.path.join('/data/', path))
    
    if not target.startswith('/data/'):
        abort(403)
    return send_file(target)
```

### TypeScript / Node.js
**❌ Vulnerable Code**
```typescript
import fs from 'fs';
import express from 'express';
const app = express();

app.get('/read', (req, res) => {
    const path = req.query.path as string;
    // fs.readFileSync automatically resolves symlinks, potentially reading host files
    res.send(fs.readFileSync(`/data/${path}`));
});
```

**✅ Secure Code**
```typescript
import fs from 'fs';
import path from 'path';
import express from 'express';
const app = express();

app.get('/read', (req, res) => {
    const requestedPath = req.query.path as string;
    const fullPath = path.join('/data/', requestedPath);
    
    const realPath = fs.realpathSync(fullPath);
    if (!realPath.startsWith('/data/')) {
        return res.status(403).send('Forbidden');
    }
    res.send(fs.readFileSync(realPath));
});
```

## 4. The Guardrail
The best defense against container escapes is to disallow mounting sensitive host paths (like `/`, `/var/run`, or `/etc`) into containers. We enforce this using an OPA Gatekeeper Rego policy.

**Rego Policy: Prevent HostPath Mounts**
```rego
package k8spspcontainercapabilities

violation[{"msg": msg}] {
    volume := input.review.object.spec.volumes[_]
    has_host_path(volume)
    msg := sprintf("HostPath volume %v is not allowed, it can lead to container escape.", [volume.name])
}

has_host_path(volume) {
    volume.hostPath
}
```
