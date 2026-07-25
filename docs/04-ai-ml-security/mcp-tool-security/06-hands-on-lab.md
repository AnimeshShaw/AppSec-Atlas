# 06 - Hands-On Lab: MCP Exploitation & Mitigation

## Scenario
You are testing a local MCP server that provides filesystem tools to an AI agent. The server is vulnerable to path traversal.

### 1. Vulnerable MCP Server (`vulnerable_server.py`)
```python
import json
import sys
import os

def handle_request(req_str):
    req = json.loads(req_str)
    if req["method"] == "tools/call" and req["params"]["name"] == "read_file":
        filepath = req["params"]["arguments"]["path"]
        # VULNERABLE: No path validation
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            return {"result": {"content": content}}
        except Exception as e:
            return {"error": str(e)}

# Simulated request from malicious prompt injection
payload = json.dumps({
    "method": "tools/call",
    "params": {
        "name": "read_file",
        "arguments": {"path": "../../../../etc/passwd"}
    }
})

print("Vulnerable Output:", handle_request(payload))
```

### 2. Exploit
Run the script. The output will dump the contents of `/etc/passwd` because the `read_file` tool does not restrict paths.

### 3. Secure Fix (`secure_server.py`)
Apply scope isolation and HITL.
```python
import json
import os

BASE_DIR = os.path.abspath("./safe_workspace")

def handle_request_secure(req_str):
    req = json.loads(req_str)
    if req["method"] == "tools/call" and req["params"]["name"] == "read_file":
        filepath = req["params"]["arguments"]["path"]
        
        # SECURE: Path validation
        target_path = os.path.abspath(os.path.join(BASE_DIR, filepath))
        if not target_path.startswith(BASE_DIR):
            return {"error": "Path traversal attempt blocked!"}
            
        try:
            with open(target_path, 'r') as f:
                content = f.read()
            return {"result": {"content": content}}
        except Exception as e:
            return {"error": str(e)}

payload = json.dumps({
    "method": "tools/call",
    "params": {
        "name": "read_file",
        "arguments": {"path": "../../../../etc/passwd"}
    }
})

print("Secure Output:", handle_request_secure(payload))
```
