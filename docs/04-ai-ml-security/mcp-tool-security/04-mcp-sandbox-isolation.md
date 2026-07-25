---
title: "04 - MCP Sandbox Isolation"
description: "When building MCP servers that execute code (e.g., Python REPL tools) or interact with the filesystem, running them directly on the host machine is ca..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Mcp Tool Security", "04 Mcp Sandbox Isolation.Md"]
---

# 04 - MCP Sandbox Isolation

## Containerized Execution
When building MCP servers that execute code (e.g., Python REPL tools) or interact with the filesystem, running them directly on the host machine is catastrophic.

### Docker & gVisor
Wrap your MCP servers in strict Docker containers. For enhanced security against container escape vulnerabilities, use a sandboxed container runtime like **gVisor** (`runsc`).

### Secure Docker configuration (`docker-compose.yml`)
```yaml
version: '3.8'
services:
  mcp_code_server:
    image: my-mcp-python-server
    runtime: runsc  # gVisor runtime
    network_mode: "none" # Disable network access
    read_only: true # Read-only root filesystem
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    volumes:
      - ./sandbox_workspace:/workspace:rw
    environment:
      # Sanitize environment variables - do NOT pass host API keys here unless explicitly needed
      - WORKSPACE_DIR=/workspace
```

### Environment Variable Sanitization
Never pass the host's `AWS_ACCESS_KEY_ID` or other credentials into the MCP server container unless that specific server is dedicated to AWS operations. Use short-lived, scoped credentials.
