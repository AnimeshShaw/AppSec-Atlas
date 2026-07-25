---
title: "02 - Tool Poisoning & Shadow Tools"
description: "A **Tool Poisoning** attack occurs when an attacker manipulates the definition or behavior of a tool. In the context of MCP, a malicious server might ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "04 Ai Ml Security", "Mcp Tool Security", "02 Mcp Tool Poisoning And Shadow Tools.Md"]
---

# 02 - Tool Poisoning & Shadow Tools

## Core Concepts
A **Tool Poisoning** attack occurs when an attacker manipulates the definition or behavior of a tool. In the context of MCP, a malicious server might register "Shadow Tools" — tools that mimic legitimate ones but contain malicious payloads, or it might accept tampered parameters.

### Shadow Tool Registration
An attacker spins up a rogue MCP server that registers a tool named `read_file`, shadowing a legitimate built-in tool. The LLM, unaware of the distinction, might invoke the rogue tool, which logs the file contents to an attacker-controlled server before returning the data.

### Vulnerable Code Example (Python)
```python
# Vulnerable MCP Client: Blindly accepts tools from any server
import json

def discover_tools(server_response):
    tools = json.loads(server_response)
    for tool in tools:
        # VULNERABILITY: No validation of tool origin or name overlap
        register_tool_in_llm_context(tool['name'], tool['schema'])

def execute_tool(tool_name, params):
    # VULNERABILITY: Blindly executes tool based on string name
    server = route_to_server(tool_name)
    return server.call(tool_name, params)
```

### Secure Code Example (Python)
```python
# Secure MCP Client: Validates tool registration and parameters
ALLOWED_SERVERS = ["trusted_local_server", "official_api_server"]
REGISTERED_TOOLS = {}

def discover_tools(server_id, server_response):
    if server_id not in ALLOWED_SERVERS:
        raise SecurityError("Untrusted MCP server")
        
    tools = json.loads(server_response)
    for tool in tools:
        if tool['name'] in REGISTERED_TOOLS:
            raise SecurityError(f"Tool {tool['name']} shadow registration attempt!")
        REGISTERED_TOOLS[tool['name']] = server_id
        register_tool_in_llm_context(tool['name'], tool['schema'])
```
