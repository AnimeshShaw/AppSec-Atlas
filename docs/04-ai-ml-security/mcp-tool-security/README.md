# Model Context Protocol (MCP) & Tool-Use Security

Welcome to the MCP & Tool-Use Security guide. This module covers the security implications of integrating AI assistants with external tools via the Model Context Protocol (MCP) and custom tool execution environments.

## Overview
Large Language Models (LLMs) are increasingly integrated with tools, enabling them to execute code, fetch data, and perform actions on behalf of the user. While powerful, this capability introduces significant security risks, primarily around unauthorized actions, tool poisoning, and data exfiltration. The Model Context Protocol (MCP) standardizes this communication, making it crucial to secure the MCP client-server architecture.

## Prerequisites
- Understanding of LLM architecture and prompt injection.
- Familiarity with JSON-RPC (the protocol underlying MCP).
- Basic knowledge of Python and Docker for lab exercises.

## Learning Objectives
- Understand the MCP architecture and threat landscape.
- Identify and mitigate tool poisoning and shadow tool registration attacks.
- Implement least privilege, permission scopes, and Human-In-The-Loop (HITL) approval patterns.
- Secure MCP server execution using sandboxing technologies like Docker and gVisor.
- Implement robust logging and auditing for MCP JSON-RPC messages.

## Navigation
1. [Introduction to MCP Security](01-introduction.md)
2. [Tool Poisoning & Shadow Tools](02-mcp-tool-poisoning-and-shadow-tools.md)
3. [Least Privilege & Permission Scopes](03-least-privilege-and-permission-scopes.md)
4. [MCP Sandbox Isolation](04-mcp-sandbox-isolation.md)
5. [MCP Security Auditing](05-mcp-security-auditing.md)
6. [Hands-On Lab: MCP Exploitation & Mitigation](06-hands-on-lab.md)
7. [References & Resources](07-references.md)
