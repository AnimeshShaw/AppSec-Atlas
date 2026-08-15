---
sidebar_position: 2
title: 02. Network Isolation Testing
---

# Network Isolation Testing

## 1. The Concept (ELI5)

Imagine you have a VIP lounge (your database) inside a club (your private network). You tell the bouncer (the firewall) that only bartenders (backend servers) are allowed into the VIP lounge. 

But what if someone climbs through the air vent? What if a regular customer puts on a bartender's shirt? 

Network Isolation Testing in Security Chaos Engineering is the act of intentionally dropping a suspicious actor into your network—or altering the routing rules—to see if your microservices correctly block traffic they shouldn't be receiving. It validates your **Zero Trust** architecture. If Server A doesn't need to talk to Server B, we intentionally make Server A try to talk to Server B to ensure the network drops the connection and the alert goes off.

## 2. The Visual

```mermaid
architecture-diagram
```
Wait, Mermaid architecture diagrams aren't always supported, let's use a standard flowchart or sequence.

```mermaid
graph TD
    subgraph VPC [Virtual Private Cloud]
        subgraph Public Subnet
            WAF[Web App Firewall]
            Web[Web Server]
        end
        
        subgraph Private Subnet
            App[App Server]
            ChaosAgent[Chaos Experiment: Rogue Container]
        end
        
        subgraph Secure Subnet
            DB[(Database)]
        end
    end

    WAF --> Web
    Web --> App
    App --> DB
    
    ChaosAgent -- "1. Attempts SSH/SQL connection" -.-> DB
    DB -- "2. Drops connection (Security Group)" --> Blocked((Blocked))
    ChaosAgent -- "3. Attempts API call" -.-> Web
    Web -- "4. Drops connection (mTLS failure)" --> Blocked
```

## 3. The Code

When injecting network chaos, you want to see how the application behaves when network dependencies vanish or behave maliciously. A common pattern is missing timeout controls, leaving the application vulnerable to DoS if a downstream service hangs (e.g., due to a chaos experiment that drops packets instead of rejecting them).

### ❌ Vulnerable Code (No Timeouts, Implicit Trust)

This code implicitly trusts the network and waits forever if the network drops packets.

**Go:**
```go
func FetchInternalData() ([]byte, error) {
    // VULNERABLE: Default HTTP client has no timeout.
    // A chaos experiment dropping packets will cause this to hang forever,
    // consuming goroutines and causing a Denial of Service.
    resp, err := http.Get("http://internal-api.svc.cluster.local/data")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    return io.ReadAll(resp.Body)
}
```

**Python:**
```python
import requests

def fetch_internal_data():
    # VULNERABLE: No timeout specified. 
    # If the network blackholes the traffic, this blocks indefinitely.
    response = requests.get("http://internal-api/data")
    return response.json()
```

**TypeScript/Node.js:**
```typescript
import fetch from 'node-fetch';

async function fetchInternalData() {
    // VULNERABLE: Promise may never resolve if network drops packets
    const response = await fetch("http://internal-api/data");
    return await response.json();
}
```

### ✅ Production-Ready Secure Code (Defensive Timeouts & mTLS)

Secure code always assumes the network is hostile or broken. It enforces strict timeouts and ideally requires mutual TLS (mTLS) for internal communication.

**Go:**
```go
func FetchInternalData(ctx context.Context) ([]byte, error) {
    // 1. Enforce strict timeout
    client := &http.Client{
        Timeout: 5 * time.Second,
    }

    req, err := http.NewRequestWithContext(ctx, "GET", "https://internal-api.svc.cluster.local/data", nil)
    if err != nil {
        return nil, err
    }

    // 2. Ideally, configure mTLS in the Transport here
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Network failure or timeout: %v", err)
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }

    return io.ReadAll(resp.Body)
}
```

**Python:**
```python
import requests
import logging

def fetch_internal_data():
    try:
        # Enforce strict timeout
        response = requests.get(
            "https://internal-api/data",
            timeout=(3.0, 10.0), # 3s connect, 10s read
            verify="/etc/ssl/certs/ca-certificates.crt" # Verify internal CA
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        logging.error("Service timed out. Network isolation/chaos in effect.")
        raise
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        raise
```

**TypeScript/Node.js:**
```typescript
import axios from 'axios';
import https from 'https';
import logger from './logger';

async function fetchInternalData() {
    try {
        // Enforce timeout and strict SSL
        const agent = new https.Agent({
            rejectUnauthorized: true
        });

        const response = await axios.get("https://internal-api/data", {
            timeout: 5000,
            httpsAgent: agent
        });
        
        return response.data;
    } catch (error) {
        logger.error(`Network error or timeout: ${error.message}`);
        throw new Error("Internal service unreachable");
    }
}
```

## 4. The Guardrail

To prevent network over-permissiveness at the infrastructure layer, we use Terraform to ensure Security Groups do not allow unrestricted internal traffic, enforcing strict boundaries.

**Terraform (AWS Security Group Check using Checkov/Rego):**
```hcl
# VULNERABLE: Allows all traffic within the VPC
resource "aws_security_group_rule" "allow_all_internal" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.db.id
}

# SECURE: Only allows specific port from a specific security group
resource "aws_security_group_rule" "allow_app_to_db" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app_servers.id
  security_group_id        = aws_security_group.db.id
}
```

**Semgrep/Rego Rule to enforce Timeout in Python requests:**
```yaml
rules:
  - id: requests-missing-timeout
    patterns:
      - pattern: requests.$METHOD(...)
      - pattern-not: requests.$METHOD(..., timeout=$T, ...)
    message: "Network calls must have a timeout defined to prevent DoS during network chaos or degradation."
    languages: [python]
    severity: ERROR
```
