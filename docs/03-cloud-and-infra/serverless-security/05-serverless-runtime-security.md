---
title: "05 - Serverless Runtime Security"
description: "Traditional endpoint security agents (like EDRs or Antivirus) cannot be installed inside serverless environments like AWS Lambda. This requires a shif..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Serverless Security", "05 Serverless Runtime Security.Md"]
---

# 05 - Serverless Runtime Security

Traditional endpoint security agents (like EDRs or Antivirus) cannot be installed inside serverless environments like AWS Lambda. This requires a shift in how we monitor and defend the runtime execution of our code.

## ⏱️ Timeout and Concurrency Attacks (Denial of Wallet)

Because serverless functions are billed by execution time and memory usage, attackers can intentionally trigger long-running processes to exhaust resources, leading to a **Denial of Wallet (DoW)** attack.

### Defense Strategies:
1. **Strict Timeouts:** Set the lowest possible timeout for your function. If an API request typically takes 200ms, set the timeout to 3 seconds, not the AWS maximum of 15 minutes.
2. **Concurrency Limits:** Use Reserved Concurrency to limit how many instances of a function can run simultaneously. This prevents an attacker from spinning up thousands of concurrent executions and draining your budget.
3. **API Gateway Throttling:** Implement rate limiting and usage plans on API Gateway to throttle abusive IPs before they ever reach the Lambda function.

## 🛡️ Runtime Protection Tools (Serverless Defenders)

Specialized security tools (like Prisma Cloud, DataDog ASM, or AWS Lambda Extensions) can be injected into the serverless runtime to monitor behavior.

### How they work:
These tools are usually deployed as **Lambda Layers**. A Layer is a ZIP archive containing libraries or dependencies. By including a security layer, the tool wraps your function handler.

When the function is invoked, the security layer intercepts the event, inspects it for malicious payloads (like a WAF), and monitors the execution for anomalies:
- **File System Monitoring:** Alerts if the function tries to write executables to `/tmp`.
- **Network Monitoring:** Blocks outbound connections to unknown IP addresses (mitigating SSRF and reverse shells).
- **Process Monitoring:** Blocks unexpected child processes (e.g., stopping `curl` or `bash` from executing).

## 📊 Logging and Observability

In the absence of traditional network logs, application logging is your primary source of security truth.

1. **Centralized Logging:** Ensure all functions forward logs to a central system (e.g., AWS CloudWatch, Datadog, Splunk).
2. **Structured Logging:** Log in JSON format to make searching and alerting easier.
3. **Log Context:** Include the `awsRequestId`, `userId`, and `sourceIp` (if available via API Gateway) in every log line to trace a transaction across multiple functions.

### Example: Structured Logging in Node.js

```javascript
exports.handler = async (event, context) => {
    const logger = {
        info: (msg, data) => console.log(JSON.stringify({ level: 'INFO', msg, awsRequestId: context.awsRequestId, ...data })),
        error: (msg, data) => console.error(JSON.stringify({ level: 'ERROR', msg, awsRequestId: context.awsRequestId, ...data }))
    };

    try {
        // ... business logic ...
        logger.info("Order processed successfully", { orderId: 12345 });
        return { statusCode: 200, body: "Success" };
    } catch (e) {
        logger.error("Failed to process order", { error: e.message });
        throw e;
    }
};
```
