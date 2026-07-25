---
title: "02. Asset Discovery & Scope Mapping"
description: "Mapping an organization's asset inventory helps identify unlinked API endpoints and forgotten subdomains."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Bug Bounty", "02 Reconnaissance And Scope Mapping.Md"]
---

# 02. Asset Discovery & Scope Mapping

Mapping an organization's asset inventory helps identify unlinked API endpoints and forgotten subdomains.

---

## 1. Asset Discovery Pipeline

```bash
# 1. Passive Subdomain Discovery
subfinder -d techcorp.com -o subdomains.txt

# 2. HTTP Probing
cat subdomains.txt | httpx -title -status-code -tech-detect -o live_targets.txt

# 3. Endpoint Crawling
katana -u live_targets.txt -jc -o endpoints.txt
```

---

*Next Chapter: [03. High-Value Vulnerability Analysis →](03-high-value-vulnerability-analysis.md)*
