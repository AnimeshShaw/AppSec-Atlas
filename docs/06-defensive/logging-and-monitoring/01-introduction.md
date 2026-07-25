# 01 - Introduction to Logging & SIEM

In modern application security, **visibility is survival**. If an attacker breaches your system and you have no logs, you have no way to detect the intrusion, understand the impact, or evict the threat actor. 

## 🏗️ Centralized Logging Architecture

A centralized logging architecture aggregates logs from various sources (applications, firewalls, operating systems) into a single, searchable platform.

```ascii
[ Web Server ] --(logs)--> [ Log Shipper ] --\
[ Database ]   --(logs)--> [ Log Shipper ] ---> [ Log Ingestion/Queue ] ---> [ SIEM ]
[ Firewall ]   --(logs)--> [ Log Shipper ] --/
```

- **Log Shippers:** Agents like Filebeat, Fluentd, or Promtail that collect and forward logs.
- **Log Ingestion/Queue:** Brokers like Kafka or Logstash that parse, enrich, and buffer logs.
- **SIEM (Security Information and Event Management):** The central brain where logs are stored, indexed, and analyzed.

## 🧠 SIEM vs. SOAR

- **SIEM (Security Information and Event Management):** The system that aggregates logs, normalizes data, and correlates events to trigger alerts based on detection rules.
  - *Examples:* Splunk, Elastic Security, Microsoft Sentinel, OpenSearch.
- **SOAR (Security Orchestration, Automation, and Response):** The system that takes SIEM alerts and executes automated playbooks to remediate the threat.
  - *Examples:* Cortex XSOAR, Splunk SOAR, Tines, Shuffle.

## 🔍 Major SIEM Platforms Overview

1. **Elastic Security:** Built on the ELK stack (Elasticsearch, Logstash, Kibana). Excellent for full-text search, highly scalable, and heavily utilizes the Elastic Common Schema (ECS).
2. **Splunk:** The enterprise gold standard. Uses SPL (Search Processing Language) for powerful data manipulation and correlation.
3. **OpenSearch:** An open-source fork of Elasticsearch (led by AWS). Often used with Fluent-bit and Dashboards as a cost-effective SIEM alternative.
