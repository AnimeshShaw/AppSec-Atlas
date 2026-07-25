---
title: "Social Engineering & Phishing Defense"
description: "Social Engineering remains the most successful initial access vector for modern adversaries. By manipulating human psychology rather than exploiting t..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Social Engineering", "Readme.Md"]
---

# Social Engineering & Phishing Defense

## Overview
Social Engineering remains the most successful initial access vector for modern adversaries. By manipulating human psychology rather than exploiting technical vulnerabilities, attackers bypass multi-million dollar perimeter defenses. This guide provides a comprehensive deep-dive into the mechanics of social engineering, email security protocols, and production-grade defenses against advanced phishing attacks like Adversary-in-the-Middle (AiTM).

## Prerequisites
- Basic understanding of SMTP and email delivery mechanisms.
- Familiarity with DNS records (TXT, MX, CNAME).
- Understanding of HTTP sessions, cookies, and Multi-Factor Authentication (MFA).

## Learning Objectives
- Understand the core psychological triggers used in social engineering attacks.
- Analyze email headers to identify spoofing and track message origins.
- Configure and enforce robust email authentication (SPF, DKIM, DMARC).
- Understand how AiTM proxies bypass legacy MFA (SMS, TOTP) and how to defend against them using FIDO2/WebAuthn.
- Design ethical and effective phishing simulation campaigns.
- Implement technical defenses, including domain monitoring and YARA rules for malicious attachments.

## Navigation
1. [Introduction to Social Engineering](01-introduction.md)
2. [Phishing Analysis and Email Security](02-phishing-analysis-and-email-security.md)
3. [Credential Harvesting and MFA Bypass](03-credential-harvesting-and-mfa-bypass.md)
4. [Defensive Awareness and Simulation](04-defensive-awareness-and-simulation.md)
5. [Technical Phishing Defenses](05-technical-phishing-defenses.md)
6. [Hands-On Lab: Email Header Parser & Auditor](06-hands-on-lab.md)
7. [References & Resources](07-references.md)
