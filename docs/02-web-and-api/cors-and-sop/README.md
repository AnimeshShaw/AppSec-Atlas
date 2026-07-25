# CORS & Same-Origin Policy

## Overview
The Same-Origin Policy (SOP) is a fundamental security concept in modern web browsers that restricts how a document or script loaded by one origin can interact with a resource from another origin. Cross-Origin Resource Sharing (CORS) is a mechanism that uses additional HTTP headers to tell browsers to give a web application running at one origin, access to selected resources from a different origin.

This guide provides an in-depth look at SOP and CORS, how they interact, common misconfigurations that lead to vulnerabilities, and how to securely implement and audit CORS policies.

## Prerequisites
- Basic understanding of HTTP protocol (requests, responses, headers).
- Familiarity with web development concepts (JavaScript, APIs).
- Understanding of web security fundamentals.

## Learning Objectives
By the end of this guide, you will be able to:
- Explain the Same-Origin Policy and why it is critical for web security.
- Understand how CORS relaxes SOP restrictions and how preflight requests work.
- Identify and exploit common CORS misconfigurations (e.g., origin reflection).
- Implement secure CORS configurations in various frameworks (Express.js, FastAPI, Flask, Nginx).
- Audit CORS configurations using automated tools and manual techniques.

## Navigation
1. [Introduction to SOP](01-introduction.md)
2. [CORS Mechanics & Headers](02-cors-mechanics-and-headers.md)
3. [CORS Misconfigurations & Exploits](03-cors-misconfigurations-and-exploits.md)
4. [Secure CORS Implementation](04-secure-cors-implementation.md)
5. [CORS Auditing Tools](05-cors-auditing-tools.md)
6. [Hands-On Lab](06-hands-on-lab.md)
7. [References](07-references.md)
