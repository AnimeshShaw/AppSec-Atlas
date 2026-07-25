# Retrieval-Augmented Generation (RAG) Security Guide

Welcome to the AppSec Atlas guide on Retrieval-Augmented Generation (RAG) Security.

## Overview
Retrieval-Augmented Generation (RAG) empowers LLMs with external knowledge bases. However, this architectural pattern introduces new attack surfaces such as indirect prompt injection, data poisoning, and cross-tenant data leakage via vector databases. This guide dives deep into attacking and securing RAG applications.

## Prerequisites
- Basic understanding of Large Language Models (LLMs) and Prompt Engineering.
- Familiarity with Vector Databases (e.g., Pinecone, Qdrant, Chroma).
- Proficiency in Python, specifically frameworks like LangChain or LlamaIndex.

## Learning Objectives
1. Understand the RAG architecture and its threat landscape.
2. Exploit Document Poisoning and Indirect Injections in RAG setups.
3. Implement strict multi-tenancy and Metadata filtering (Row-Level Security) in Vector Databases.
4. Apply Retrieval Sanitization and Guardrails before context injection.
5. Evaluate RAG security using specialized frameworks.

## Navigation
- [01 Introduction](01-introduction.md)
- [02 RAG Poisoning & Indirect Injection](02-rag-poisoning-and-indirect-injection.md)
- [03 Vector DB Access Control](03-vector-db-access-control.md)
- [04 Retrieval Sanitization & Guardrails](04-retrieval-sanitization-and-guardrails.md)
- [05 RAG Security Evaluations](05-rag-security-evaluations.md)
- [06 Hands-on Lab](06-hands-on-lab.md)
- [07 References](07-references.md)
