---
title: 03 - Multi-Tenancy & Vector Database Access Control
description: Implement enterprise multi-tenancy, Row-Level Security (RLS), metadata
  filtering, namespace isolation, and ABAC in Pinecone, Qdrant, Milvus, and pgvector.
keywords:
- Vector
- Database
- Security
- Multi-Tenancy
- Row-Level
- Security
- Pinecone
- Qdrant
- pgvector
- LangChain
- Access
- Control
- AppSec
slug: /ai-ml-security/rag-security/vector-db-access-control
---


# 03 - Multi-Tenancy & Vector Database Access Control

In enterprise software architecture, multi-tenancy guarantees that User A cannot read, search, or infer data belonging to User B. When vector databases are introduced into RAG pipelines, traditional authorization checks are easily compromised if vector search is executed globally across an entire collection without tenant boundaries.

This chapter analyzes vector multi-tenancy design patterns, identifies cross-tenant data leakage vectors, and delivers production implementations across **Python, Node.js, Go, and Java**.

---

## 1. Multi-Tenancy Design Patterns in Vector Databases

Vector databases support three primary architectures for isolating multi-tenant data, each presenting distinct security and operational trade-offs:

```
                  VECTOR DATABASE MULTI-TENANCY PATTERNS

Pattern 1: Index Per Tenant         Pattern 2: Namespace Isolation      Pattern 3: Metadata Filtering (RLS)
┌────────────────────────────┐      ┌────────────────────────────┐      ┌────────────────────────────┐
│ Collection: Tenant_A       │      │ Collection: Main_Index     │      │ Collection: Shared_Index   │
│ ┌────────────────────────┐ │      │ ┌────────────────────────┐ │      │ ┌────────────────────────┐ │
│ │ Vector 1, Vector 2     │ │      │ │ Namespace: Tenant_A    │ │      │ │ Vector 1 [tenant_id: A]│ │
│ └────────────────────────┘ │      │ │ ┌────────────────────┐ │ │      │ │ Vector 2 [tenant_id: B]│ │
├────────────────────────────┤      │ │ │ Vector 1, Vector 2 │ │ │      │ │ Vector 3 [tenant_id: A]│ │
│ Collection: Tenant_B       │      │ │ └────────────────────┘ │ │      │ └────────────────────────┘ │
│ ┌────────────────────────┐ │      │ └────────────────────────┘ │      └────────────────────────────┘
│ │ Vector 3, Vector 4     │ │      └────────────────────────────┘
│ └────────────────────────┘ │
└────────────────────────────┘
```

### Comparative Architecture Matrix

| Dimension | Pattern 1: Index / Collection Per Tenant | Pattern 2: Namespace Isolation | Pattern 3: Server-Side Metadata Filtering (RLS) |
| :--- | :--- | :--- | :--- |
| **Isolation Level** | **Physical Isolation** (Maximum Security) | **Logical Isolation** (High Security) | **Logical Isolation** (Moderate/High Security) |
| **Blast Radius** | Contained to single tenant index | Contained to namespace segment | High (Single query bug leaks global data) |
| **Max Capacity** | Restricted by cluster index limits (e.g., 100-1000) | Hundreds of thousands of namespaces | Millions of tenants in a single collection |
| **Cost Efficiency** | Poor (High memory/CPU overhead per index) | High (Shared index structures) | Maximum (Optimal memory utilization) |
| **Implementation** | Provision separate collection per tenant | Specify `namespace` parameter in query SDK | Mandate `filter={"tenant_id": id}` on query |

> [!IMPORTANT]
> **Architectural Recommendation:** For high-compliance SaaS applications (FinTech, HealthCare), adopt **Namespace Isolation** or **Physical Index Isolation**. For large-scale SaaS with millions of tenants, adopt **Metadata Filtering**, but enforce filter application deterministically at the backend server layer or database engine layer (e.g., `pgvector` RLS).

---

## 2. Cross-Tenant Data Leakage Vectors

### Leakage Vector A: Developer Omission of Metadata Filters
If a backend developer constructs a vector similarity search and forgets to include the `tenant_id` filter dictionary, the vector database executes a global Approximate Nearest Neighbor (ANN) search across all tenants:

```python
# VULNERABLE: Global ANN Search returns document vectors from ANY tenant!
results = vector_store.similarity_search(query="q3 financial statements", k=5)
```

### Leakage Vector B: Client-Side Filter Tampering
If the frontend client supplies the filter payload in the REST request (e.g., `POST /api/v1/search {"query": "foo", "filter": {"tenant_id": "tenant_123"}}`), an attacker modifies the payload to query another organization's `tenant_id`.

### Leakage Vector C: Proximity Leakage & Score Oracle
Even if text content is redacted, if similarity score metrics (e.g., `score = 0.92`) or distance vectors are returned without authorization checks, attackers can perform **Vector Membership Inference Attacks**. By probing the embedding space with boundary queries, attackers deduce whether a specific target vector exists within another tenant's private collection.

---

## 3. Production Implementations across Languages

### Python: Enforcing Backend Metadata Isolation (Pinecone & Qdrant)

```python
# secure_vector_service.py - SECURE Python Backend Service
import os
from typing import List, Dict, Any
from pinecone import Pinecone
from langchain_openai import OpenAIEmbeddings

class SecureVectorSearchService:
    def __init__(self, api_key: str, index_name: str):
        self.pc = Pinecone(api_key=api_key)
        self.index = self.pc.Index(index_name)
        self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small")

    def search_tenant_documents(self, tenant_id: str, user_query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        # SECURITY CRITICAL: Validate tenant_id from verified JWT context, NOT client payload!
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("Unauthorized: Invalid or missing tenant_id context.")

        query_vector = self.embeddings.embed_query(user_query)

        # Enforce server-side metadata filtering combined with namespace isolation
        response = self.index.query(
            vector=query_vector,
            top_k=top_k,
            namespace=f"tenant_{tenant_id}",  # SECURE 1: Namespace boundary
            filter={
                "tenant_id": {"$eq": tenant_id},  # SECURE 2: Metadata RLS tag
                "status": {"$eq": "ACTIVE"}
            },
            include_metadata=True
        )

        results = []
        for match in response.matches:
            results.append({
                "id": match.id,
                "score": match.score,
                "text": match.metadata.get("text", ""),
                "document_id": match.metadata.get("document_id")
            })
        return results
```

---

### Node.js / TypeScript: Secure Multi-Tenant Pinecone Search

```typescript
// secureVectorService.ts - SECURE Node.js Backend Service
import { Pinecone } from '@pinecone-database/pinecone';
import { OpenAIEmbeddings } from '@langchain/openai';

export interface UserContext {
  userId: string;
  tenantId: string;
  roles: string[];
}

export class SecureVectorStore {
  private pinecone: Pinecone;
  private indexName: string;
  private embeddings: OpenAIEmbeddings;

  constructor(apiKey: string, indexName: string) {
    this.pinecone = new Pinecone({ apiKey });
    this.indexName = indexName;
    this.embeddings = new OpenAIEmbeddings({ modelName: 'text-embedding-3-small' });
  }

  public async searchTenantDocs(userCtx: UserContext, query: string, topK: number = 5) {
    // SECURE 1: Enforce mandatory user context
    if (!userCtx || !userCtx.tenantId) {
      throw new Error("Security Violation: Missing tenant authorization context.");
    }

    const queryEmbedding = await this.embeddings.embedQuery(query);
    const index = this.pinecone.index(this.indexName);

    // SECURE 2: Hardcode tenant metadata filter on server-side
    const queryResponse = await index.namespace(`ns_${userCtx.tenantId}`).query({
      vector: queryEmbedding,
      topK: topK,
      filter: {
        tenant_id: { $eq: userCtx.tenantId },
        allowed_roles: { $in: userCtx.roles } // Attribute-Based Access Control (ABAC)
      },
      includeMetadata: true,
    });

    return queryResponse.matches.map(match => ({
      id: match.id,
      score: match.score,
      content: match.metadata?.text || ''
    }));
  }
}
```

---

### Go: PostgreSQL `pgvector` Native Row-Level Security (RLS)

PostgreSQL with `pgvector` offers the highest security guarantees because **Row-Level Security policies are enforced natively inside the database engine**, rendering application-level filter omission impossible.

```sql
-- schema.sql: Database-enforced Tenant Isolation for pgvector
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE document_embeddings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(64) NOT NULL,
    document_id VARCHAR(64) NOT NULL,
    content TEXT NOT NULL,
    embedding vector(1536) NOT NULL
);

-- Enable Row-Level Security
ALTER TABLE document_embeddings ENABLE ROW LEVEL SECURITY;

-- Create RLS Policy tied to session configuration variable
CREATE POLICY tenant_isolation_policy ON document_embeddings
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true));
```

```go
// secure_pgvector.go - SECURE Go backend executing queries with RLS
package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/lib/pq"
)

type VectorSearchResult struct {
	ID         string
	DocumentID string
	Content    string
	Distance   float64
}

func PerformSecureSearch(ctx context.Context, db *sql.DB, tenantID string, queryVector []float32, limit int) ([]VectorSearchResult, error) {
	// Start database transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// SECURE 1: Set database session local variable for RLS enforcement
	_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true);", tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to set tenant context: %w", err)
	}

	// SECURE 2: Execute vector search query. 
	// PostgreSQL RLS automatically filters rows where tenant_id != current_setting('app.current_tenant_id')
	query := `
		SELECT id, document_id, content, embedding <=> $1 AS distance 
		FROM document_embeddings 
		ORDER BY distance ASC 
		LIMIT $2;`

	rows, err := tx.QueryContext(ctx, query, pq.Array(queryVector), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []VectorSearchResult
	for rows.Next() {
		var res VectorSearchResult
		if err := rows.Scan(&res.ID, &res.DocumentID, &res.Content, &res.Distance); err != nil {
			return nil, err
		}
		results = append(results, res)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}
```

---

### Java: Spring AI / Enterprise Vector Security Filter

```java
// SecureVectorSearchService.java - SECURE Java Enterprise Implementation
package com.appsec.atlas.security;

import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.document.Document;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecureVectorSearchService {

    private final VectorStore vectorStore;

    public SecureVectorSearchService(VectorStore vectorStore) {
        this.vectorStore = vectorStore;
    }

    public List<Document> searchTenantContext(String userQuery) {
        // SECURE 1: Extract verified authenticated user principal from Spring Security
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SecurityException("Access Denied: Unauthenticated vector request.");
        }

        // Retrieve verified tenant ID from principal details
        String authenticatedTenantId = ((UserPrincipal) authentication.getPrincipal()).getTenantId();

        // SECURE 2: Programmatically enforce tenant metadata expression filter
        SearchRequest searchRequest = SearchRequest.query(userQuery)
                .withTopK(5)
                .withSimilarityThreshold(0.75)
                .withFilterExpression("tenant_id == '" + authenticatedTenantId + "'");

        return vectorStore.similaritySearch(searchRequest);
    }
}
```

---

> [!WARNING]
> **Audit Guidance:** Never pass client-controlled JSON parameters directly to vector database query filters without server-side schema validation and override of identity properties (`tenant_id`, `user_id`, `org_id`).
