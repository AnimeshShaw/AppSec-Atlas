# 03 - Vector DB Access Control

## Multi-tenancy in Vector DBs
In a multi-tenant application (e.g., a SaaS AI assistant), storing documents from all users in a single vector collection without strict isolation leads to cross-tenant data leakage.

## Namespace Isolation vs. Metadata Filtering
1. **Namespaces**: Creating separate collections/namespaces per user. Highly secure but harder to scale.
2. **Metadata Filtering**: Storing documents with a `tenant_id` metadata tag and filtering during retrieval. This acts as Row-Level Security (RLS).

### Code Example: Secure Metadata Filtering (LangChain + Pinecone)

#### Vulnerable: No Filtering
```python
retriever = vectorstore.as_retriever(search_kwargs={"k": 5})
# Retrieves top 5 chunks globally!
```

#### Secure: Tenant-Specific Metadata Filtering
```python
user_id = "user_12345"

# Only retrieve chunks that belong to the specific user
retriever = vectorstore.as_retriever(
    search_kwargs={
        "k": 5,
        "filter": {"tenant_id": user_id}
    }
)

qa_chain = RetrievalQA.from_chain_type(
    llm=OpenAI(),
    retriever=retriever
)
```
Always enforce the `tenant_id` at the backend API layer. Never trust the client to provide their tenant ID in the search query.
