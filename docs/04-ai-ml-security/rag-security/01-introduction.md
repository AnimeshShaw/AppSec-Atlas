# 01 - Introduction to RAG Security

## Retrieval-Augmented Generation (RAG) Architecture
RAG combines the reasoning capabilities of LLMs with the dynamic information retrieval abilities of Vector Databases. 

### The RAG Pipeline
1. **Data Ingestion**: Documents are chunked and converted into dense vector embeddings using models like OpenAI's `text-embedding-ada-002`.
2. **Storage**: Embeddings are stored in a Vector Database (e.g., Pinecone, Qdrant, Chroma) alongside metadata.
3. **Retrieval**: A user query is embedded and compared against stored vectors using semantic similarity (e.g., cosine similarity).
4. **Generation**: Top-k matching documents are appended to the LLM prompt as context, enabling informed generation.

## Vector Search & Embeddings
Embeddings represent semantic meaning in a high-dimensional space. Vector search retrieves documents based on meaning rather than keyword matching. While powerful, this means malicious payloads semantically similar to a user's query can easily be retrieved and injected into the LLM context.

## Threat Landscape
- **Indirect Prompt Injection**: Malicious instructions embedded in retrieved documents (PDFs, websites) that hijack the LLM's goal.
- **Data Poisoning**: Attackers injecting false or malicious data into the vector DB to alter the system's factual responses.
- **Cross-Tenant Data Leakage**: In multi-tenant environments, a lack of strict row-level security (RLS) can allow User A to retrieve User B's sensitive documents.
