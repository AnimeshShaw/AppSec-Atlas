---
title: 03. GraphQL Code Examples & Attack Scenarios
description: Production-grade code examples showcasing vulnerable vs secure implementations
  in Python, Node.js, Go, and Java across key GraphQL attack scenarios.
keywords:
- GraphQL
- Code
- Examples
- Python
- GraphQL
- Node
- js
- Apollo
- Go
- gqlgen
- Java
- Spring
- GraphQL
- Secure
- Coding
slug: /web-and-api/graphql-security/code-examples
---


# 03. GraphQL Code Examples & Attack Scenarios

This chapter provides runnable, production-grade code snippets contrasting **Vulnerable (❌)** and **Secure (✅)** implementations across major backend ecosystems: **Node.js (TypeScript/JavaScript)**, **Python**, **Go**, and **Java**.

---

## 1. Introspection Hardening & Error Masking

### Scenario 1: Node.js (Apollo Server v4)

#### ❌ Vulnerable Implementation: Introspection & Stack Traces Exposed
```typescript
// VULNERABLE: Introspection enabled explicitly or defaults in production;
// full stack traces returned in errors array!
import { ApolloServer } from '@apollo/server';
import { startStandaloneServer } from '@apollo/server/standalone';
import { typeDefs, resolvers } from './schema';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // ❌ Exposed schema introspection in production!
  includeStacktraceInErrorResponses: true, // ❌ Exposes database stack traces!
});

await startStandaloneServer(server, { listen: { port: 4000 } });
```

#### ✅ Secure Implementation: Environment-Aware Introspection & Masked Errors
```typescript
// SECURE: Introspection disabled in production, error stack traces masked
import { ApolloServer } from '@apollo/server';
import { ApolloServerPluginLandingPageDisabled } from '@apollo/server/plugin/disabled';
import { typeDefs, resolvers } from './schema';

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  // ✅ Disable introspection in production environment
  introspection: !IS_PRODUCTION,
  // ✅ Strip internal exception stack traces from response errors
  includeStacktraceInErrorResponses: false,
  formatError: (formattedError, error) => {
    // ✅ Log internal error details server-side securely
    console.error('[GraphQL Error]', {
      message: formattedError.message,
      path: formattedError.path,
      originalError: error,
    });

    // Mask database/internal errors before sending response to client
    if (formattedError.extensions?.code === 'INTERNAL_SERVER_ERROR') {
      return {
        message: 'An internal server error occurred. Please contact support.',
        locations: formattedError.locations,
        path: formattedError.path,
      };
    }
    return formattedError;
  },
  plugins: IS_PRODUCTION ? [ApolloServerPluginLandingPageDisabled()] : [],
});
```

---

### Scenario 2: Python (FastAPI + Strawberry)

#### ❌ Vulnerable Implementation
```python
# VULNERABLE: Strawberry GraphQL server with introspection unconstrained
from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
import strawberry

@strawberry.type
class Query:
    @strawberry.field
    def secret_data(self) -> str:
        return "Sensitive Internal API Key"

schema = strawberry.Schema(query=Query)
# ❌ Introspection remains enabled by default on all environments
graphql_app = GraphQLRouter(schema)

app = FastAPI()
app.include_router(graphql_app, prefix="/graphql")
```

#### ✅ Secure Implementation
```python
# SECURE: Environment-gated introspection and custom extension error filter
import os
from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
from strawberry.extensions import Extension
import strawberry

class MaskInternalErrorsExtension(Extension):
    """Custom Strawberry extension to strip sensitive tracebacks from error output."""
    def on_request_end(self):
        execution_context = self.execution_context
        if execution_context.errors:
            for error in execution_context.errors:
                # Log actual exception server-side
                print(f"[SECURITY LOG] Internal exception: {error.original_error}")
                # Mask user-facing message if it contains SQL/DB hints
                if "sqlalchemy" in str(error).lower() or "postgres" in str(error).lower():
                    error.message = "A database operation error occurred."

IS_PROD = os.getenv("ENV") == "production"

@strawberry.type
class Query:
    @strawberry.field
    def public_info(self) -> str:
        return "Public Data"

# ✅ Disable introspection in production via schema configuration
schema = strawberry.Schema(
    query=Query,
    extensions=[MaskInternalErrorsExtension] if IS_PROD else []
)

graphql_app = GraphQLRouter(
    schema=schema,
    allow_queries_via_get=False, # ✅ Require POST requests to mitigate CSRF
)

app = FastAPI()
app.include_router(graphql_app, prefix="/graphql")
```

---

## 2. Query Depth & Complexity Limit Enforcement

### Scenario 1: Node.js (graphql-depth-limit & graphql-validation-complexity)

#### ❌ Vulnerable: Unlimited Nested Execution
```javascript
// VULNERABLE: No depth or complexity rules configured
const server = new ApolloServer({ typeDefs, resolvers });
```

#### ✅ Secure: Enforcing Max Depth = 5 & Max Complexity Score = 1000
```javascript
import { ApolloServer } from '@apollo/server';
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const MAX_QUERY_DEPTH = 5;
const MAX_QUERY_COMPLEXITY = 1000;

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    // ✅ Reject queries nested deeper than 5 levels
    depthLimit(MAX_QUERY_DEPTH),
    // ✅ Calculate static node complexity and reject queries exceeding cost threshold
    createComplexityLimitRule(MAX_QUERY_COMPLEXITY, {
      onCost: (cost) => console.log(`[GraphQL Cost] Query complexity cost: ${cost}`),
      formatErrorMessage: (cost) =>
        `Query complexity score of `${cost} exceeds maximum allowed threshold of $`{MAX_QUERY_COMPLEXITY}.`,
    }),
  ],
});
```

---

### Scenario 2: Go (gqlgen Complexity Calculation)

#### ❌ Vulnerable: Default Unlimited Gqlgen Complexity
```go
// VULNERABLE: Server created without complexity limit handler
package main

import (
	"net/http"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
)

func main() {
	srv := handler.NewDefaultServer(NewExecutableSchema(Config{Resolvers: &Resolver{}}))
	http.Handle("/", playground.Handler("GraphQL", "/query"))
	http.Handle("/query", srv)
	http.ListenAndServe(":8080", nil)
}
```

#### ✅ Secure: Setting Maximum Complexity & Custom Field Cost in Go
```go
// SECURE: Gqlgen configured with max complexity & custom field multipliers
package main

import (
	"net/http"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
)

func main() {
	c := Config{Resolvers: &Resolver{}}

	// ✅ Assign custom high complexity cost to resource-intensive resolvers
	c.Complexity.Query.Users = func(childComplexity int, limit *int) int {
		if limit != nil {
			return childComplexity * (*limit) // Cost scales dynamically with requested limit!
		}
		return childComplexity * 10
	}

	srv := handler.New(NewExecutableSchema(c))

	// ✅ Reject queries exceeding total complexity threshold of 250 points
	srv.Use(extension.FixedComplexityLimit(250))

	http.Handle("/query", srv)
	http.ListenAndServe(":8080", nil)
}
```

---

## 3. Field-Level Authorization (BOLA / BFLA Defenses)

### Scenario 1: Java (Spring Boot GraphQL & Custom Security Directives)

#### ❌ Vulnerable: Unprotected Child Resolver (BOLA Vulnerability)
```java
// VULNERABLE: Child resolver returns sensitive user profile without identity check
@Controller
public class UserController {

    @QueryMapping
    public User user(@Argument String id) {
        // Top level lookup
        return userRepository.findById(id);
    }

    @SchemaMapping(typeName = "User", field = "taxIdentifier")
    public String getTaxIdentifier(User user) {
        // ❌ VULNERABLE: Returns SSN/Tax ID for ANY User object requested in a query!
        // No verification that context authenticated user owns this 'user' instance!
        return user.getTaxIdentifier();
    }
}
```

#### ✅ Secure: Context-Aware Field Authorization Verification
```java
// SECURE: Field resolver validates authenticated principal against requested resource
@Controller
public class UserController {

    @QueryMapping
    public User user(@Argument String id) {
        return userRepository.findById(id);
    }

    @SchemaMapping(typeName = "User", field = "taxIdentifier")
    public String getTaxIdentifier(User user, Authentication authentication) {
        // ✅ SECURE: Verify caller context principal
        String currentUserId = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        // Enforce Object Level Authorization (BOLA defense)
        if (!isAdmin && !user.getId().equals(currentUserId)) {
            throw new AccessDeniedException("Unauthorized to access requested field 'taxIdentifier'.");
        }

        return user.getTaxIdentifier();
    }
}
```

---

## 4. N+1 Query Resolution with DataLoaders

### Scenario 1: Node.js (DataLoader Implementation)

#### ❌ Vulnerable: `1 + N` Database Query Storm
```typescript
// VULNERABLE: Resolving author individually for every post in a list
const resolvers = {
  Query: {
    posts: async () => db.query('SELECT * FROM posts LIMIT 100'), // 1 Query
  },
  Post: {
    author: async (post) => {
      // ❌ Executes 100 separate database queries for 100 posts! (N+1 Problem)
      return db.query('SELECT * FROM users WHERE id = ?', [post.authorId]);
    },
  },
};
```

#### ✅ Secure: Batching Resolvers using DataLoader
```typescript
// SECURE: Batching and caching database lookups across execution turn
import DataLoader from 'dataloader';

// DataLoader batches array of authorIDs: [1, 2, 5, 2, 1] -> Single Query: WHERE id IN (1, 2, 5)
const batchAuthors = async (authorIds: readonly string[]) => {
  const authors = await db.query(
    'SELECT * FROM users WHERE id IN (?)',
    [Array.from(new Set(authorIds))]
  );
  // Map returned database rows back to exact requested ID order
  const authorMap = new Map(authors.map((a) => [a.id, a]));
  return authorIds.map((id) => authorMap.get(id) || null);
};

// Instantiated per HTTP request context!
export const createLoaders = () => ({
  authorLoader: new DataLoader(batchAuthors),
});

const resolvers = {
  Query: {
    posts: async () => db.query('SELECT * FROM posts LIMIT 100'),
  },
  Post: {
    author: async (post, _args, context) => {
      // ✅ Loads author via batched DataLoader (1 single SQL IN query instead of 100!)
      return context.loaders.authorLoader.load(post.authorId);
    },
  },
};
```

---

*Next Chapter: [04. Production-Grade Defenses & Architecture →](04-defenses.md)*
