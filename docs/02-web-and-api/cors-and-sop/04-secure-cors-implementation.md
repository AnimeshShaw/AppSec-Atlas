---
title: 04 - Secure CORS Implementation & Mitigations
description: Production-ready, secure CORS implementation patterns across Node.js
  (Express), Python (FastAPI, Flask), Go (Gin), Java (Spring Boot), Nginx, and Apache.
keywords:
- AppSec
- Secure
- CORS
- Express
- CORS
- FastAPI
- CORS
- Spring
- Boot
- CORS
- Nginx
- CORS
- Defensive
- Security
- CORS
- Allowlist
slug: /web-and-api/cors-and-sop/secure-cors-implementation
---


# 04 - Secure CORS Implementation & Mitigations

To secure applications against CORS vulnerabilities, developers must move away from dynamic origin reflection and permissive wildcards. Production environments require **strict, server-side allowlists**, accurate regex boundaries, mandatory `Vary: Origin` headers, and secure gateway configurations.

---

## 1. Defensive Architectural Rules

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   PRODUCTION CORS SECURITY GOLD RULES                    │
├──────────────────────────────────────────────────────────────────────────┤
│ 1. Enforce Strict Allowlists: Maintain an explicit, hardcoded list of    │
│    authorized domains. Validate exact origin strings via O(1) set/map.   │
├──────────────────────────────────────────────────────────────────────────┤
│ 2. Never Trust 'null': Reject the `null` origin string unconditionally. │
├──────────────────────────────────────────────────────────────────────────┤
│ 3. Never Combine Wildcards with Credentials: If ACAC is true, ACAO MUST  │
│    be an exact explicit origin string, never `*`.                        │
├──────────────────────────────────────────────────────────────────────────┤
│ 4. Anchor Regex Patterns: If domain matching requires regex, explicitly  │
│    anchor with `^` and `$`, and escape all domain literal dots (`\.`).   │
├──────────────────────────────────────────────────────────────────────────┤
│ 5. Always Append `Vary: Origin`: Ensure CDNs and intermediate caches do  │
│    not serve cached CORS headers to unauthorized origins.                │
├──────────────────────────────────────────────────────────────────────────┤
│ 6. Minimize Preflight Max-Age: Restrict `Access-Control-Max-Age` to      │
│    reasonable limits (e.g., 600 - 3600 seconds) to enable fast revoking. │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Multi-Language Implementation Snippets

### A. Node.js (Express.js)

#### ❌ Insecure Pattern (Dynamic Reflection)
```javascript
// INSECURE: Echoing Origin header blindly
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});
```

#### ✅ Secure Production Pattern (`cors` middleware)
```javascript
const express = require('express');
const cors = require('cors');
const app = express();

// Strict explicit allowlist
const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://admin.example.com'
]);

const corsOptions = {
    origin: (origin, callback) => {
        // Allow requests with no origin (e.g., mobile native apps, cURL, server-to-server)
        if (!origin) {
            return callback(null, true);
        }
        
        if (ALLOWED_ORIGINS.has(origin)) {
            callback(null, true); // Origin authorized
        } else {
            callback(new Error('CORS Policy Violation: Origin not allowed'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['X-Total-Count'],
    maxAge: 600, // 10 minutes
    optionsSuccessStatus: 204
};

// Apply CORS middleware globally
app.use(cors(corsOptions));

// Ensure Vary: Origin header is set on all responses
app.use((req, res, next) => {
    res.header('Vary', 'Origin');
    next();
});

app.get('/api/v1/data', (req, res) => {
    res.json({ status: "success", data: "Protected Content" });
});
```

---

### B. Python (FastAPI)

#### ❌ Insecure Pattern (`allow_origins=["*"]` + Credentials)
```python
# INSECURE: Wildcard origins with credentials set to True
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True, # Triggers security issues or browser errors
)
```

#### ✅ Secure Production Pattern
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="Secure API")

# Explicit production allowlist
ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://dashboard.example.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Total-Count"],
    max_age=600,
)

# Custom Middleware to enforce Vary: Origin
class VaryOriginMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Vary"] = "Origin"
        return response

app.add_middleware(VaryOriginMiddleware)

@app.get("/api/v1/user")
async def get_user_profile():
    return {"user_id": 42, "role": "administrator"}
```

---

### C. Python (Flask)

#### ✅ Secure Production Pattern (`Flask-CORS`)
```python
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Strict dictionary-based CORS configuration
CORS_CONFIG = {
    "origins": [
        "https://app.example.com",
        "https://portal.example.com"
    ],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "expose_headers": ["X-Total-Count"],
    "supports_credentials": True,
    "max_age": 600
}

# Apply strictly to /api/* routes
CORS(app, resources={r"/api/*": CORS_CONFIG})

@app.after_request
def add_vary_header(response):
    response.headers['Vary'] = 'Origin'
    return response

@app.route('/api/profile', methods=['GET'])
def get_profile():
    return jsonify({"username": "alice", "email": "alice@example.com"})
```

---

### D. Go (Gin Framework & Standard `net/http`)

#### ✅ Secure Gin Middleware (`github.com/gin-contrib/cors`)
```go
package main

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	// Configure strict CORS rules
	config := cors.Config{
		AllowOrigins:     []string{"https://app.example.com", "https://admin.example.com"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"X-Total-Count"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	router.Use(cors.New(config))

	// Custom Vary Header Middleware
	router.Use(func(c *gin.Context) {
		c.Header("Vary", "Origin")
		c.Next()
	})

	router.GET("/api/v1/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	router.Run(":8080")
}
```

#### ✅ Secure Standard `net/http` Middleware
```go
package main

import (
	"net/http"
)

var allowedOrigins = map[string]bool{
	"https://app.example.com":   true,
	"https://portal.example.com": true,
}

func SecureCORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Always set Vary: Origin for caching proxies
		w.Header().Set("Vary", "Origin")

		if origin != "" && allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}

		// Handle Preflight OPTIONS requests directly
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
```

---

### E. Java (Spring Boot)

#### ✅ Secure `WebMvcConfigurer` Configuration
```java
package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class SecurityCorsConfiguration {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                        .allowedOrigins("https://app.example.com", "https://admin.example.com")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("Authorization", "Content-Type", "X-Requested-With")
                        .exposedHeaders("X-Total-Count")
                        .allowCredentials(true)
                        .maxAge(3600);
            }
        };
    }
}
```

---

## 3. Reverse Proxy & API Gateway Configurations

### A. Nginx Reverse Proxy

To manage CORS securely at the API gateway level without relying on backend code, use an Nginx `map` block for `O(1)` origin matching.

> [!IMPORTANT]
> **Avoid Nginx `if` Statements in Location Blocks:** Using `if` directives inside Nginx location blocks can cause unexpected side effects. Using a `map` directive in the `http` context is clean, secure, and performant.

```nginx
http {
    # Define an explicit origin allowlist map
    map `$http_origin $`cors_allowed_origin {
        default "";
        "https://app.example.com"      $http_origin;
        "https://dashboard.example.com" $http_origin;
    }

    server {
        listen 443 ssl http2;
        server_name api.example.com;

        # SSL Configuration omitted for brevity

        location /api/ {
            # Set Vary header to prevent CDN cache poisoning
            add_header 'Vary' 'Origin' always;

            # Check if request is Preflight OPTIONS
            if ($request_method = 'OPTIONS') {
                add_header 'Access-Control-Allow-Origin' $cors_allowed_origin always;
                add_header 'Access-Control-Allow-Credentials' 'true' always;
                add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
                add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, X-Request-ID' always;
                add_header 'Access-Control-Max-Age' 86400 always;
                add_header 'Content-Type' 'text/plain charset=UTF-8';
                add_header 'Content-Length' 0;
                return 204;
            }

            # Actual Request Headers
            add_header 'Access-Control-Allow-Origin' $cors_allowed_origin always;
            add_header 'Access-Control-Allow-Credentials' 'true' always;

            proxy_pass http://backend_upstream;
        }
    }
}
```

---

### B. Apache HTTP Server

```apache
# In Apache Configuration or .htaccess
<IfModule mod_headers.c>
    # Set Vary: Origin
    Header always set Vary "Origin"

    # Match allowed origin explicitly
    SetEnvIf Origin "^https://(app|portal)\.example\.com`$" CORS_ALLOWED_ORIGIN=$`0
    Header always set Access-Control-Allow-Origin "%{CORS_ALLOWED_ORIGIN}e" env=CORS_ALLOWED_ORIGIN
    Header always set Access-Control-Allow-Credentials "true" env=CORS_ALLOWED_ORIGIN
</IfModule>
```
