---
title: "04 - Secure CORS Implementation"
description: "To implement CORS securely, you must enforce a strict server-side origin allowlist. Do not trust user input (the `Origin` header) without validating i..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Cors And Sop", "04 Secure Cors Implementation.Md"]
---

# 04 - Secure CORS Implementation

To implement CORS securely, you must enforce a strict server-side origin allowlist. Do not trust user input (the `Origin` header) without validating it against a predefined list of authorized domains.

## Best Practices
1.  **Use a Strict Allowlist:** Define exactly which origins are permitted.
2.  **Avoid Wildcards with Credentials:** Never use `Access-Control-Allow-Origin: *` if `Access-Control-Allow-Credentials: true` is set.
3.  **Do Not Allow `null`:** Never allow the `null` origin.
4.  **Validate Carefully:** If using regex, ensure it is anchored (`^` and `$`) and dots are escaped (`\.`). Use exact string matching whenever possible.
5.  **Use Standard Middleware:** Rely on established framework middleware rather than writing custom header-setting logic.

---

## Code Examples

### 1. Express.js (Node.js)
Use the official `cors` package.

```javascript
const express = require('express');
const cors = require('cors');
const app = express();

const allowedOrigins = [
  'https://www.example.com',
  'https://api.example.com'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true); // Origin is allowed
    } else {
      callback(new Error('Not allowed by CORS')); // Origin is blocked
    }
  },
  credentials: true, // Allow cookies to be sent
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

app.get('/api/data', (req, res) => {
  res.json({ secret: 'Secure Data' });
});
```

### 2. FastAPI (Python)
FastAPI provides a built-in `CORSMiddleware`.

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "https://www.example.com",
    "https://app.example.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/api/data")
async def get_data():
    return {"secret": "Secure Data"}
```

### 3. Flask (Python)
Use the `Flask-CORS` extension.

```python
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Strict dictionary-based configuration
cors_config = {
    "origins": ["https://www.example.com", "https://app.example.com"],
    "methods": ["GET", "POST", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True
}

# Apply to entire app
CORS(app, resources={r"/api/*": cors_config})

@app.route('/api/data')
def get_data():
    return jsonify({"secret": "Secure Data"})
```

### 4. Nginx (Reverse Proxy)
If you manage CORS at the API gateway or reverse proxy level, use a map to check the origin securely.

```nginx
# Define the allowed origins
map $http_origin $cors_origin {
    default "";
    "~^https://(www\.)?example\.com$" $http_origin;
    "https://app.example.com" $http_origin;
}

server {
    listen 443 ssl;
    server_name api.example.com;

    location / {
        # Handle Preflight OPTIONS
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' $cors_origin always;
            add_header 'Access-Control-Allow-Credentials' 'true' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type' always;
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain charset=UTF-8';
            add_header 'Content-Length' 0;
            return 204;
        }

        # Handle Actual Requests
        add_header 'Access-Control-Allow-Origin' $cors_origin always;
        add_header 'Access-Control-Allow-Credentials' 'true' always;

        proxy_pass http://backend_server;
    }
}
```
