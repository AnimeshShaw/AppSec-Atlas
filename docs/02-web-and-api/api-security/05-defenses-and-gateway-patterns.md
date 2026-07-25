# 05. API Gateway & Defense Patterns

Enforcing security controls at the **API Gateway tier** (Nginx, Kong, Envoy, AWS API Gateway) ensures consistent protection across all downstream microservices.

---

## 1. OpenAPI / JSON Schema Validation at Gateway

Validating incoming JSON payloads against strict OpenAPI schemas at the gateway drops malformed requests before they hit backend services.

### OpenAPI Schema Definition (`user_schema.json`)
```json
{
  "type": "object",
  "properties": {
    "email": { "type": "string", "format": "email", "maxLength": 100 },
    "age": { "type": "integer", "minimum": 18, "maximum": 120 }
  },
  "required": ["email", "age"],
  "additionalProperties": false
}
```

---

## 2. Secure Nginx API Gateway Configuration

```nginx
# secure_api_gateway.conf
server {
    listen 443 ssl http2;
    server_name api.techcorp.com;

    # SSL TLS 1.3 Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    
    # Global Rate Limiting (10 requests per second per IP)
    limit_req zone=api_limit burst=20 nodelay;

    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Restrict Payload Size (Max 1MB)
    client_max_body_size 1M;

    location /v1/ {
        proxy_pass http://backend_services;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

*Next Chapter: [06. Hands-On Vulnerability Lab →](06-hands-on-lab.md)*
