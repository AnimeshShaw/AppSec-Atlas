---
sidebar_position: 5
title: 04 - Cross-Site Scripting (XSS) & Client-Side Attacks
---

# 04 - Cross-Site Scripting (XSS)

## 1. The Concept (ELI5)
Imagine a bulletin board where anyone can pin a note. Someone pins a note that says "When anyone reads this note, secretly hand me your wallet." If the board doesn't filter out magical commands, people who read the note lose their wallets. XSS is injecting malicious JavaScript into a website so that when other users visit, the script steals their session cookies or performs actions as them.

## 2. The Visual
```mermaid
sequenceDiagram
    participant Attacker
    participant Server
    participant Victim

    Attacker->>Server: POST /comment (Body: <script>steal_cookie()</script>)
    Server-->>Attacker: 200 OK (Saved)
    
    Victim->>Server: GET /comments
    Server-->>Victim: 200 OK (Includes malicious script)
    Note over Victim: Browser executes script
    Victim-->>Attacker: Sends Session Cookie
```

## 3. The Code

### Vulnerable Code ❌
```python
# Python (Flask/Jinja)
# VULNERABLE: safe filter disables autoescaping
return render_template_string("Hello {{ name | safe }}", name=request.args.get('name'))
```

```go
// Go
// VULNERABLE: template.HTML does not escape
t.Execute(w, template.HTML(r.URL.Query().Get("input")))
```

```typescript
// TypeScript (React)
// VULNERABLE: dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userInput }} />
```

### Production-Ready Secure Code ✅
```python
# Python
# Secure by default (autoescaped)
return render_template_string("Hello {{ name }}", name=request.args.get('name'))
```

```go
// Go
// Secure by default (escapes string)
t.Execute(w, r.URL.Query().Get("input"))
```

```typescript
// TypeScript
// Secure by default
<div>{userInput}</div>
```

## 4. The Guardrail
```yaml
rules:
  - id: react-dangerouslysetinnerhtml
    patterns:
      - pattern: dangerouslySetInnerHTML=...
    message: "Potential XSS via dangerouslySetInnerHTML"
    severity: WARNING
    languages: [javascript, typescript]
```
