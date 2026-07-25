# Chapter 3: Output Encoding & XSS Prevention

## Context-Aware Encoding
To prevent Cross-Site Scripting (XSS), user input must be encoded *before* being rendered. The type of encoding depends on the context (HTML body, attribute, JavaScript, or URL).

### Reflected vs Stored XSS
- **Reflected XSS:** The payload is immediately returned by the web application in an error message or search result.
- **Stored XSS:** The payload is saved to the database and displayed to other users later.

## Code Examples

### Node.js (Express + DOMPurify)
Vulnerable vs Secure code when reflecting user input.

#### ❌ Vulnerable (Raw HTML injection)
```javascript
app.get('/search', (req, res) => {
    // Attack: ?q=<script>alert(1)</script>
    const query = req.query.q;
    res.send(`<h1>Search results for: ${query}</h1>`); // XSS!
});
```

#### ✅ Secure (Context-aware escaping)
Most modern template engines (EJS, Jinja2, React) auto-escape HTML by default. If manually handling it, use a library like `escape-html`.

```javascript
const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
    const query = req.query.q;
    // Safely escapes < to &lt;, > to &gt;
    const safeQuery = escapeHtml(query); 
    res.send(`<h1>Search results for: ${safeQuery}</h1>`);
});
```

### Python (Jinja2 / Flask)
Jinja2 auto-escapes HTML by default. However, developers sometimes bypass it using the `safe` filter.

#### ❌ Vulnerable
```html
<!-- Disabling autoescape enables XSS -->
<p>Hello, {{ user_input | safe }}</p> 
```

#### ✅ Secure
```html
<!-- Default behavior securely escapes HTML -->
<p>Hello, {{ user_input }}</p>
```

### Sanitizing Rich Text
If you *must* accept HTML (e.g., a blog editor), sanitize it using DOMPurify (Node.js) or Bleach (Python) to strip dangerous tags.
