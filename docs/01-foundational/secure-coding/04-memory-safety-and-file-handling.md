---
title: "Chapter 4: Memory Safety & File Handling"
description: "File uploads are a common attack vector (Remote Code Execution via web shells, XSS via SVG uploads)."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Secure Coding", "04 Memory Safety And File Handling.Md"]
---

# Chapter 4: Memory Safety & File Handling

## Secure File Uploads
File uploads are a common attack vector (Remote Code Execution via web shells, XSS via SVG uploads). 

### Validation Strategies:
1. **Never trust the extension or `Content-Type` header:** Attackers can easily spoof them.
2. **Use Magic Bytes (File Signatures):** Verify the actual file content format.
3. **Randomize Filenames:** Never use the user-supplied filename. Use UUIDs.
4. **External Storage:** Store uploads on a separate domain (e.g., AWS S3) to prevent code execution on the app server.

## Path Traversal (`../`) Prevention
Attackers use `../` (dot-dot-slash) to traverse out of the intended directory and access sensitive files like `/etc/passwd`.

### Node.js Path Traversal Prevention

#### ❌ Vulnerable
```javascript
app.get('/download', (req, res) => {
    const file = req.query.file; 
    // Attack: ?file=../../../etc/passwd
    const filePath = path.join(__dirname, 'uploads', file); 
    res.sendFile(filePath);
});
```

#### ✅ Secure
```javascript
app.get('/download', (req, res) => {
    const file = req.query.file;
    
    // 1. Validate filename strictly (only alphanumeric + .txt)
    if (!/^[a-zA-Z0-9]+\.txt$/.test(file)) {
        return res.status(400).send("Invalid file format");
    }

    // 2. Resolve absolute path and verify it stays within bounds
    const basePath = path.resolve(__dirname, 'uploads');
    const filePath = path.resolve(basePath, file);

    if (!filePath.startsWith(basePath)) {
        return res.status(403).send("Path traversal detected");
    }

    res.sendFile(filePath);
});
```
