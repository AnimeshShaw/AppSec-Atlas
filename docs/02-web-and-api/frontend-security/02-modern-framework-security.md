---
title: "02. Modern Framework Security"
description: "Modern JavaScript frameworks like React, Vue, and Angular provide built-in protections against common vulnerabilities, particularly XSS. However, they..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Frontend Security", "02 Modern Framework Security.Md"]
---

# 02. Modern Framework Security

Modern JavaScript frameworks like React, Vue, and Angular provide built-in protections against common vulnerabilities, particularly XSS. However, they are not bulletproof.

## 🛡️ React Security

React automatically escapes values embedded in JSX, making it inherently safe against most XSS attacks.

### The Danger of `dangerouslySetInnerHTML`

React provides an escape hatch to inject raw HTML using `dangerouslySetInnerHTML`. As the name implies, this is dangerous.

#### Vulnerable Code
```jsx
import React from 'react';

function Article({ content }) {
  // If 'content' contains malicious scripts, they will execute.
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}
```

#### Secure Code (Using DOMPurify)
To safely render HTML, always sanitize it first.
```jsx
import React from 'react';
import DOMPurify from 'dompurify';

function Article({ content }) {
  const cleanContent = DOMPurify.sanitize(content);
  return <div dangerouslySetInnerHTML={{ __html: cleanContent }} />;
}
```

## 🛡️ Vue.js Security

Vue automatically escapes content inside mustache tags `{{ }}`.

### The Danger of `v-html`

Similar to React, Vue provides the `v-html` directive to render raw HTML.

#### Vulnerable Code
```vue
<template>
  <!-- Vulnerable to XSS -->
  <div v-html="userProvidedHtml"></div>
</template>

<script>
export default {
  data() {
    return {
      userProvidedHtml: '<img src="x" onerror="alert(1)">'
    }
  }
}
</script>
```

#### Secure Code (Using DOMPurify)
```vue
<template>
  <div v-html="cleanHtml"></div>
</template>

<script>
import DOMPurify from 'dompurify';

export default {
  data() {
    return {
      userProvidedHtml: '<img src="x" onerror="alert(1)">'
    }
  },
  computed: {
    cleanHtml() {
      return DOMPurify.sanitize(this.userProvidedHtml);
    }
  }
}
</script>
```

## 🔒 Trusted Types API

The Trusted Types API is a browser-level defense that aims to eliminate DOM XSS by forcing developers to sanitize data before passing it to dangerous sinks (like `innerHTML`).

When Trusted Types are enforced (via CSP), the browser will throw a `TypeError` if you try to assign a plain string to a sink. You must pass a `TrustedHTML` object instead.

### Example Policy Creation
```javascript
if (window.trustedTypes && trustedTypes.createPolicy) {
  trustedTypes.createPolicy('default', {
    createHTML: (string) => DOMPurify.sanitize(string, {RETURN_TRUSTED_TYPE: true})
  });
}

// Now this is safe, and the browser will accept it.
document.getElementById('content').innerHTML = userProvidedString; // Sanitized by the 'default' policy implicitly
```
