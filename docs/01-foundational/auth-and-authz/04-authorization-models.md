# 04 - Authorization Models

Authorization ensures that an authenticated user has the right to access a resource or perform an action.

## Role-Based Access Control (RBAC)
Permissions are assigned to roles (e.g., `Admin`, `Editor`, `Viewer`), and users are assigned to roles.
- **Pros:** Simple, easy to understand.
- **Cons:** Role explosion; lacks fine-grained control over specific resource instances.

## Attribute-Based Access Control (ABAC)
Permissions depend on attributes of the user, the resource, and the environment.
- Example: `User.department == Resource.department AND Time < 17:00`
- **Pros:** Highly granular and flexible.
- **Cons:** Complex to design, implement, and audit.

## Relationship-Based Access Control (ReBAC)
Based on Google's Zanzibar model. Access is determined by a graph of relationships (e.g., `User A is the OWNER of Folder B`, `Folder B CONTAINS Document C`, therefore `User A can READ Document C`).
- **Pros:** Excellent for hierarchical resources and sharing models.
- **Cons:** Requires specialized database/service for relationship traversal.

## Policy as Code: Open Policy Agent (OPA)
Decouple authorization logic from application code using OPA. Policies are written in a high-level declarative language called **Rego**.

### Example Rego Policy (RBAC + Ownership)

```rego
package app.authz

default allow = false

# Allow if user is admin
allow {
    input.user.role == "admin"
}

# Allow if user owns the document
allow {
    input.action == "read"
    input.resource.owner_id == input.user.id
}
```

### Application Code Querying OPA (Node.js)

```javascript
const axios = require('axios');

async function checkAccess(user, action, resource) {
    const response = await axios.post('http://localhost:8181/v1/data/app/authz/allow', {
        input: { user, action, resource }
    });
    return response.data.result === true;
}

// Usage
const user = { id: 123, role: "user" };
const resource = { id: 456, owner_id: 123 };

if (await checkAccess(user, "read", resource)) {
    console.log("Access Granted");
} else {
    console.log("Access Denied");
}
```
