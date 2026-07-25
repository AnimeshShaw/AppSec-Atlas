# 06 - Hands-On Lab: Building a DevSecOps Pipeline

In this lab, you will create a self-contained DevSecOps GitHub Actions pipeline for a dummy Node.js application.

## Scenario
You have a repository with a `package.json`, an `app.js`, and a `Dockerfile`. You need to ensure that no secrets are committed, the code is scanned for vulnerabilities, the dependencies are checked, and a container image is scanned before deployment.

## Step 1: Prepare the Vulnerable App
Create a file named `app.js` with intentional vulnerabilities (e.g., hardcoded secrets and basic injection):

```javascript
// app.js
const express = require('express');
const app = express();

// Intentional Secret (TruffleHog will catch this)
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

app.get('/user', (req, res) => {
    let user_id = req.query.id;
    // Intentional SQLi pattern (Semgrep will catch this)
    let query = "SELECT * FROM users WHERE id = " + user_id;
    res.send("Executing: " + query);
});

app.listen(3000, () => console.log('Server running'));
```

Create a `package.json` with an outdated, vulnerable dependency (e.g., an old version of `express`):
```json
{
  "name": "vuln-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.16.0" 
  }
}
```

Create a basic `Dockerfile`:
```dockerfile
FROM node:14-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "app.js"]
```

## Step 2: Create the Pipeline
Create the file `.github/workflows/devsecops.yml` and paste the pipeline from Chapter 02.

## Step 3: Trigger the Pipeline (The Quality Gate)
Commit and push these files to a new branch and open a Pull Request.
1. **Secret Scanning:** TruffleHog will fail the build because of the `AWS_ACCESS_KEY`.
2. **SAST:** Semgrep will detect the string concatenation in the SQL query and flag it as a potential injection.
3. **SCA:** Trivy will flag the old `express` version and the `node:14-alpine` base image (which is deprecated).

## Step 4: Auto-Remediation Workflow (Fixing the code)
To pass the Quality Gate, you must remediate the findings.

1. **Remove the Secret:** Delete the AWS key and use environment variables (`process.env.AWS_ACCESS_KEY`).
2. **Fix the SAST issue:** Parameterize the query or remove the concatenation.
3. **Fix the SCA issue:** Update `express` to `^4.18.2` and change the Docker base image to a modern, supported version (e.g., `node:20-alpine`).

Push the changes. The pipeline will re-run, pass all checks, and allow the PR to be merged!
