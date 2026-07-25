---
title: "03 - Azure and GCP Security"
description: "While AWS uses IAM policies attached to users and roles, Azure and GCP have distinct but conceptually similar models for handling identity, network se..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Cloud Security", "03 Azure And Gcp Security.Md"]
---

# 03 - Azure and GCP Security

While AWS uses IAM policies attached to users and roles, Azure and GCP have distinct but conceptually similar models for handling identity, network security, and infrastructure configuration.

## Azure Security Fundamentals

### Azure RBAC and Entra ID (formerly Azure AD)
Azure uses Role-Based Access Control (RBAC). Instead of writing custom JSON policies for every micro-interaction, you assign predefined or custom roles to identities at specific scopes (Subscription, Resource Group, or Resource).

**Checking Role Assignments via Azure CLI:**
```bash
# List role assignments for a specific user
az role assignment list \
  --assignee user@domain.com \
  --output table

# Create a custom role with least privilege
az role definition create --role-definition @custom-role.json
```

### Securing Azure Storage Accounts
By default, newly created storage accounts might allow public access to blobs depending on organizational policies. It is crucial to disable public blob access.

**Disabling Public Blob Access (Azure CLI):**
```bash
az storage account update \
  --name mystorageaccount \
  --resource-group myResourceGroup \
  --allow-blob-public-access false
```

## Google Cloud Platform (GCP) Security

### GCP IAM
GCP IAM also relies heavily on predefined roles (e.g., `roles/storage.objectViewer`, `roles/compute.admin`). Roles are granted to members at the Organization, Folder, Project, or Resource level.

**Checking IAM Policies via gcloud:**
```bash
# View IAM policy for a project
gcloud projects get-iam-policy my-gcp-project-id

# Bind a specific role to a user
gcloud projects add-iam-policy-binding my-gcp-project-id \
    --member="user:alice@example.com" \
    --role="roles/viewer"
```

### GCP VPC Service Controls
VPC Service Controls (VPC SC) act as a security perimeter around GCP managed services (like Cloud Storage or BigQuery). It mitigates data exfiltration risks by ensuring that access to these services can only occur from authorized networks, preventing a leaked service account key from being used from the public internet.

**Creating a VPC Service Perimeter (gcloud):**
```bash
gcloud access-context-manager perimeters create my_perimeter \
  --title="Production Perimeter" \
  --resources="projects/1234567890" \
  --restricted-services="storage.googleapis.com,bigquery.googleapis.com" \
  --policy=my_policy
```
