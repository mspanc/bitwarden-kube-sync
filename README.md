# Bitwarden → Kubernetes Secret Sync

A small Go application intended to run **inside a Kubernetes cluster**.  
It periodically pulls secrets from **Bitwarden Secrets Manager** and materializes them as a **Kubernetes Secret**.

The app is designed to be:
- deterministic (ordered project merge)
- safe (no overlapping syncs)
- resilient (errors are logged, loop keeps running)
- Kubernetes-native (in-cluster config, RBAC friendly)

## How it works

1. Authenticates to **Bitwarden Secrets Manager** using an **access token**
2. Fetches all secrets from the given **organization**
3. Filters secrets by the configured **project IDs (in order)**
4. Merges secrets into a single key/value map
   - later projects override earlier ones
   - duplicate keys are logged as warnings
5. Creates or updates a Kubernetes `Secret`
6. Sleeps for `REFRESH_INTERVAL`
7. Repeats (no overlapping executions)

## Requirements

- Kubernetes cluster
- ServiceAccount with permissions to manage Secrets
- Bitwarden Secrets Manager access token

## Secret merge semantics

- Projects are processed **in the order provided**
- If the same key exists multiple times:
  - a warning is logged
  - the **latest project wins**
- Secret keys are written verbatim, values are stored as bytes

## Usage 

This is intended to be deployed within Kubernetes cluster.

### RBAC

Minimal RBAC required (namespace-scoped):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: bitwarden-kube-sync
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create", "update", "patch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: bitwarden-kube-sync
subjects:
  - kind: ServiceAccount
    name: bitwarden-kube-sync
roleRef:
  kind: Role
  name: bitwarden-kube-sync
  apiGroup: rbac.authorization.k8s.io
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bitwarden-kube-sync
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bitwarden-kube-sync
  template:
    metadata:
      labels:
        app: bitwarden-k8s-secret-sync
    spec:
      serviceAccountName: bitwarden-k8s-secret-sync
      containers:
        - name: app
          image: mspanc/bitwarden-kube-sync:latest
          env:
            - name: BITWARDEN_API_URL
              value: https://api.bitwarden.com
            - name: BITWARDEN_IDENTITY_URL
              value: https://identity.bitwarden.com
            - name: BITWARDEN_ACCESS_TOKEN
              valueFrom:
                secretKeyRef:
                  name: bitwarden-access-token
                  key: token
            - name: BITWARDEN_ORGANIZATION_ID
              value: "<org-uuid>"
            - name: BITWARDEN_PROJECT_IDS
              value: "<project-a-uuid>,<project-b-uuid>"
            - name: KUBE_SECRET_NAME
              value: app-secrets
```

### Environment variables

#### Required

| Variable | Description |
|--------|-------------|
| `BITWARDEN_API_URL` | Bitwarden API base URL |
| `BITWARDEN_IDENTITY_URL` | Bitwarden Identity URL |
| `BITWARDEN_ACCESS_TOKEN` | Secrets Manager access token |
| `BITWARDEN_ORGANIZATION_ID` | Bitwarden organization UUID |
| `BITWARDEN_PROJECT_IDS` | Comma-separated list of project UUIDs |
| `KUBE_SECRET_NAME` | Name of the Kubernetes Secret to create/update |

#### Optional

| Variable | Default | Description |
|--------|---------|-------------|
| `REFRESH_INTERVAL` | `60s` | Sync interval (Go duration format) |
| `KUBE_NAMESPACE` | auto-detected | Namespace to manage the secret |

Namespace resolution order:

1. `KUBE_NAMESPACE`
2. `POD_NAMESPACE`
3. `/var/run/secrets/kubernetes.io/serviceaccount/namespace`

## Building

CGO must be enabled.

```sh
CGO_ENABLED=1 go build -o bitwarden-kube-sync
```