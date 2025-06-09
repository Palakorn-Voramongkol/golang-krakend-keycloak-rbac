# Secure Go RBAC Backend API with KrakenD and Keycloak

This project demonstrates a complete, production-ready setup for securing a Backend API using **KrakenD** as an API Gateway and **Keycloak** for identity and access management. It also implements **fine-grained Role-Based Access Control (RBAC)** backed by MongoDB.

All traffic—including token requests—is routed through KrakenD. The gateway validates JWTs and applies routing rules before forwarding requests to the backend.

---

## 🧱 Architecture

In this secure architecture, the **only** entry point for external traffic is the KrakenD Gateway. All internal services are isolated inside the Docker network.

```
+--------+            +-------------------+      +-----------------+
| Client |----------->|                   |----->| Keycloak        |
|        |            |   KrakenD Gateway |<-----| (for /login &   |
|        |            |   (Port :8081)    |      |  JWKS)          |
|        |<---------- |                   |
+--------+            |  - JWT Validation |      +-----------------+
                      |  - Routing        |----->|  Backend API    |
                      |  - Proxy /login   |<-----|  (Port :3000)   |
                      |                   |      +-----------------+
                      +-------------------+
```

---

## 🔐 RBAC: Role-Based Access Control

RBAC is enforced by the backend using JWT claims and role-permission mappings stored in **MongoDB**.

### Example Role Document (MongoDB: `roles` collection)

```json
{
  "role_id": "user",
  "permissions": [
    {
      "path": "hr:payroll:view",
      "regions": ["SEA"],
      "except_countries": ["MM"]
    }
  ]
}
```

### Access Evaluation Rules

* **Paths** are in the format: `domain:resource:action` (e.g. `hr:payroll:view`).
* Wildcards `*` are supported (`admin:*:*`, `*:*:*`).
* Permissions can include:

  * `regions`: predefined region names (e.g., `SEA`, `GLOBAL`)
  * `countries`: allowlist for specific countries
  * `except_regions` / `except_countries`: to explicitly deny
  * `except_paths`: path-based exclusions

The backend:

* Parses the JWT from KrakenD
* Retrieves MongoDB role definitions for the user’s roles
* Evaluates whether access is permitted based on path and country

---

## 🚦 Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant KrakenD Gateway
    participant Keycloak
    participant Backend API

    Note over Client, Keycloak: Step 1: Client gets a token via the Gateway
    Client->>+KrakenD Gateway: POST /login (user & pass)
    KrakenD Gateway->>+Keycloak: POST /realms/.../token
    Keycloak-->>-KrakenD Gateway: JWT
    KrakenD Gateway-->>-Client: JWT

    Note over Client, Backend API: Step 2: Client accesses protected API
    Client->>+KrakenD Gateway: GET /admin (Bearer JWT)
    KrakenD Gateway->>+Backend API: GET /admin (Authorized)
    Backend API-->>-KrakenD Gateway: 200 OK
    KrakenD Gateway-->>-Client: 200 OK
```

---

## 📁 Project Structure

```
.
├── docker-compose.yml         # Services: MongoDB, Keycloak, Backend, Gateway
├── Dockerfile                 # Backend API
├── Dockerfile.keycloak        # Custom Keycloak image
├── krakend.json               # KrakenD declarative config
├── main.go                    # Go backend w/ JWT & MongoDB RBAC
├── mongo-init.js              # MongoDB seed data (roles, items)
├── test-all.ps1               # PowerShell test script
├── test-all.sh                # Bash test script
└── keycloak/
    └── import-realm.json      # Realm setup with users and client
```

---

## ✅ Prerequisites

* [Docker](https://www.docker.com/)
* [Docker Compose](https://docs.docker.com/compose/)
* Windows users: PowerShell 7+, and set execution policy:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 🚀 How to Run

```bash
# 1. Clean up volumes (reset Keycloak, MongoDB)
docker-compose down -v

# 2. Build & start all services
docker-compose up --build -d

# 3. Wait ~60s for all to initialize
docker-compose ps

# 4. Verify gateway works
curl http://localhost:8081/public
# → {"message":"This is a public endpoint."}
```

---

## 👥 Available Users

| Username | Password      | Roles   |
| -------- | ------------- | ------- |
| `alice`  | `password123` | `user`  |
| `bob`    | `password123` | `admin` |

---

## 🧪 Testing the System

### Manual

```bash
# Get JWT
curl -X POST http://localhost:8081/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=fiber-app&username=alice&password=password123"

# Then test endpoints with Authorization header
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/profile
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/user
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/admin
```

### Automated

Run full script for Alice and Bob:

```bash
./test-all.sh    # or .\test-all.ps1 on Windows
```

---

## 🧠 Tips for Extending RBAC

* Add more roles to MongoDB using `mongo-init.js` or `mongosh`:

  ```js
  db.roles.insertOne({
    role_id: "manager",
    permissions: [
      { path: "report:monthly:view", regions: ["SEA"], countries: ["TH"] }
    ]
  })
  ```

* Add endpoints to `main.go` with `requirePermission(...)` middleware.

* Use `curl localhost:8081/__debug/` if enabled for live inspection.

---

