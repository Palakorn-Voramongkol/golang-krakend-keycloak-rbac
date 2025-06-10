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

RBAC is enforced by the backend using JWT claims and role-permission mappings stored in **MongoDB**. Each role can contain multiple permissions, which define what the user can access based on **path**, **region**, and **country-level** rules.

### Example Role Document (`roles` collection in MongoDB)

```json
{
  "role_id": "user",
  "permissions": [
    {
      "path": "hr:payroll:view",
      "regions": ["SEA"],
      "except_countries": ["MM"]
    },
    {
      "path": "hr:benefits:view",
      "regions": ["SEA"],
      "except_regions": ["VN"]
    },
    {
      "path": "profile:info:read",
      "countries": ["TH", "SG"]
    }
  ]
}
````

> 🔍 This example grants the `user` role:
>
> * Access to **payroll view** in Southeast Asia, except Myanmar.
> * Access to **benefits view** in Southeast Asia, except Vietnam.
> * Access to **profile info read** only for users from Thailand and Singapore.

---

### 🧾 Access Evaluation Logic

* **Paths** follow the format `domain:resource:action` (e.g., `hr:payroll:view`).
* Wildcards `*` are supported in any segment:
  e.g., `admin:*:*`, `*:payroll:view`, or `*:*:*`.
* Each permission may include:

  * `regions`: allowed region codes (`SEA`, `GLOBAL`, etc.)
  * `countries`: specific allowed countries
  * `except_regions` and `except_countries`: explicit deny lists
  * `except_paths`: override to block certain paths even if matched

---

### 🧠 How It Works (Backend Logic)

1. **JWT arrives from KrakenD** in `Authorization: Bearer <token>`.  
2. **`parseToken`** does an unverified parse (`ParseUnverified`) to pull out the claims.  
3. **`extractUser`** looks up each role in MongoDB and builds:
   - A `User.Roles` slice of `Role{Permissions: [...]}`  
   - A deduplicated `User.AllowedCountries` list by expanding every `Permission.Regions` (via a static `regionMap`) and honoring any `GLOBAL` wildcard.  
4. **`IsAllowed(user, Requirement)`** enforces:
   1. **Country pre-check**: if `Requirement.Country` ∉ `user.AllowedCountries` → **deny**.  
   2. **For each** `role.Permissions`:
      - **❌ Exclusions**: if any `ExceptPaths` matches `Requirement.Path`, **deny** immediately.  
      - **✅ Allow**: if `matchPath(perm.Path, Requirement.Path)` **and** `isCountryPermitted(Requirement.Country, perm)` (which itself checks included/excluded countries & regions), **allow**.  
   3. If no permission grants access, **deny**.  
5. If allowed, request proceeds; otherwise you get a `403 Forbidden`.

---

## 🔄 What Happens When a JWT Request Comes In?

This section details the **internal logic** of the Go backend whenever it receives a request with a JWT token.

### ✅ 1. **Client sends request with JWT**

The request includes an `Authorization` header:

```
Authorization: Bearer <JWT>
```

Example endpoint:

```
GET /user/payroll/view
```

---

### 🧰 2. **Middleware `requirePermission(...)` is triggered**

This middleware wraps the protected route and is configured with:

```go
Requirement{
  Path: "hr:payroll:view",
  Country: "TH",
}
```

It performs token parsing, user-role lookup, and access permission checks.

---

### 🔓 3. **JWT is parsed (no revalidation)**

Function used: `parseToken(c *fiber.Ctx)`

* Extracts the claims (such as `preferred_username`, `roles`, `sub`)
* JWT signature is not revalidated (already trusted by KrakenD)

Example claims:

```json
{
  "preferred_username": "alice",
  "roles": ["user"],
  "sub": "abc123"
}
```

---

### 👤 4. **Roles are resolved from MongoDB**

Function used: `extractUser(claims)`

* The backend uses the `roles` array to query MongoDB (`roles` collection)
* Each role contains permission rules based on paths, regions, countries, and exclusions
* The allowed countries are computed based on `regions` like `SEA` or `GLOBAL`

---

### 🔐 5. **Access is evaluated against path + region/country rules**

Function used: `IsAllowed(user, req)`

It checks:

* ✅ If the requested path matches any permission
* ✅ If the region/country is allowed (directly or via region mapping)
* ❌ If any exclusion overrides deny the request

---

### 🛑 6. **Decision is made**

* ✅ If allowed → proceeds to route handler
* ❌ If not allowed → returns 403 Forbidden with explanation

---

### ✅ Example Success Response

```json
{
  "message": "Authorized to view payroll in Thailand"
}
```

---

### ❌ Example Denied Response

```json
{
  "error": "Access denied for: hr:payroll:view"
}
```

---

> ℹ️ This layered RBAC model ensures **dynamic, MongoDB-driven, fine-grained access control** for each endpoint based on JWT identity and geography.

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

### 🖥️ Manual Testing

#### 🔸 For **Linux/macOS (bash)**

```bash
# Get JWT for 'alice'
TOKEN=$(curl -s -X POST http://localhost:8081/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=fiber-app&username=alice&password=password123" | jq -r .access_token)

# Call protected endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/profile
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/user
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/admin
```

> 💡 You need `jq` installed for this script to extract the token.

---

#### 🔸 For **Windows (PowerShell)**

```powershell
# Get JWT for 'alice'
$response = Invoke-RestMethod -Method Post `
  -Uri http://localhost:8081/login `
  -ContentType "application/x-www-form-urlencoded" `
  -Body @{ grant_type='password'; client_id='fiber-app'; username='alice'; password='password123' }

$token = $response.access_token

# Call protected endpoints
Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri http://localhost:8081/profile
Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri http://localhost:8081/user
Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } -Uri http://localhost:8081/admin
```

> ✅ Works with PowerShell 7+. If you're using Windows Terminal or VSCode terminal, you're ready to go.

---

## ⚙️ Automated

Run full test script for Alice and Bob:

#### 🔸 Linux/macOS:

```bash
./test-all.sh
```

#### 🔸 Windows (PowerShell 7+):

```powershell
.\test-all.ps1
```

> 🧪 This script will:
>
> 1. Acquire tokens via `/login`
> 2. Test `/public`, `/profile`, `/user`, and `/admin`
> 3. Report ✅ success or ❌ failure per check

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
