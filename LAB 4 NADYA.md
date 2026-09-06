# LAB 4 REPORT: ACCESS CONTROL & NETWORK SECURITY
**Name:** Nadya Zafirah Binti Mohd Fairuz  
**Student ID:** 52215225256 
**Course:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Instructor:** Prof. Dr. Shahrulniza Musa  
**Topics:** AuthN vs AuthZ, Network Segmentation, Firewall Rules, Host & Container Hardening  

---

## 1. Executive Summary & Learning Outcomes

This technical report details the implementation and verification of access control mechanisms, network segmentation, firewall rules, and container hardening techniques for cloud and containerized environments.

### Core Objectives & Outcomes:
1. **Authentication vs. Authorization (AuthN vs AuthZ):** Configured HTTP Basic Authentication using Nginx with `htpasswd` and enforced fine-grained Role-Based Access Control (RBAC) in Kubernetes using `Role`, `RoleBinding`, and `ServiceAccount`.
2. **Multi-Factor Authentication (MFA):** Built a Time-Based One-Time Password (TOTP) generator and verification workflow using `oathtool`.
3. **Network Access Control & Segmentation:** Constructed a multi-tier isolated network model (`frontend-net` and `backend-net`) using Docker custom bridge networks to prevent lateral movement.
4. **Host-Level Firewall Policy:** Modeled a default-deny ingress policy using `iptables` with explicit port-based whitelist rules (mirroring Cloud Security Groups).
5. **Container & Host Hardening:** Applied least privilege controls to container execution (non-root execution, read-only root filesystem, dropped capabilities, no-new-privileges) and scanned container images for known vulnerabilities using Trivy.

---

## 2. Session A (Week 7) — Authentication & Authorization

### Task 1 — Authentication: A Password-Protected Service

Authentication verifies identity ("who you are"). In this task, an HTTP Basic Authentication layer was configured on an Nginx reverse proxy using an encrypted credentials file created with `htpasswd`.

#### Step-by-Step Execution & Commands:

1. **Generate Encrypted Password File (`htpasswd.txt`):**
   ```bash
   htpasswd -c htpasswd.txt student
   # User entered password: P@ssw0rd!
   ```
   *Alternative Docker-based command:*
   ```bash
   docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt
   ```

2. **Configure Nginx Authentication Policy (`default.conf`):**
   ```bash
   cat > default.conf <<'EOF'
   server {
       listen 80 default_server;
       server_name _;
       location / {
           auth_basic "Restricted";
           auth_basic_user_file /etc/nginx/.htpasswd;
           return 200 'Authenticated OK\n';
       }
   }
   EOF
   ```

3. **Deploy the Authenticated Web Container (`authsvc`):**
   ```bash
   docker run --rm -d --name authsvc -p 8080:80 \
     -v "$(pwd)/default.conf:/etc/nginx/conf.d/default.conf" \
     -v "$(pwd)/htpasswd.txt:/etc/nginx/.htpasswd" nginx
   ```

4. **Verification & HTTP Status Testing:**
   - **Unauthenticated Access (Expect HTTP 401 Unauthorized):**
     ```bash
     curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
     ```
     *Output:* `no-creds: 401`

   - **Authenticated Access with Valid Credentials (Expect HTTP 200 OK):**
     ```bash
     curl -s -u student:'P@ssw0rd!' http://localhost:8080
     ```
     *Output:* `Authenticated OK`

#### Empirical Screenshot Evidence:
![Task 1 - Password File Generation](EVIDENCE/Task%201%20%E2%80%94%20Authentication%20a%20Password-Protected%20Service%20(1).png)  
![Task 1 - Nginx Config & HTTP Verification](EVIDENCE/Task%201%20%E2%80%94%20Authentication%20a%20Password-Protected%20Service%20(2).png)

---

### Task 2 — Add a Second Factor (MFA / TOTP)

Passwords alone are vulnerable to theft and interception. Multi-Factor Authentication (MFA) introduces a second dynamic factor based on RFC 6238 Time-Based One-Time Password (TOTP).

#### Step-by-Step Execution & Commands:

1. **Generate a Shared Secret (Base32 Encoded):**
   ```bash
   SECRET=$(head -c20 /dev/urandom | base32)
   echo "Secret: $SECRET"
   ```
   *Captured Secret:* `XOJAQ7J5GAREJWQBNDEHSGCH6PORLXZI`

2. **Generate Current 6-Digit TOTP Code:**
   ```bash
   CODE=$(oathtool --totp -b "$SECRET")
   echo "Generated code: $CODE"
   ```
   *Captured Code:* `072744`

3. **Validate Code Verification Logic:**
   ```bash
   [ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo "MFA OK" || echo "MFA FAILED"
   ```
   *Output:* `MFA OK`

#### Empirical Screenshot Evidence:
![Task 2 - MFA TOTP Verification](EVIDENCE/Task%202%20%E2%80%94%20Add%20a%20Second%20Factor%20(MFA%20%20TOTP).png)

---

### Task 3 — Authorization: RBAC Roles

Authorization decides permissions ("what you may do"). Kubernetes Role-Based Access Control (RBAC) was configured to enforce the principle of least privilege for a developer service account.

#### Step-by-Step Execution & Commands:

1. **Initialize Kubernetes Cluster & Namespace:**
   ```bash
   kind create cluster --name ccse-lab4
   kubectl create namespace app
   kubectl create serviceaccount dev -n app
   ```

2. **Define Least-Privilege Role & RoleBinding:**
   ```bash
   # Create Role allowing only GET and LIST on pods
   kubectl create role dev-role -n app --verb=get,list --resource=pods

   # Bind Role to the dev ServiceAccount
   kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev
   ```

3. **Verify RBAC Permission Matrix using `kubectl auth can-i`:**
   ```bash
   SA=system:serviceaccount:app:dev

   # Check read permission on pods (Expected: yes)
   kubectl auth can-i list pods -n app --as=$SA

   # Check deploy creation permission (Expected: no)
   kubectl auth can-i create deploy -n app --as=$SA

   # Check pod deletion permission (Expected: no)
   kubectl auth can-i delete pods -n app --as=$SA
   ```

#### RBAC Verification Matrix:

| Action / Command | Resource | Target Namespace | Subject (`--as`) | Authorized Result | Security Evaluation |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `list pods` | Pods | `app` | `system:serviceaccount:app:dev` | **`yes`** | Permitted by `dev-role` rule |
| `create deploy` | Deployments | `app` | `system:serviceaccount:app:dev` | **`no`** | Denied (Least privilege enforced) |
| `delete pods` | Pods | `app` | `system:serviceaccount:app:dev` | **`no`** | Denied (Destructive action blocked) |

#### Empirical Screenshot Evidence:
![Task 3 - Kubernetes RBAC Creation & Permission Check](EVIDENCE/Task%203%20%E2%80%94%20Authorization%20RBAC%20Roles.png)

---

## 3. Session B (Week 8) — Network Security & Hardening

### Task 4 — Network Segmentation (Three-Tier Architecture)

Network segmentation restricts communication paths between application tiers to contain potential security breaches and block lateral movement.

```
       [ Internet / Client ]
                 │
                 ▼
        ┌─────────────────┐
        │   web tier      │  (frontend-net)
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │   app tier      │  (frontend-net & backend-net)
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │   db tier       │  (backend-net ONLY)
        └─────────────────┘
```

#### Step-by-Step Execution & Commands:

1. **Create Segmented Docker Bridge Networks:**
   ```bash
   docker network create frontend-net
   docker network create backend-net
   ```

2. **Deploy Tiers onto Specific Networks:**
   ```bash
   # DB tier on backend-net only
   docker run -d --name db --network backend-net redis:alpine

   # App tier connected to backend-net initially, then connected to frontend-net
   docker run -d --name app --network backend-net nginx
   docker network connect frontend-net app

   # Web tier on frontend-net only
   docker run -d --name web --network frontend-net nginx
   ```

3. **Validate Segmentation & Boundary Controls:**
   - **Frontend (`web`) -> Database (`db`) Direct Access Test (Expected: FAIL / BLOCKED):**
     ```bash
     docker exec web sh -c 'apk add -q curl; curl -s -m 3 db:6379 || echo BLOCKED'
     ```
     *Output:* `BLOCKED`

   - **Application (`app`) -> Database (`db`) Access Test (Expected: REACHABLE):**
     ```bash
     docker exec app sh -c 'apk add -q curl; nc -z -w3 db 6379 && echo REACHABLE'
     ```
     *Output:* `REACHABLE`

#### Empirical Screenshot Evidence:
![Task 4 - Network Segmentation Verification](EVIDENCE/Task%204%20%E2%80%94%20Network%20Segmentation%20(Three-Tier).png)

---

### Task 5 — Firewall Rules (Default-Deny Pattern)

Host-level firewalls enforce network least privilege by dropping all traffic by default and explicitly opening only required ports. This models cloud infrastructure Security Groups (SGs) and Network Security Groups (NSGs).

#### Step-by-Step Execution & Commands:

1. **Execute Throwaway Security Container with `NET_ADMIN` Capability:**
   ```bash
   docker run --rm --cap-add=NET_ADMIN alpine sh -c '\
    apk add -q iptables; \
    iptables -P INPUT DROP; \
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
    iptables -A INPUT -i lo -j ACCEPT; \
    iptables -L INPUT -n'
   ```

2. **`iptables` Configuration Breakdown:**

| Command / Flag | Purpose / Policy Effect | Cloud Equivalent |
| :--- | :--- | :--- |
| `iptables -P INPUT DROP` | Set default policy to **DROP** for all incoming traffic | Inbound Default-Deny rule in AWS Security Group / Azure NSG |
| `iptables -A INPUT -p tcp --dport 443 -j ACCEPT` | Explicitly permit HTTPS traffic on TCP port 443 | Inbound Allow Rule (Port 443) |
| `iptables -A INPUT -i lo -j ACCEPT` | Explicitly permit loopback interface communication | Localhost IPC communication |
| `iptables -L INPUT -n` | List active rules on `INPUT` chain with numeric formatting | Security Group Rules Audit |

---

### Task 6 — Container / Host Hardening & Vulnerability Scanning

Container hardening reduces attack surfaces by limiting privileges, locking down the filesystem, and eliminating execution capabilities.

#### Step-by-Step Execution & Commands:

1. **Launch Hardened Container Instance:**
   ```bash
   docker run -d --name hardened \
     --user 1000:1000 \
     --read-only \
     --cap-drop=ALL \
     --security-opt no-new-privileges \
     --tmpfs /tmp \
     nginxinc/nginx-unprivileged
   ```

2. **Inspect Runtime Security Flags:**
   ```bash
   docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'
   ```
   *Captured Output:* `User=1000:1000 ReadOnly=true`

3. **Image Vulnerability Scan via Trivy:**
   ```bash
   docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
   ```

#### Trivy Vulnerability Scan Findings Summary:
- **Target Image:** `nginx:alpine` (Alpine OS version 3.24.1)
- **Scan Type:** OS Package & Library Vulnerability Analysis
- **High Severity Vulnerabilities:** `2`
- **Critical Severity Vulnerabilities:** `0`
- **Secrets Audit:** Clean (`-`)

#### Empirical Screenshot Evidence:
![Task 6 - Container Hardening & Inspect Output](EVIDENCE/Task%206%20%E2%80%94%20Container%20%20Host%20Hardening%20(1).png)  
![Task 6 - Trivy Vulnerability Scan Summary](EVIDENCE/Task%206%20%E2%80%94%20Container%20%20Host%20Hardening%20(2).png)

---

## 4. Deliverables & Technical Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.
- **Authentication (AuthN - Task 1):** Focuses on proving identity (*"Who are you?"*). Task 1 implements HTTP Basic Authentication, requiring valid user credentials (`student:P@ssw0rd!`). The web server checks the provided hash against `/etc/nginx/.htpasswd` to establish the caller's identity. Unauthenticated requests are rejected with `HTTP 401 Unauthorized`.
- **Authorization (AuthZ - Task 3):** Focuses on granting or denying specific permissions (*"What are you allowed to do?"*). In Task 3, identity is already established as the `dev` ServiceAccount. Kubernetes RBAC inspects the action being attempted. The `dev-role` explicitly permits `get` and `list` operations on `pods` (`yes`), but rejects `create deployment` or `delete pods` operations (`no`).

### Q2. Why is MFA so effective, and which attacks does it defeat?
- **Effectiveness:** MFA enforces multi-factor verification by requiring factors from distinct classes: *something you know* (password) and *something you have* (a TOTP seed on an authenticator device). Because TOTP codes change every 30 seconds based on HMAC-SHA1 hash calculations, a stolen password alone cannot grant access.
- **Attacks Defeated:**
  1. **Credential Stuffing & Leaked Passwords:** Stolen credentials from database breaches fail without the live authenticator code.
  2. **Password Spraying & Brute-Force:** Automated password guessing cannot predict time-synchronized dynamic codes.
  3. **Replay Attacks:** Intercepted OTP codes become invalid after the 30-second window expires.

### Q3. How does network segmentation limit the damage of a compromised web server?
- **Damage Containment (Blast Radius Reduction):** In Task 4, the `web` frontend resides solely on `frontend-net`, while the database (`db`) resides exclusively on `backend-net`. If an attacker compromises the web server (e.g., via a Remote Code Execution vulnerability), the isolation of Docker networks prevents direct IP routing or socket connections to the database. The attacker cannot pivot or perform lateral movement directly to `db:6379`, protecting sensitive data at rest.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?
- **Achievement:** A default-deny policy (`iptables -P INPUT DROP`) ensures zero-trust network positioning. All incoming packets are blocked unless explicitly allowed by a firewall rule.
- **Relation to Cloud Security Groups:** AWS Security Groups and Azure Network Security Groups (NSGs) operate on an implicit default-deny posture for inbound traffic. Administrators must explicitly write "Allow" rules (e.g., allow TCP 443 from `0.0.0.0/0`). Implementing `iptables -P INPUT DROP` mirrors this fundamental cloud infrastructure security design.

### Q5. List the hardening measures you applied and the attack surface each one removes.

| Hardening Measure | Applied Directive / Flag | Attack Surface Removed / Threat Blunted |
| :--- | :--- | :--- |
| **Non-Root Execution** | `--user 1000:1000` | Prevents container breakout vulnerabilities from gaining `root` privilege on the host kernel. |
| **Read-Only Root Filesystem** | `--read-only` | Prevents attackers from writing malware binaries, webshells, or modifying application source code on disk. |
| **Drop Linux Capabilities** | `--cap-drop=ALL` | Strips kernel-level administrative capabilities (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`), preventing raw socket sniffing and kernel privilege exploitation. |
| **No New Privileges** | `--security-opt no-new-privileges` | Blocks processes from acquiring setuid/setgid elevated privileges during execution. |
| **Vulnerability Scanning** | `trivy image nginx:alpine` | Identifies known CVEs in OS libraries prior to production deployment. |

---

## 5. Verification Commands & Security Checklist

### Verification Commands & Outputs

1. **Verify Kubernetes RoleBinding Specification:**
   ```bash
   kubectl get rolebinding dev-rb -n app -o yaml
   ```

2. **Verify Hardened Container Capabilities Drop:**
   ```bash
   docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
   ```
   *Expected Output:* `["ALL"]`

### Security Best-Practices Checklist

- [x] **Service Authentication Enforced:** Unauthenticated HTTP requests correctly rejected (`HTTP 401`).
- [x] **Multi-Factor Authentication Implemented:** TOTP 6-digit code verified successfully (`MFA OK`).
- [x] **Authorization Enforced via RBAC:** Least privilege configured; unauthorised actions explicitly denied (`no`).
- [x] **Network Segmented:** Data tier (`db`) isolated on `backend-net` and unreachable from `web` tier.
- [x] **Default-Deny Firewall Active:** Host firewall default policy set to `DROP` with explicit `ACCEPT` rules.
- [x] **Container Image Hardened & Scanned:** Executed as non-root (`1000:1000`), read-only root FS, dropped capabilities (`ALL`), scanned with Trivy.

---

## 6. Teardown & Cleanup

To restore the environment to its initial state, execute the following teardown commands:

```bash
# Stop and remove all lab containers
docker rm -f authsvc db app web hardened 2>/dev/null

# Remove custom Docker networks
docker network rm frontend-net backend-net 2>/dev/null

# Delete Kind Kubernetes cluster
kind delete cluster --name ccse-lab4
```
