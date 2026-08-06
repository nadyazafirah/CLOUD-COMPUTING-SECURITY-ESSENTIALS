# LAB 1 — Cloud Account Security, Identity & Access Management
## Identity Governance and Least Privilege — LocalStack IAM & Kubernetes RBAC

---

### Course & Student Details
* **Student Name:** Nadya Zafirah 
Binti Mohd Fairuz
* **Student ID:** 52215225256
* **Course:** IKB42603 Cloud Computing Security Essentials
* **Lab Title:** Lab 1 — Identity Governance and Least Privilege (LocalStack IAM & Kubernetes RBAC)
* **Institution:** Universiti Kuala Lumpur (UniKL MIIT)



---

## Executive Summary & Learning Outcomes
This laboratory report documents the implementation and verification of cloud identity governance, role-based access control (RBAC), and the Principle of Least Privilege (PoLP). Using **LocalStack** (an offline AWS cloud service emulator) and **kind** (Kubernetes-in-Docker), this lab demonstrates how cloud administrators transition away from root user liabilities by implementing scoped IAM policies, identity groups, key rotation hygiene, and Kubernetes RBAC namespace boundaries.

### Key Objectives Achieved:
1. Deployed an offline, containerized local cloud environment with Docker and LocalStack.
2. Replaced root user operations with a dedicated administrative user assigned via group permissions.
3. Enforced fine-grained permissions using a read-only policy for a security analyst identity.
4. Demonstrated credential hygiene through access key generation, auditing, and deactivation/rotation.
5. Provisioned a Kubernetes cluster and enforced namespace-isolated Role-Based Access Control (RBAC).
6. Validated authentication vs. authorization boundaries using `kubectl auth can-i`.

---

## Technical Architecture & Setup

| Tool | Technology | Purpose |
| :--- | :--- | :--- |
| **Docker** | Container Engine | Runs LocalStack and Kubernetes kind nodes locally |
| **LocalStack** | Cloud Emulator | Local emulation of AWS IAM, STS, and S3 APIs |
| **AWS CLI v2** | Command Line Tool | Configured with dummy credentials targeting LocalStack API endpoint |
| **kind** | Kubernetes Engine | Runs a local Kubernetes cluster inside Docker containers |
| **kubectl** | K8s Control CLI | Inspects cluster resources and tests RBAC permissions |

---

## Session A (Week 1) — Cloud Identity with LocalStack

### One-Time Environment Setup

#### 1. Verifying Docker & Starting LocalStack
The containerized environment was initialized by starting the `localstack/localstack` container mapping port `4566`.

```bash
# 1. Confirm Docker status
sudo docker ps

# 2. Start LocalStack container
docker run -d --name localstack -p 4566:4566 localstack/localstack

# 3. Verify LocalStack health endpoint
curl http://localhost:4566/_localstack/health
```

**Docker Container Status:**
![Docker Container Status](sudo%20docker%20ps.png)

**LocalStack Health Check Output:**
![LocalStack Health Check](localstack%20health.png)

#### 2. AWS CLI Configuration & Identity Verification
The AWS CLI was configured with dummy credentials and directed to `http://localhost:4566`. Initial identity check confirmed execution under root account credentials.

```bash
# Configure dummy credentials for LocalStack
sudo aws configure set aws_access_key_id test
sudo aws configure set aws_secret_access_key test
sudo aws configure set region us-east-1

# Verify initial identity
sudo aws --endpoint-url=http://localhost:4566 sts get-caller-identity
```

**STS Get-Caller-Identity Output:**
![STS Get-Caller-Identity Output](dummy%20credentials.png)

```json
{
    "UserId": "000000000000",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

---

### Task 1 — Map the Cloud Identity Landscape

Understanding the core primitives of cloud identity is fundamental to designing a secure access control model. Below is the mapping of identity concepts to AWS terms and their explicit security purposes:

| Concept | AWS Term | Purpose (Detailed Description) |
| :--- | :--- | :--- |
| **All-powerful owner** | `Root user` | The initial identity created with the account having unrestricted access to all resources. It bypasses IAM policies and should only be used for initial setup or emergency break-glass procedures. |
| **Human/app identity** | `IAM User` | A long-term identity created within AWS representing a specific person or service requiring interactive or programmatic credentials to perform tasks. |
| **Permission bundle** | `IAM Policy` | A JSON document that defines formal permissions (actions, resources, conditions). Attached to identities or resources to explicitly grant or deny operations. |
| **Collection of users** | `IAM Group` | A management container used to group multiple IAM users together so permissions can be managed collectively rather than assigned individually. |
| **Temporary identity** | `IAM Role` | A identity with temporary security credentials that can be assumed by users, applications, or AWS services for short-term, privilege-scoped access. |

---

### Task 2 — Create a Least-Privilege Admin (Stop Using Root)

To eliminate continuous reliance on the root account, an administrative group (`Admins`) was created, attached with the managed `AdministratorAccess` policy, and populated with a dedicated personal admin user (`CloudAdmin_NADYA`).

```bash
EP='--endpoint-url=http://localhost:4566'

# 2.1 Create group and attach AdministratorAccess managed policy
aws $EP iam create-group --group-name Admins
aws $EP iam attach-group-policy --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2.2 Create personal admin user
aws $EP iam create-user --user-name CloudAdmin_NADYA

# 2.3 Put the user in the group (permissions flow from the group)
aws $EP iam add-user-to-group --group-name Admins \
  --user-name CloudAdmin_NADYA

# 2.4 Verify group membership
aws $EP iam get-group --group-name Admins
```

**Creating Group & Personal Admin User:**
![Create Admin Group and User](create%20group.png)

**Verifying Group Membership (`get-group`):**
![Verify Group Membership](#%202.3%20Put%20the%20user%20in%20the%20group%20#%202.4%20Verify%20the%20membership.png)

---

### Task 3 — Enforce Least Privilege with a Scoped Policy

To grant a teammate access without exposing administrative capabilities, a read-only identity (`Analyst_NADYA`) was provisioned and restricted to S3 read operations.

```bash
# 3.1 Create read-only user
aws $EP iam create-user --user-name Analyst_NADYA

# 3.2 Attach scoped read-only policy (AmazonS3ReadOnlyAccess)
aws $EP iam attach-user-policy --user-name Analyst_NADYA \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 3.3 List attached user policies
aws $EP iam list-attached-user-policies --user-name Analyst_NADYA
```

**Creating Analyst User:**
![Create Analyst User](#%203.1%20Create%20a%20read-only%20user.png)

**Listing Attached User Policies (`list-attached-user-policies`):**
![List Attached User Policies](#%203.3%20List%20what%20the%20user%20can%20do.png)

#### Blast-Radius Reduction Analysis:
If the `Analyst_NADYA` account credentials were stolen or compromised:
1. **Confined Scope:** The attacker cannot modify, delete, or upload data within S3 buckets, nor can they touch any other AWS services (EC2, IAM, DynamoDB, Lambda, etc.).
2. **Blast-Radius Containment:** Unlike an admin account breach which leads to full infrastructure takeover, compromising a least-privilege read-only identity limits the risk strictly to data exposure of S3 resources permitted under `AmazonS3ReadOnlyAccess`.

---

### Task 4 — Credential Hygiene & Access Keys

Programmatic credentials (access key pairs) must be audited and rotated regularly to mitigate risks associated with credential leakage.

```bash
# 4.1 Create programmatic access key for Analyst
aws $EP iam create-access-key --user-name Analyst_NADYA

# 4.2 List active access keys
aws $EP iam list-access-keys --user-name Analyst_NADYA

# 4.3 Key Rotation: Deactivate the old key
aws $EP iam update-access-key --user-name Analyst_NADYA \
  --access-key-id LKIAQAAAAAAALEF5QZ43 --status Inactive
```

**Access Key Creation, Listing, and Deactivation:**
![Task 4 Credential Hygiene](Task%204%20%E2%80%94%20Credential%20Hygiene%20%26%20Access%20Keys.png)

---

## Session B (Week 2) — Enforced Access Control with Kubernetes RBAC

While IAM defines identities and permission policies, platform engines like Kubernetes enforce access control dynamically at the API server layer.

### Environment Setup — Local Kubernetes Cluster
A local Kubernetes cluster `ccse-lab1` was launched using `kind`.

```bash
# Create local cluster inside Docker
sudo kind create cluster --name ccse-lab1

# Verify cluster connection and nodes
sudo kubectl cluster-info --context kind-ccse-lab1
sudo kubectl get nodes
```

**Kubernetes Cluster Initialization (`kind`):**
![Create Local Kubernetes Cluster](#%20Create%20a%20throwaway%20cluster.png)

---

### Task 5 — Separate Environments with Namespaces
Namespaces create virtual boundary separation within the same physical cluster.

```bash
# Create isolated dev and prod namespaces
sudo kubectl create namespace dev
sudo kubectl create namespace prod

# List namespaces
sudo kubectl get namespaces
```

**Creating `dev` and `prod` Namespaces:**
![Create Namespaces](Task%205%20%E2%80%94%20Separate%20Environments%20with%20Namespaces.png)

---

### Task 6 — Define a Role and Bind It (Least Privilege)
RBAC couples permissions (`Role`) to identities (`ServiceAccount`) through an explicit assignment object (`RoleBinding`).

```bash
# 6.1 Create Service Account in dev namespace
sudo kubectl create serviceaccount dev-user -n dev

# 6.2 Create Role granting read-only pod permissions in dev
sudo kubectl create role pod-reader -n dev \
  --verb=get,list,watch --resource=pods

# 6.3 Bind the Role to the Service Account
sudo kubectl create rolebinding dev-user-binding -n dev \
  --role=pod-reader --serviceaccount=dev:dev-user
```

**Creating ServiceAccount, Role, and RoleBinding:**
![Define Role and RoleBinding](Task%206%20%E2%80%94%20Define%20a%20Role%20and%20Bind%20It%20(Least%20Privilege).png)

---

### Task 7 — Test That Access Control Works

The authorization boundaries were verified using `kubectl auth can-i` under the identity of `dev-user`.

```bash
SA=system:serviceaccount:dev:dev-user

# Test 1: Reading pods in dev (Expected: YES)
sudo kubectl auth can-i list pods -n dev --as=$SA

# Test 2: Deleting pods in dev (Expected: NO)
sudo kubectl auth can-i delete pods -n dev --as=$SA

# Test 3: Reading pods in prod (Expected: NO)
sudo kubectl auth can-i list pods -n prod --as=$SA
```

**Testing RBAC Permissions (`kubectl auth can-i`):**
![Test Access Control Boundaries](Task%207%20%E2%80%94%20Test%20That%20Access%20Control%20Works.png)

#### Authentication vs. Authorization Analysis:
* **Authentication (AuthN):** In all three tests, the API server successfully authenticated the caller identity as `system:serviceaccount:dev:dev-user`.
* **Authorization (AuthZ):** 
  * **Test 1 (`list pods -n dev`):** Passed AuthZ because `pod-reader` explicitly allows `get, list, watch` on `pods` in `dev`.
  * **Test 2 (`delete pods -n dev`):** Blocked by AuthZ because the verb `delete` is not listed in `pod-reader`.
  * **Test 3 (`list pods -n prod`):** Blocked by AuthZ because `dev-user-binding` is scoped exclusively to namespace `dev`. Cross-namespace permission to `prod` is denied.

---

## Short-Answer Deliverable Questions

### Q1. Why is attaching policies to groups better than attaching them directly to users?
Attaching policies to groups centralizes identity administration and enforces consistent security standards. When permissions are managed at the group level:
1. **Scalability & Maintainability:** Updating a policy attached to a group automatically updates permissions for all current and future members.
2. **Auditability:** Security auditors can evaluate a few group definitions rather than inspecting hundreds of individual user permission profiles.
3. **Reduced Drift:** Assigning policies directly to users leads to permission creep and unmanageable, fragmented access configurations.

---

### Q2. What is the difference between an IAM User and an IAM Role?
* **IAM User:** A permanent identity with long-term credentials (passwords, permanent access keys) tied to a specific human or application.
* **IAM Role:** An identity with no permanent credentials. It is designed to be assumed temporarily by users, workloads, or external identities, issuing short-lived STS security tokens. Roles promote credential rotation and temporary privilege escalation.

---

### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.
The Principle of Least Privilege (PoLP) dictates that an identity should only possess the minimum set of permissions required to complete its operational function. 
* In this lab, `Analyst_NADYA` was assigned only `AmazonS3ReadOnlyAccess`.
* If compromised, the adversary cannot modify data, create administrative credentials, or delete infrastructure. The damage is restricted solely to viewing S3 data, suppressing potential lateral movement and cluster/cloud takeover.

---

### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?
* **Role:** An API object that defines a set of permission rules (allowed HTTP verbs like `get`, `list`, `watch` on specific Kubernetes resources like `pods`). It contains no information about *who* gets the permissions.
* **RoleBinding:** An API object that connects a `Role` (permissions) to one or more `subjects` (users, groups, or ServiceAccounts), enforcing those permissions within a designated namespace.

---

### Q5. Why did the developer service account fail to access `prod`, and which security principle does that demonstrate?
The `dev-user` ServiceAccount failed to access `prod` because its `RoleBinding` (`dev-user-binding`) was defined inside namespace `dev` and referenced a namespaced `Role` (`pod-reader`). 
* This demonstrates **Least Privilege and Compartmentalization (Isolation)**. Namespaces enforce administrative boundaries; permissions in one namespace do not grant implicit access to adjacent namespaces.

---

## Verification Command Output

Command executed to verify cluster RBAC configuration:
```bash
sudo kubectl get rolebinding dev-user-binding -n dev -o yaml
```

**Terminal Proof Screenshot:**
![Prove Cluster RBAC is in Place](prove%20cluster%20RBAC%20is%20in%20place.png)

**YAML Manifest Output:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-04T10:28:45Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "823"
  uid: 93864742-432e-4cc0-a666-391a47aec782
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

---

## Security Best-Practices Checklist

| Security Control / Requirement | Status | Verification Detail |
| :--- | :---: | :--- |
| **Root user avoidance for daily tasks** | ✅ Completed | Created dedicated `CloudAdmin_NADYA` admin identity. |
| **Group/Role policy assignment** | ✅ Completed | Attached `AdministratorAccess` to `Admins` group. |
| **Least-privilege read-only identity** | ✅ Completed | Created `Analyst_NADYA` with `AmazonS3ReadOnlyAccess`. |
| **Access key hygiene & rotation** | ✅ Completed | Deactivated old key (`LKIAQAAAAAAALEF5QZ43`) to `Inactive`. |
| **Kubernetes RBAC boundary enforcement** | ✅ Completed | Verified `dev-user` access blocks `delete` & `prod` access. |

---

## Cleanup & Teardown Instructions

To clean up local lab resources after completion:

```bash
# 1. Delete local Kubernetes kind cluster
sudo kind delete cluster --name ccse-lab1

# 2. Stop and remove LocalStack container
docker stop localstack && docker rm localstack
```

---
*Report generated for IKB42603 Cloud Computing Security Essentials — UniKL MIIT*
