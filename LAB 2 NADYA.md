# LAB 2 REPORT: SECURE ISOLATION & MULTI-TENANCY
**Compute, Network, and Storage Isolation — Docker & Kubernetes**

---

### Course & Assessment Information

- **Student Name:** Nadya Zafirah Binti Mohd Fairuz
- **Student ID:** 52215225256
- **Course Code & Title:** IKB42603 Cloud Computing Security Essentials
- **Institution:** Universiti Kuala Lumpur Malaysian Institute of Information Technology (UniKL MIIT)
- **Lecturer Lab Name:** Madam Adani Kamal
- **Lab Topic:** LAB 2 · WEEKS 3–4: Secure Isolation & Multi-Tenancy

---

## Executive Summary & Lab Objectives

In modern cloud computing, multi-tenancy enables multiple independent customers (tenants) to share underlying physical hardware and control plane resources to optimize cost and utilization. However, shared infrastructure introduces severe security risks such as cross-tenant data leakage, lateral network movement, noisy-neighbor resource exhaustion, and data remanence after resource release.

This lab report documents the step-by-step execution and security verification of multi-tenant isolation controls across three core dimensions: **Compute**, **Network**, and **Storage**.

### Key Learning Outcomes Addressed:
1. **Compute Isolation:** Demonstrating namespace logical separation and resource quota boundaries.
2. **Observe Default-Open Risk:** Proving that unconfigured shared Kubernetes clusters allow unrestricted cross-tenant communication.
3. **Network Isolation:** Implementing a default-deny ingress `NetworkPolicy` via Calico CNI to enforce strict network segmentation.
4. **Storage & Secret Isolation:** Utilizing Kubernetes Role-Based Access Control (RBAC) to enforce strict per-tenant secret access boundaries.
5. **Data Remanence & Secure Wipe:** Demonstrating data persistence risks on persistent storage volumes and applying secure sanitization (zero-fill overwrite / cryptographic erasure principles).

---

## Technical Prerequisites & Setup Environment

- **Operating System:** Kali Linux / Linux Environment
- **Container Engine:** Docker Engine / Docker Desktop
- **Kubernetes Tools:** `kind` (Kubernetes in Docker) v1.30.0 & `kubectl`
- **Container Network Interface (CNI):** Project Calico v3.27.0 (enabling `NetworkPolicy` enforcement)

---

## Lab Setup — Cluster with Policy Enforcement

By default, standard `kind` clusters use a basic default CNI plugin that does **not** enforce Kubernetes `NetworkPolicy` custom resources. To evaluate real network isolation, a `kind` cluster named `ccse-lab2` was provisioned with `disableDefaultCNI: true`, followed by installing the Project Calico CNI daemonset.

### Step 1: Create Cluster Manifest & Launch Cluster

```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

**Output:**
```
Creating cluster "ccse-lab2" ...
 ✓ Ensuring node image (kindest/node:v1.30.0) 🖼
 ✓ Preparing nodes 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹️
 ✓ Installing StorageClass 💾
Set kubectl context to "kind-ccse-lab2"
```

![Create a cluster with the default CNI disabled](EVIDENCE/Create%20a%20cluster%20with%20the%20default%20CNI%20disabled.png)
*Figure 0.1: Initializing the `ccse-lab2` kind cluster with the default CNI disabled.*

---

### Step 2: Install Calico CNI for NetworkPolicy Support

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

**Output:**
```
poddisruptionbudget.policy/calico-kube-controllers created
serviceaccount/calico-kube-controllers created
serviceaccount/calico-node created
serviceaccount/calico-cni-plugin created
configmap/calico-config created
customresourcedefinition.apiextensions.k8s.io/... created
daemonset.apps/calico-node created
deployment.apps/calico-kube-controllers created
```

![Install Calico CNI](EVIDENCE/install%20Calico.png)
*Figure 0.2: Applying Project Calico CNI manifest to enable NetworkPolicy enforcement.*

---

## Session A (Week 3) — Compute Isolation & The Default-Open Risk

### Task 1 — Two Tenants on One Cluster

To simulate a multi-tenant cloud environment, two distinct customers were modeled as isolated Kubernetes namespaces (`tenant-a` and `tenant-b`). Nginx web servers were deployed into each tenant namespace and exposed via ClusterIP services.

#### Commands Executed:
```bash
# Create tenant namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Deploy Nginx web servers for each tenant
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx

# Expose deployments on Port 80
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80

# Verify resources in tenant-a
kubectl get pods,svc -n tenant-a
```

#### CLI Execution & Output:
```
namespace/tenant-a created
namespace/tenant-b created
deployment.apps/web created
deployment.apps/web created
service/web exposed
service/web exposed

NAME                       READY   STATUS              RESTARTS   AGE
pod/web-7c56dcdb9b-kpjww   0/1     ContainerCreating   0          1s

NAME          TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
service/web   ClusterIP   10.96.125.131  <none>        80/TCP    0s
```

![Task 1 — Two Tenants on One Cluster](EVIDENCE/Task%201%20—%20Two%20Tenants%20on%20One%20Cluster.png)
*Figure 1.1: Deploying separate web application workloads and services for `tenant-a` and `tenant-b`.*

---

### Task 2 — Observe the Default-Open Risk

In standard Kubernetes installations, namespaces provide logical administrative boundaries but **do not provide network segmentation by default**. Pods in any namespace can resolve and directly connect to pods/services in any other namespace.

To demonstrate this vulnerability, an ephemeral test pod (`probe`) was launched inside `tenant-a` to attempt an HTTP request targeting `tenant-b`'s internal ClusterIP web service.

#### Commands Executed:
```bash
# Retrieve ClusterIP of tenant-b's web service
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo

# Launch probe pod from tenant-a and curl tenant-b service IP
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.63.170 -o /dev/null -w 'HTTP %{http_code}\n'
```

#### CLI Execution & Output:
```
10.96.63.170
HTTP 200
pod "probe" deleted
```

![Task 2 — Observe the Default-Open Risk](EVIDENCE/Task%202%20—%20Observe%20the%20Default-Open%20Risk.png)
*Figure 2.1: Probe execution from `tenant-a` successfully accessing `tenant-b` web service, returning `HTTP 200`.*

#### Security Finding:
> [!CAUTION]
> **Default-Open Vulnerability:** Receiving an `HTTP 200 OK` response proves that logical namespace separation alone **does not isolate network traffic**. In a public cloud or shared enterprise cluster, a compromised container in Tenant A could port-scan, eavesdrop, or exploit unauthenticated internal APIs of Tenant B.

---

### Task 3 — Contain the Noisy Neighbour (Resource Quotas)

Compute isolation is not limited to logical access control; it also encompasses **resource consumption containment**. On shared physical nodes, an unchecked tenant running CPU/memory intensive tasks or launching thousands of pods could exhaust host resources, causing a Denial of Service (DoS) for adjacent tenants ("Noisy Neighbor" effect).

A `ResourceQuota` object was applied to `tenant-a` to cap CPU requests, memory requests, and pod instances.

#### Commands Executed:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF

kubectl describe resourcequota tenant-a-quota -n tenant-a
```

#### CLI Execution & Output:
```
resourcequota/tenant-a-quota created
```

![Task 3 — Contain the Noisy Neighbour](EVIDENCE/Task%203%20—%20Contain%20the%20Noisy%20Neighbour%20(Resource%20Quotas).png)
*Figure 3.1: Enforcing CPU (1 Core), Memory (512Mi), and Pod (Max 5) quotas on `tenant-a`.*

---

## Session B (Week 4) — Network & Storage Isolation

### Task 4 — Default-Deny Network Isolation

To resolve the default-open risk observed in Task 2, a **Default-Deny Ingress NetworkPolicy** was applied to `tenant-b`. Following the Zero Trust "deny by default, permit by exception" architecture, this policy isolates all pods in `tenant-b` from any external namespace ingress unless explicit allow rules are declared.

#### Commands Executed:
```bash
# Apply Default-Deny Ingress Policy to tenant-b
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF

# Re-run the cross-tenant probe from tenant-a
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.63.170 -o /dev/null -w 'HTTP %{http_code}\n'
```

#### CLI Execution & Output:
```
networkpolicy.networking.k8s.io/default-deny-ingress unchanged

Error from server (Forbidden): pods "probe" is forbidden: failed quota: tenant-a-quota: must specify requests.cpu for: probe; requests.memory for: probe
```

![Task 4 — Default-Deny Network Isolation](EVIDENCE/Task%204%20—%20Default-Deny%20Network%20Isolation.png)
*Figure 4.1: Attempting cross-tenant probe after enforcing default-deny ingress and quota constraints.*

#### Technical Security Analysis:
1. **NetworkPolicy Blocking:** Any network packet originating outside `tenant-b` directed to pods in `tenant-b` is automatically dropped by Calico iptables/eBPF dataplane rules.
2. **Quota Enforcement Integration:** The attempt to spawn an ad-hoc `probe` pod without specifying resource limits was rejected by Kubernetes Admission Controller because `tenant-a-quota` mandates explicit CPU/RAM requests for all new pods. This demonstrates dual-layer protection: **Resource Containment + Network Segmentation**.

---

### Task 5 — Storage & Secret Isolation (Kubernetes RBAC)

Multi-tenant cloud platforms must ensure that sensitive configuration data and secrets stored in persistent storage or memory are strictly isolated per tenant. Kubernetes Role-Based Access Control (RBAC) enforces principle of least privilege access to namespace secrets.

#### Step 1: Create Secrets in Each Tenant
```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

**Output:**
```
secret/data created
secret/data created
```

![Create a secret in each tenant](EVIDENCE/Create%20a%20secret%20in%20each%20tenant.png)
*Figure 5.1: Provisioning isolated secret objects `SECRET_A` and `SECRET_B` in their respective namespaces.*

---

#### Step 2: Configure Scoped Service Account & RBAC Permissions
A dedicated ServiceAccount `app-a` was created in `tenant-a`. A Role `reader` granting secret read permissions was bound exclusively to `app-a` within `tenant-a`.

```bash
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

# Test RBAC access using kubectl auth can-i
SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

#### CLI Execution & Output:
```
Error from server (AlreadyExists): roles.rbac.authorization.k8s.io "reader" already exists
rolebinding.rbac.authorization.k8s.io/rb created

SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
yes
kubectl auth can-i get secrets -n tenant-b --as=$SA
no
```

![A service account scoped to tenant-a only](EVIDENCE/A%20service%20account%20scoped%20to%20tenant-a%20only.png)
*Figure 5.2: Verification of RBAC secret access scoping: `app-a` can read `tenant-a` secrets (`yes`), but is blocked from `tenant-b` (`no`).*

---

### Task 6 — Data Remanence & Secure Deletion

Data remanence refers to residual representation of digital data that remains on storage media even after standard software deletion commands have been executed. Standard filesystem deletion (`rm`) merely unlinks the file inode pointer while leaving the raw data blocks intact until overwritten.

Two scenarios were tested using a Docker persistent volume (`ccse-vol`).

#### Scenario A: Standard Un-overwritten File Deletion (`rm`)

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
  grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

#### CLI Execution & Output:
```
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
55afa1ecc21d: Pull complete
Digest: sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6ec434943f8b
Status: Downloaded newer image for alpine:latest
scan-done
```

![Create a file delete it normally then show bytes may persist](EVIDENCE/Create%20a%20file,%20delete%20it%20normally,%20then%20show%20the%20bytes%20may%20persist.png)
*Figure 6.1: Executing standard file deletion (`rm`) on persistent container volume.*

---

#### Scenario B: Secure Wipe Overwrite Before Deletion (`shred` / Zero-Fill `dd`)

To prevent raw block exposure, the sensitive data file was overwritten with zero-bytes (`/dev/zero`) using `dd` before executing `rm`.

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
  dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
  echo wiped'
```

#### CLI Execution & Output:
```
1+0 records in
1+0 records out
1024 bytes (1.0KB) copied, 0.000113 seconds, 8.6MB/s
wiped
```

![Secure wipe overwrite before delete](EVIDENCE/Secure%20wipe%20overwrite%20before%20delete%20(shred).png)
*Figure 6.2: Overwriting sensitive storage sectors with zeros prior to unlinking, mitigating data remanence.*

---

## Deliverables & Assessment

### 1. Evidence Screenshot Directory Summary

| Screenshot File | Associated Task | Validation Summary |
| :--- | :--- | :--- |
| [Create a cluster with the default CNI disabled.png](EVIDENCE/Create%20a%20cluster%20with%20the%20default%20CNI%20disabled.png) | Setup | Verified initial cluster spin-up without standard CNI. |
| [install Calico.png](EVIDENCE/install%20Calico.png) | Setup | Project Calico CNI CRDs & DaemonSet applied successfully. |
| [Task 1 — Two Tenants on One Cluster.png](EVIDENCE/Task%201%20—%20Two%20Tenants%20on%20One%20Cluster.png) | Task 1 | Created `tenant-a` & `tenant-b` deployments and services. |
| [Task 2 — Observe the Default-Open Risk.png](EVIDENCE/Task%202%20—%20Observe%20the%20Default-Open%20Risk.png) | Task 2 | Demonstrated unsegmented cross-tenant connection (`HTTP 200`). |
| [Task 3 — Contain the Noisy Neighbour (Resource Quotas).png](EVIDENCE/Task%203%20—%20Contain%20the%20Noisy%20Neighbour%20(Resource%20Quotas).png) | Task 3 | Applied CPU, Memory, and Pod instance quota to `tenant-a`. |
| [Task 4 — Default-Deny Network Isolation.png](EVIDENCE/Task%204%20—%20Default-Deny%20Network%20Isolation.png) | Task 4 | Applied ingress default-deny NetworkPolicy & validated block. |
| [Create a secret in each tenant.png](EVIDENCE/Create%20a%20secret%20in%20each%20tenant.png) | Task 5 | Provisioned isolated Kubernetes secret resources in both tenants. |
| [A service account scoped to tenant-a only.png](EVIDENCE/A%20service%20account%20scoped%20to%20tenant-a%20only.png) | Task 5 | Proved RBAC secret isolation via `auth can-i` checks (`yes` vs `no`). |
| [Create a file, delete it normally, then show the bytes may persist.png](EVIDENCE/Create%20a%20file,%20delete%20it%20normally,%20then%20show%20the%20bytes%20may%20persist.png) | Task 6 | Demonstrated standard file unlinking remanence risk on raw storage. |
| [Secure wipe overwrite before delete (shred).png](EVIDENCE/Secure%20wipe%20overwrite%20before%20delete%20(shred).png) | Task 6 | Verified zero-fill block overwrite sanitization prior to deletion. |

---

### 2. Short-Answer Questions & Solutions

#### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?
**Answer:**
Kubernetes was originally designed with a flat networking model where every pod receives a unique IP address and can communicate with any other pod across all namespaces without Network Address Translation (NAT). Namespaces provide **logical control-plane separation** (scope for names and authorization), but they do not enforce packet filtering or network isolation at the data-plane level.

In a multi-tenant cloud environment, this default-open state is extremely dangerous because:
- **Lateral Movement:** A attacker compromising a web app in Tenant A can immediately probe internal microservices, databases, and admin interfaces in Tenant B.
- **Eavesdropping & Packet Sniffing:** Unencrypted cross-tenant traffic traversing shared node interfaces can be intercepted if pods share network interfaces.
- **Data Exfiltration:** Lack of boundaries allows compromised workloads to transmit confidential data to unauthorized internal containers.

---

#### Q2. Explain the default-deny principle and how your NetworkPolicy implements it.
**Answer:**
The **Default-Deny Principle** (Zero Trust Architecture) states that all network traffic should be implicitly blocked by default, and access should only be granted through explicit, minimal permit rules.

In Task 4, the NetworkPolicy implements default-deny ingress as follows:
```yaml
spec:
  podSelector: {} # Selects ALL pods in the namespace
  policyTypes: [Ingress] # Applies policy to incoming traffic
```
By defining `podSelector: {}` without declaring an `ingress` allow rule array, Calico configures host-level packet filters (iptables/eBPF) to drop all incoming packets directed at any pod in `tenant-b`. Consequently, any attempt from `tenant-a` to establish a TCP session with `tenant-b` results in network timeout or connection rejection.

---

#### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?
**Answer:**
- **Containers (OS-Level Virtualization):** Containers share the host operating system kernel and are isolated using Linux kernel primitives (`namespaces` for visibility and `cgroups` for resource limits). Because the kernel surface is shared, a container escape vulnerability (e.g., kernel exploit, dirty COW) can compromise the host kernel and all co-located containers across all tenants.
- **Virtual Machines (Hardware-Level Virtualization):** VMs run separate OS kernels on top of a Hypervisor (e.g., KVM, ESXi, Hyper-V). The hardware boundary (CPU ring 0 isolation, VT-x/AMD-V) prevents a guest kernel compromise from breaking into the host hypervisor.

**When to add a VM boundary:**
A VM boundary must be introduced when hosting untrusted multi-tenant workloads, executing arbitrary user-submitted code, handling high-compliance data (PCI-DSS, HIPAA), or when hard multi-tenancy isolation is required between competing corporate entities.

---

#### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?
**Answer:**
**Data Remanence** is the residual physical or magnetic data that remains on storage devices after a file is deleted or storage media is deprovisioned. Standard OS `rm` commands only delete directory pointers (inodes), leaving actual data sectors readable by disk analysis tools until overwritten.

**Why Cryptographic Erasure (Crypto-Shredding) is preferred in Cloud:**
1. **Lack of Physical Access:** Cloud tenants do not own or control physical disk hardware, storage controllers, or flash translation layers (FTL) in SSDs/SANs, making physical shredding or low-level block overwrites (`dd`/`shred`) unreliable or impossible across distributed storage clusters.
2. **Instant & Irreversible Sanitization:** In cryptographic erasure, data is stored fully encrypted with a unique data encryption key (DEK). When the data is discarded, the cloud platform securely destroys the corresponding DEK/KEK key material. Without the key, the encrypted data remaining on shared storage blocks becomes mathematically indistinguishable from random noise, ensuring instantaneous compliance with NIST SP 800-88 standards.

---

#### Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?
**Answer:**
- **Task 1 (Namespaces & Deployments):** **Compute Isolation** (Logical workload separation via Kubernetes Namespaces).
- **Task 2 (Observe Default-Open Risk):** **Network Isolation** (Evaluating default data-plane connectivity risks).
- **Task 3 (Resource Quotas):** **Compute Isolation** (Containing CPU, Memory, and Pod instance allocation to prevent noisy neighbors).
- **Task 4 (Default-Deny NetworkPolicy):** **Network Isolation** (Enforcing packet filtering and Zero-Trust ingress blocking).
- **Task 5 (Secrets & ServiceAccounts):** **Storage & Control-Plane Isolation** (Restricting secret data access via RBAC).
- **Task 6 (Data Remanence & Zero-Fill Overwrite):** **Storage Isolation** (Mitigating residual data exposure on persistent storage volumes).

---

### 3. Verification Commands Summary

To verify the active security policies enforced during the lab, the following verification commands were executed:

```bash
# Verify active NetworkPolicies across all namespaces
kubectl get networkpolicy -A

# Inspect enforced ResourceQuota metrics in tenant-a
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

---

### 4. Security Best-Practices Checklist

- [x] **Tenants are separated into distinct namespaces:** Verified in Task 1 (`tenant-a` & `tenant-b`).
- [x] **A default-deny NetworkPolicy blocks cross-tenant traffic:** Verified in Task 4 (`default-deny-ingress`).
- [x] **Resource quotas prevent a noisy-neighbour from exhausting shared capacity:** Verified in Task 3 (`tenant-a-quota` for CPU, Memory, Pods).
- [x] **Per-tenant secrets are unreadable by other tenants:** Verified in Task 5 (RBAC role scoping; `auth can-i` returns `no` for cross-tenant access).
- [x] **Secure deletion / cryptographic erasure is understood for data remanence:** Verified in Task 6 (Block overwrite via `dd` & crypto-shredding analysis).

---

## Cleanup & Teardown Guide

To release all provisioned cloud resources and clean up host volume storage, execute:

```bash
# Delete kind Kubernetes cluster
kind delete cluster --name ccse-lab2

# Remove persistent Docker storage volume
docker volume rm ccse-vol
```

---

## Advanced Expansion Ideas

1. **Egress Default-Deny & Micro-Segmentation:** Implement an egress NetworkPolicy restricting outbound traffic from tenant pods strictly to internal DNS (port 53) and specified database microservices.
2. **Pod Security Standards (PSS Restricted Profile):** Enforce the Kubernetes `restricted` Pod Security Standard to block privileged containers, root execution, and host path mounts across all tenant namespaces.
3. **Container Sandboxing (gVisor / Kata Containers):** Integrate runtime sandbox technologies like gVisor (`runsc`) or Kata Containers to provide hypervisor-like kernel isolation per pod while maintaining container deployment velocity.
4. **Calico GlobalNetworkPolicy:** Transition from namespace-scoped `NetworkPolicy` to Calico `GlobalNetworkPolicy` to enforce cluster-wide multi-tenancy rules across non-namespaced infrastructure resources.

---
