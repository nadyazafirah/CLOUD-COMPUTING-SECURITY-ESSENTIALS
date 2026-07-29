# IKB42603 Cloud Computing Security Essentials
## Lab 0: Environment Setup Report

* **Student Name**: Nadya Zafirah Binti Mohd Fairuz
* **Student ID**: 52215225256
* **Course**: IKB42603 Cloud Computing Security Essentials
* **Institution**: Universiti Kuala Lumpur (UniKL MIIT)
* **Instructor**: Prof. Dr. Shahrulniza Musa
* **Document**: `Environment-Setup.md` (Lab 0 Step-by-Step Report)

---

## 1. Overview & Tool Summary

Before starting the Cloud Computing Security Essentials labs, the required local environment tools must be installed and verified. All components run locally on your machine without requiring a paid cloud account, credit card, or active internet connection during lab execution.

### Installed Tools Overview

| Tool | Purpose | Target Labs |
| :--- | :--- | :--- |
| **Docker** | Runs containers and the LocalStack cloud simulator | All Labs |
| **AWS CLI v2** | Sends AWS service API commands to LocalStack | Labs 1, 3, 5 |
| **kind** | Runs a local Kubernetes cluster inside Docker containers | Labs 1, 2, 4 |
| **kubectl** | Command-line tool to control the Kubernetes cluster | Labs 1, 2, 4 |
| **OpenSSL** | Handles cryptographic functions, keys, and certificates | Lab 3 |
| **oathtool** | Generates Multi-Factor Authentication (MFA) / TOTP codes | Lab 4 |
| **Trivy** | Scans container images for security vulnerabilities (Run via Docker) | Lab 4 |

> [!TIP]
> **Operating System Note**: On Windows systems, all lab commands should be executed inside **Git Bash** or **WSL (Ubuntu)** to ensure compatibility with bash features (e.g., heredocs, `sha256sum`, single-quoting). Linux distributions (such as Kali Linux) run these natively.

---

## 2. Step-by-Step Tool Installation & Verification

### Step 1: Install & Verify Docker

Docker serves as the container engine for LocalStack and `kind` Kubernetes clusters.

#### Verification Command
```bash
docker --version
docker run --rm hello-world
```

#### Output & Verification
- Executed on Kali Linux environment.
- Output: `Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed`

![Docker Installation Verification](docker%20installation.png)

---

### Step 2: Install & Verify AWS CLI v2

AWS CLI v2 is used to interact with LocalStack's local AWS endpoints.

#### Verification Command
```bash
aws --version
```

#### Output & Verification
- Output: `aws-cli/2.34.56 Python/3.13.12 Linux/6.18.12+kali-amd64 source/x86_64.kali.2026`

![AWS CLI Installation Verification](aws%20installation.png)

---

### Step 3: Install & Verify `kind` and `kubectl`

`kind` (Kubernetes in Docker) spins up local nodes using Docker containers, while `kubectl` manages the cluster resources.

#### Verification Commands
```bash
kind --version
kubectl version --client
```

#### Output & Verification
* **kind**: `kind version 0.31.0`
* **kubectl**: `Client Version: v1.33.4`, `Kustomize Version: v5.5.0`

![kind Installation Verification](kind%20installation.png)

![kubectl Installation Verification](kubectl%20installation.png)

---

### Step 4: Install & Verify Helper Tools (OpenSSL & oathtool)

Helper security tools facilitate encryption exercises and MFA/TOTP token generation.

#### Verification Commands
```bash
openssl version
oathtool --version
```

#### Output & Verification
* **OpenSSL**: `OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)`
* **oathtool**: `oathtool (OATH Toolkit) 2.6.14`

![OpenSSL Version Verification](openssl%20version.png)

![oathtool Installation Verification](oathtool%20installation.png)

---

## 3. Start & Stop the Lab Environment

### 3.1 LocalStack Cloud Simulator

LocalStack simulates AWS cloud services locally on port `4566`.

#### Execution Commands
```bash
# 1. Start LocalStack container in background
docker run -d --name localstack -p 4566:4566 localstack/localstack:3.0

# 2. Check health status of LocalStack endpoints
curl http://localhost:4566/_localstack/health

# 3. Managing LocalStack container lifecycle
docker stop localstack
docker start localstack
docker rm -f localstack
```

#### Output & Verification
The health endpoint returns a JSON payload showing all services (IAM, S3, STS, EC2, Lambda, DynamoDB, etc.) with status `"available"`.

![LocalStack Container Running & Health Check](localstack.png)

![Start & Stop Local Environment](5.%20start%20stop%20local%20environment.png)

---

### 3.2 Kubernetes Cluster (`kind`)

Create and manage local Kubernetes clusters named `ccse` for security testing.

#### Execution Commands
```bash
# 1. Create a kind cluster named 'ccse'
sudo kind create cluster --name ccse

# 2. Check cluster control plane and nodes
sudo kubectl cluster-info --context kind-ccse
sudo kubectl get nodes

# 3. Delete cluster after lab completion
sudo kind delete cluster --name ccse
```

#### Output & Verification
- Cluster created successfully using node image `kindest/node:v1.35.0`.
- Control plane running at `https://127.0.0.1:39093`.
- `ccse-control-plane` status: **Ready** (Version `v1.35.0`).

![Kubernetes Cluster Creation & Verification](5.%20kubernetes%20cluster.png)

---

## 4. One-Time AWS CLI Configuration

To allow AWS CLI to communicate with LocalStack without requiring real AWS credentials, configure dummy parameters once.

#### Setup Commands
```bash
# 1. Set dummy AWS credentials and default region
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

# 2. Define LocalStack endpoint environment variable shortcut
EP='--endpoint-url=http://localhost:4566'

# 3. Verify AWS CLI connection to LocalStack
aws $EP sts get-caller-identity
```

#### Expected Response
```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

![AWS CLI Configuration and LocalStack Identity Verification](6.%20One-Time%20AWS%20CLI%20Configuration.png)

---

## 5. Pre-Lab Verification Checklist

Ensure all items below are checked prior to starting Lab 1:

- [x] `docker --version` prints valid version & `docker run --rm hello-world` executes cleanly.
- [x] `aws --version` prints `aws-cli/2.x`.
- [x] `kind --version` and `kubectl version --client` both execute without errors.
- [x] LocalStack container starts and `curl http://localhost:4566/_localstack/health` returns healthy JSON response.
- [x] `aws $EP sts get-caller-identity` returns the dummy LocalStack root identity.
- [x] `kind create cluster --name ccse` creates cluster and `kubectl get nodes` displays `ccse-control-plane` node as `Ready`.
- [x] All terminal operations are run inside Git Bash, WSL, or native Linux shell.

---

## 6. Troubleshooting Guide

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| `Cannot connect to the Docker daemon` | Docker service isn't active or permission error | Start Docker Desktop or run `sudo usermod -aG docker $USER` and re-login. |
| `Docker won't start / very slow` | BIOS/UEFI virtualization disabled | Enable Virtualization (VT-x / AMD-V) in BIOS/UEFI. On Windows, enable WSL 2 and Virtual Machine Platform. |
| `Port 4566 already in use` | Existing LocalStack instance is running | Execute `docker rm -f localstack` before re-launching container. |
| `aws: Could not connect to the endpoint URL` | LocalStack is down or `$EP` variable omitted | Ensure LocalStack is running and append `--endpoint-url=http://localhost:4566` (or `$EP`). |
| `aws: command not found` / `kubectl not found` | Tools not installed or missing from `PATH` | Install missing tools and ensure installation directory is in system `PATH`. |
| `heredoc / sha256sum errors on Windows` | Executing commands in CMD or PowerShell | Switch shell to Git Bash or WSL (Ubuntu). |
| `kind create cluster fails` | Low allocated RAM or Docker inactive | Ensure Docker Desktop has at least 4 GB RAM allocated and is running. |

---

## 7. Handy One-Liners & Cheat Commands

```bash
# Start LocalStack session
docker start localstack 2>/dev/null || docker run -d --name localstack -p 4566:4566 localstack/localstack:3.0
EP='--endpoint-url=http://localhost:4566'

# Inspect running environment resources
docker ps
kind get clusters

# Clean up resources to free disk space
docker rm -f localstack
kind delete clusters --all
docker system prune -f
```
