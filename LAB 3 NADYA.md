# LAB 3 REPORT: DATA PROTECTION, ENCRYPTION & KEY MANAGEMENT

**Name:** Nadya Zafirah Binti Mohd Fairuz  
**Student ID:** 52215225256 
**Course:** IKB42603 Cloud Computing Security Essentials  
**Session:** Weeks 5–6 (Session A & Session B)  
**Institution:** Universiti Kuala Lumpur Malaysian Institute of Information Technology (UniKL MIIT)  
**Lecturer:** Madam Nor Adani Kamal Binti Mohamad Nasir  

---

## Executive Summary & Lab Learning Outcomes

This report documents the practical execution of **Lab 3: Data Protection: Encryption & Key Management**. The objective of this lab is to evaluate data protection techniques at rest and in transit, master envelope encryption using AWS KMS (simulated via LocalStack), implement per-tenant cryptographic erasure, and construct tamper-evident log records using hash chaining.

### Learning Outcomes Covered:
1. **Symmetric (AES) and Asymmetric (RSA) Cryptography:** Hands-on data encryption, decryption, and digital signatures with OpenSSL.
2. **Data in Transit Protection (TLS):** Configuring HTTPS endpoints using self-signed X.509 certificates and Docker Nginx containers.
3. **Key Management Services (KMS) & Envelope Encryption:** Generating Customer Master Keys (CMKs) and ephemeral data keys via LocalStack KMS.
4. **Per-Tenant Keys & Cryptographic Erasure:** Demonstrating tenant data isolation and provable data deletion by revoking/scheduling deletion of master keys.
5. **Data Integrity & Tamper-Evidence:** Detecting unauthorized modifications with SHA-256 fingerprinting and implementing a cryptographic hash chain.

---

## Session A (Week 5) — Encryption Fundamentals

### Task 1 — Symmetric Encryption (Data at Rest)

#### Objective
Create a sensitive patient record and encrypt it using symmetric cipher **AES-256-CBC** with PBKDF2 key derivation. Verify that the encrypted file is unreadable and successfully restore it via symmetric decryption.

#### Step-by-Step Execution & Commands

```bash
# 1. Create a sample sensitive record
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt

# 2. Encrypt with AES-256-CBC (PBKDF2 salt enabled)
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

# 3. View binary ciphertext to verify data unreadability
cat record.enc

# 4. Decrypt the record and verify integrity against original file
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

#### Terminal Execution & Evidence

- **Encryption & Ciphertext Verification:**  
  ![Task 1 - Encryption Output](EVIDENCE/Task%201%20—%20Symmetric%20Encryption%20(Data%20at%20Rest).png)

- **Decryption & Match Confirmation:**  
  ![Task 1 - Decryption Match](EVIDENCE/Task%201%20-%20%23%20Decrypt%20back.png)

#### Terminal Output Captured
```text
enter AES-256-CBC encryption password:
Verifying - enter AES-256-CBC encryption password:

cat record.enc
.K!fs'"|'<t#NWL5 9

enter AES-256-CBC decryption password:
MATCH: decryption successful
```

#### Discussion: Symmetric Key Distribution Problem in Cloud Computing
Symmetric encryption uses a single shared secret key for both encryption and decryption. In modern cloud architecture, this introduces a severe **Key Distribution Problem**:
- **Transmission Risk:** Transmitting the secret key securely across untrusted networks to multiple distributed cloud nodes or client applications is inherently complex. If the shared key is intercepted in transit, the confidentiality of all encrypted records is compromised.
- **Scale & N-to-N Complexity:** Sharing symmetric keys between $N$ parties requires $N(N-1)/2$ secret key exchanges, which creates massive key management overhead for multi-tenant cloud platforms.

---

### Task 2 — Asymmetric Encryption & Digital Signatures

#### Objective
Generate a 2048-bit RSA public/private key pair. Perform public key encryption, private key decryption, and utilize private key signing with public key verification (`Verified OK`).

#### Step-by-Step Execution & Commands

```bash
# 1. Generate a 2048-bit RSA private key
openssl genrsa -out private.pem 2048

# 2. Extract corresponding public key
openssl rsa -in private.pem -pubout -out public.pem

# 3. Encrypt data with the PUBLIC key, decrypt with the PRIVATE key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# 4. Sign data with the PRIVATE key, verify signature with the PUBLIC key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

#### Terminal Execution & Evidence

![Task 2 - Asymmetric & Signatures](EVIDENCE/Task%202%20—%20Asymmetric%20Encryption%20%26%20Digital%20Signatures.png)

#### Terminal Output Captured
```text
writing RSA key
Verified OK
```

#### Technical Analysis: Role Reversal in Asymmetric Cryptography
- **Confidentiality (Encryption):** Public key encrypts, Private key decrypts. Anyone can securely send data to the recipient, but only the holder of the secret private key can read it.
- **Authenticity & Non-Repudiation (Digital Signatures):** Private key signs, Public key verifies. Only the owner of the private key could have produced the signature, enabling anyone holding the public key to mathematically verify origin and data integrity.

---

### Task 3 — Encryption in Transit (TLS)

#### Objective
Generate a self-signed X.509 certificate and private key, launch an Nginx web server inside a Docker container serving over HTTPS (TLS port 8443), and confirm transport encryption via `curl`.

#### Step-by-Step Execution & Commands

```bash
# 1. Generate self-signed certificate and key
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 7 -nodes -subj '/CN=localhost'

# 2. Deploy HTTPS Nginx container mounting certificate and sensitive file
docker run --rm -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
  -v $(pwd)/key.pem:/etc/nginx/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
  -v $(pwd)/nginx.conf:/etc/nginx/conf.d/default.conf nginx

# 3. Query the endpoint securely via HTTPS (skipping self-signed certificate check with -k)
curl -k https://localhost:8443/record.txt
```

#### Terminal Execution & Evidence

- **Self-Signed Certificate Generation:**  
  ![Task 3 - Certificate Generation](EVIDENCE/Task%203%20-%20%23%20Generate%20a%20self-signed%20certificate.png)

- **Docker Container & HTTPS Request:**  
  ![Task 3 - TLS Execution](EVIDENCE/Task%203%20—%20Encryption%20in%20Transit%20(TLS).png)

#### Terminal Output Captured
```text
docker run container ID: f60bd9c35e63d82f3f366a8145bcb2943f44bdfc56217174b3ff3aa28edacffe

curl -k https://localhost:8443/record.txt
Patient: Ahmad, Diagnosis: confidential
```

#### Security Analysis: Plain HTTP vs. TLS (HTTPS)
- **Plain HTTP (Unencrypted):** Data is transmitted in clear text across routers, switches, and internet service providers. Any adversary positioned on the network path (on-path eavesdropping or Man-in-the-Middle) can capture packets and read confidential payload items directly.
- **TLS Protection:** TLS establishes an encrypted session layer using asymmetric cryptography for handshakes/key exchange and symmetric ciphers for high-speed bulk data transport. Intercepted network traffic appears as random ciphertext.

---

## Session B (Week 6) — Key Management, Envelope Encryption & Erasure

### Task 4 — Create and Use a KMS Master Key

#### Objective
Configure LocalStack KMS (`http://localhost:4566`), create a Customer Master Key (CMK) for Tenant A, and perform direct encryption of a short secret payload via AWS CLI.

#### Step-by-Step Execution & Commands

```bash
# 1. Set LocalStack KMS Endpoint variable
EP='--endpoint-url=http://localhost:4566'

# 2. Create CMK for Tenant A
aws $EP kms create-key --description 'CCSE tenant-A master key'

# 3. Store KeyId output
KEY_A='6bef6f84-667e-4f4c-8efe-3c0cdb7dc0bc'

# 4. Directly encrypt a small secret via KMS API
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text
```

#### Terminal Execution & Evidence

- **CMK Key Creation Metadata:**  
  ![Task 4 - Master Key Creation](EVIDENCE/Task%204%20—%20Create%20and%20Use%20a%20KMS%20Master%20Key.jpeg)

- **Direct KMS Encryption:**  
  ![Task 4 - Direct Encryption](EVIDENCE/Task%204%20—%20%23%20Encrypt%20a%20small%20secret%20directly%20with%20KMS.jpeg)

#### Captured Master Key Details
```json
{
    "KeyMetadata": {
        "AWSAccountId": "000000000000",
        "KeyId": "6bef6f84-667e-4f4c-8efe-3c0cdb7dc0bc",
        "Arn": "arn:aws:kms:us-east-1:000000000000:key/6bef6f84-667e-4f4c-8efe-3c0cdb7dc0bc",
        "CreationDate": "2026-08-20T16:39:34.106616+08:00",
        "Enabled": true,
        "Description": "CCSE tenant-A master key",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled"
    }
}
```

---

### Task 5 — Envelope Encryption

#### Objective
Implement **Envelope Encryption** by generating a symmetric Data Encryption Key (DEK) from KMS, encrypting local files with the plaintext DEK, and immediately purging the plaintext key from local disk—leaving only the KMS-wrapped data key (`datakey.enc`).

#### Step-by-Step Execution & Commands

```bash
# 5.1 Generate data key from KMS (returns Plaintext + CiphertextBlob)
aws $EP kms generate-data-key --key-id 6bef6f84-667e-4f4c-8efe-3c0cdb7dc0bc --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text > temp.txt

# 5.2 Decode plaintext data key and encrypt file locally
base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc -pass file:./datakey.bin

# 5.3 Purge plaintext key from disk
rm datakey.bin datakey.b64
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
```

#### Terminal Execution & Evidence

![Task 5 - Envelope Encryption](EVIDENCE/Task%205%20—%20Envelope%20Encryption.jpeg)

#### Terminal Output Captured
```text
Only the KMS-wrapped data key (datakey.enc) remains.
```

---

### Task 6 — Per-Tenant Keys & Cryptographic Erasure

#### Objective
Demonstrate multi-tenant key isolation by creating a separate master key for Tenant B (`KEY_B`), schedule deletion on Tenant A's master key (`KEY_A`), and verify that unwrapping Tenant A's data key fails (`NotFoundException` / `KMSInvalidStateException`), proving permanent **Cryptographic Erasure**.

#### Step-by-Step Execution & Commands

```bash
# 1. Create separate master key for Tenant B
aws $EP kms create-key --description 'CCSE tenant-B master key'
KEY_B='d696f465-b0f0-4d57-ba30-b4702effd7ab'

# 2. Schedule key deletion for Tenant A (7-day window)
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7

# 3. Disable Tenant A master key immediately
aws $EP kms disable-key --key-id $KEY_A

# 4. Attempt to decrypt Tenant A's wrapped data key (Must FAIL)
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

#### Terminal Execution & Evidence

- **Schedule Deletion & Key State Verification:**  
  ![Task 6 - Key Deletion Scheduling](EVIDENCE/Task%206%20—%20Per-Tenant%20Keys%20%26%20Cryptographic%20Erasure.png)

- **Failed Decryption Attempt (Cryptographic Erasure):**  
  ![Task 6 - Decryption Failure](EVIDENCE/Task%206%20—%20Attempt%20to%20unwrap%20tenant%20A's%20data%20key%20now%20—%20it%20should%20FAIL.png)

#### Terminal Error Logs Captured
```text
{
    "KeyId": "6bef6f84-667e-4f4c-8efe-3c0cdb7dc0bc",
    "DeletionDate": "2026-08-28T18:14:03.762829+08:00",
    "KeyState": "PendingDeletion",
    "PendingWindowInDays": 7
}

aws: [ERROR]: An error occurred (KMSInvalidStateException) when calling the DisableKey operation: 
arn:aws:kms:us-east-1:000000000000:key/6bef6f84-667e-4f4c-8efe-3c0cdb7dc0bc is pending deletion.

aws: [ERROR]: An error occurred (NotFoundException) when calling the Decrypt operation: 
Invalid keyId 'NmJlZjZmMDQtNjY3ZS00ZjRjLThlZmUtM2MwY2RiN2RjMGMw'
```

---

### Task 7 — Integrity & Tamper-Evidence

#### Objective
Verify data integrity using SHA-256 cryptographic hashes, demonstrate tamper detection on modified files, and build a hash-chained audit log where each entry incorporates the hash of the preceding entry.

#### Step-by-Step Execution & Commands

```bash
# 1. Compute SHA-256 fingerprint of original file
sha256sum record.txt

# 2. Tamper with a copy and observe hash change
cp record.txt tampered.txt
echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt

# 3. Execute hash chain algorithm over log events
PREV=0
for line in 'login ok' 'file read' 'export data'; do \
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1); \
  echo "$line | $PREV"; \
done
```

#### Terminal Execution & Evidence

![Task 7 - Hashes & Hash Chain](EVIDENCE/Task%207%20—%20Integrity%20%26%20Tamper-Evidence.png)

#### Terminal Output Captured
```text
9345a32351cc1ad03e8b318059b753da6cd4e325688da97a01599b32bc945dd5  record.txt

login ok | 573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053
file read | 6c3adc61ece69412b338e43d761435e9sdbfc948253f8f600087b0a4c5ad2d3d
export data | e1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c503431b32da68
```

---

## Deliverables & Assessment

### 1. Evidence Verification Matrix

| Deliverable Requirement | Screenshot Artifact File | Verified Output / State |
| :--- | :--- | :--- |
| **AES Encrypt / Decrypt Confirmation** | [Task 1 - Symmetric Encryption](EVIDENCE/Task%201%20—%20Symmetric%20Encryption%20(Data%20at%20Rest).png)<br>[Task 1 - Decrypt Back](EVIDENCE/Task%201%20-%20%23%20Decrypt%20back.png) | `MATCH: decryption successful` |
| **RSA Digital Signature Verification** | [Task 2 - Asymmetric Encryption](EVIDENCE/Task%202%20—%20Asymmetric%20Encryption%20%26%20Digital%20Signatures.png) | `Verified OK` |
| **TLS Encrypted Traffic Request** | [Task 3 - Self Signed Cert](EVIDENCE/Task%203%20-%20%23%20Generate%20a%20self-signed%20certificate.png)<br>[Task 3 - TLS](EVIDENCE/Task%203%20—%20Encryption%20in%20Transit%20(TLS).png) | `Patient: Ahmad, Diagnosis: confidential` via HTTPS |
| **KMS Master Keys & Envelope Steps** | [Task 4 - KMS Master Key](EVIDENCE/Task%204%20—%20Create%20and%20Use%20a%20KMS%20Master%20Key.jpeg)<br>[Task 5 - Envelope Encryption](EVIDENCE/Task%205%20—%20Envelope%20Encryption.jpeg) | CMK `6bef6f84-667e-4f4c-8efe-3c0cdb7dc0bc`<br>Plaintext DEK deleted from disk |
| **Failed KMS Decrypt After Erasure** | [Task 6 - Key Deletion](EVIDENCE/Task%206%20—%20Per-Tenant%20Keys%20%26%20Cryptographic%20Erasure.png)<br>[Task 6 - Failed Decrypt](EVIDENCE/Task%206%20—%20Attempt%20to%20unwrap%20tenant%20A's%20data%20key%20now%20—%20it%20should%20FAIL.png) | `aws: [ERROR]: (NotFoundException)` |
| **Differing Hashes & Hash Chain** | [Task 7 - Integrity](EVIDENCE/Task%207%20—%20Integrity%20%26%20Tamper-Evidence.png) | Differing SHA-256 hashes & 3-stage chain computed |

---

### 2. Short-Answer Questions

#### Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.

| Criteria | Symmetric Encryption (e.g., AES-256) | Asymmetric Encryption (e.g., RSA-2048, ECC) |
| :--- | :--- | :--- |
| **Execution Speed** | Extremely fast; optimized via CPU hardware acceleration (AES-NI). Suitable for gigabytes of data. | Mathematically intensive and computationally slow (~1000x slower than symmetric encryption). |
| **Key Distribution** | High complexity. Requires pre-sharing a single secret key securely between parties before communication. | Simple and secure. Public key can be distributed freely; private key stays local and protected. |
| **Typical Use Cases** | Bulk data encryption at rest (S3 bucket encryption, database storage, disk encryption). | Key exchange/establishment, digital signatures, PKI certificates, and TLS handshakes. |

#### Q2. Why is key management described as the weakest link, not the algorithm?
Modern cryptographic algorithms like AES-256 and RSA-2048 are mathematically robust and practically immune to brute-force attacks with current computational capabilities. However, security collapses if **Key Management** fails:
- Hardcoded keys in source repositories, plaintext keys left on local storage, or weak key access control permissions allow attackers to bypass the algorithm entirely.
- If an adversary steals the decryption key, data can be unwrapped instantaneously without needing to break the algorithm. Thus, security resides strictly in key lifecycle management (generation, rotation, access policy, and destruction).

#### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.
- **Envelope Encryption Concept:** Data is encrypted locally using a unique **Data Encryption Key (DEK)**. The DEK itself is encrypted (wrapped) using a **Customer Master Key (CMK)** managed inside a Key Management Service (KMS). The wrapped DEK is stored alongside the encrypted data, while the plaintext DEK is immediately purged from memory.
- **Why Hardware-Grade Protection for CMK Only:** Hardware Security Modules (HSMs) are expensive and throughput-limited. Encrypting large datasets directly inside an HSM creates performance bottlenecks. Envelope encryption offloads bulk data encryption to fast symmetric hardware (using DEKs locally), requiring only the small master key (CMK) to be protected inside high-security, hardware-grade FIPS 140-2/3 validated KMS/HSMs.

#### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?
- **Limitation of Physical Overwriting in Cloud Storage:** In multi-tenant cloud storage (e.g., AWS S3, SAN arrays, block storage), data is stripped, replicated across multiple physical disks, cached in edge locations, and backed up snapshot-wise. Zero-filling or physically overwriting sectors is impossible or unverifiable for tenants due to virtualization and abstraction layers.
- **Provable Cryptographic Erasure:** When data is encrypted with a dedicated per-tenant or per-object key, destroying the corresponding Customer Master Key (CMK) in the KMS renders the ciphertext mathematically indistinguishable from random noise. Without the master key to unwrap the DEK, no entity—including the cloud provider—can decrypt the data, offering instant, provable deletion across all distributed copies.

#### Q5. How does a hash chain make a log tamper-evident (link to tamper-proof logs, Week 6)?
A hash chain links log entries cryptographically by computing each entry's hash as:
$$H_n = \text{SHA256}(H_{n-1} \parallel \text{LogEntry}_n)$$
If an attacker alters an earlier log entry ($\text{LogEntry}_1$), its hash $H_1$ changes. Because $H_2$ depends on $H_1$, the mismatch propagates through all subsequent entries ($H_2, H_3, \dots, H_n$). Any audit verification script comparing calculated hashes against recorded chain states immediately identifies the exact point of tampering, establishing append-only immutability for cloud logging services (e.g., AWS CloudTrail digest files).

---

### 3. Security Best-Practices Checklist

- [x] **Data encrypted at rest (AES) and decryption verified.** (Task 1)
- [x] **Asymmetric keys used correctly (encrypt with public, sign with private).** (Task 2)
- [x] **Data protected in transit with TLS.** (Task 3)
- [x] **Envelope encryption used; plaintext data key not left on disk.** (Task 5)
- [x] **Per-tenant keys used; cryptographic erasure demonstrated.** (Task 6)
- [x] **Integrity verified with hashing / hash chain.** (Task 7)

---

### 4. Verification Commands

The following commands verify the overall environment state and cryptographic signatures:

```bash
# 1. Verify KMS Key inventory in LocalStack
aws --endpoint-url=http://localhost:4566 kms list-keys

# 2. Verify RSA Digital Signature against original document
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

---

### 5. Cleanup & Teardown Instructions

To teardown the local containers and remove transient keys/encrypted artifacts generated during this lab session, run:

```bash
# Stop and remove TLS container
docker stop tls 2>/dev/null

# Clean up ephemeral lab files
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt

# Teardown LocalStack container
docker stop localstack && docker rm localstack
```

---

### 6. Expansion Ideas (Advanced Concepts)
1. **Software HSM (SoftHSM2) Integration:** Configure SoftHSM using PKCS#11 standard interface to model hardware key protection and sign documents directly inside a cryptoki token.
2. **HashiCorp Vault Transit Secrets Engine:** Deploy HashiCorp Vault container to handle encryption-as-a-service, automatic key rotation, and Datakey wrapping for microservices architecture.
3. **Mutual TLS (mTLS):** Enforce bi-directional certificate authentication between client and server containers to prevent unauthorized client connection attempts.
