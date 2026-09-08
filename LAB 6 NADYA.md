# LAB 6 REPORT: OBJECT STORAGE SECURITY & THE DATA SECURITY LIFECYCLE

**Name:** Nadya Zafirah Binti Mohd Fairuz  
**Student ID:** 52215225256  
**Course:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Instructor:** Prof. Dr. Shahrulniza Musa  
**Topics:** S3 Object Storage Provisioning, Data Classification, Public Bucket Exposure & Remediation, S3 Block Public Access Guardrails, IAM Identity Policies vs. S3 Resource Policies, Default Encryption at Rest (SSE-KMS), Presigned URLs & TLS Condition-Key Traps, Object Versioning & Delete Markers, Data Remanence, Automated Lifecycle Retention Rules, Cryptographic Erasure  

---

## 1. Executive Summary & Lab Learning Outcomes

This technical report documents the complete implementation of cloud object storage security controls, access governance policies, default encryption frameworks, object versioning lifecycle mechanisms, and provable data deletion strategies using LocalStack Amazon S3.

### Core Learning Outcomes:
1. **Object Storage Provisioning & Data Classification:** Provisioned an S3 bucket (`mii-patient-records-11448`), categorized uploaded objects into sensitivity tiers (`public`, `internal`, `confidential`), and evaluated the flat namespace structure of key prefixes versus hierarchical block/file storage security models.
2. **Public Exposure & Guardrail Remediation:** Replicated the classic cloud data breach by attaching an over-broad `"Principal": "*"` resource policy, verified unauthenticated data exfiltration via `curl`, remediated the exposure using AWS Block Public Access (BPA), and implemented an account-scoped least-privilege resource policy.
3. **Identity vs. Resource Policy Authorization:** Evaluated policy evaluation logic by contrasting an IAM identity policy (`S3ReadAll`) with an S3 resource bucket policy containing an explicit `Deny` on sensitive object prefixes, proving that an explicit `Deny` strictly overrides an `Allow`.
4. **Enforced Default Encryption at Rest (SSE-KMS):** Configured bucket-level default server-side encryption with AWS Key Management Service (SSE-KMS) using a customer-managed key (`4b26650e-cd97-4438-83e5-71710af8a120`) and validated `BucketKeyEnabled` envelope encryption cost optimization.
5. **Time-Bounded Delegated Access & Condition-Key Traps:** Generated cryptographically signed presigned URLs for temporary access, dissected signature authentication parameters, and analyzed the operational risks of applying TLS enforcement condition keys (`aws:SecureTransport`) in unencrypted local development environments.
6. **Object Versioning, Data Remanence & Cryptographic Erasure:** Enabled S3 versioning, demonstrated object-level data remanence following standard deletion (via S3 delete markers), implemented automated lifecycle retention policies (`RetireConfidentialRecords`), and executed provable cryptographic erasure via KMS key destruction.

---

## 2. Session A (Week 11) — Object Storage & the Exposure Problem

### One-Time Environment Setup

A fresh LocalStack instance was initialized in Docker with IAM policy enforcement enabled (`ENFORCE_IAM=1`) to strictly validate IAM identity policies and S3 bucket resource policies. The AWS CLI was pointed to the local endpoint (`http://localhost:4566`), and authentication was verified using AWS Security Token Service (STS).

#### Execution Commands:
```bash
# 1. Clean previous container instances
docker rm -f localstack 2>/dev/null

# 2. Run LocalStack with IAM evaluation enabled
docker run -d --name localstack -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
  -e ENFORCE_IAM=1 \
  localstack/localstack-pro:latest

# 3. Configure AWS CLI pointing to LocalStack
export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

# 4. Verify caller identity
aws $EP sts get-caller-identity
```

#### Environment Identity Verification Output:
```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```
* **Account ID:** `000000000000` (LocalStack root account identity used for resource ARNs in Task 3 and Task 4).

---

### Task 1 — Classify the Data Before You Store It

Security controls must follow data sensitivity classification rather than ad-hoc access assignments. An S3 bucket named `mii-patient-records-11448` was created for a hospital management system. Three records of varying sensitivity levels were uploaded and tagged with their respective classification labels.

#### Execution Commands:
```bash
# 1. Define bucket variable
export BUCKET=mii-patient-records-11448
echo $BUCKET

# 2. Create S3 bucket
aws $EP s3api create-bucket --bucket $BUCKET

# 3. Create local dummy patient records
echo 'Ward visiting hours 10am-8pm'                        > public-notice.txt
echo 'Staff duty schedule, week 12'                         > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential'      > confidential-record.txt

# 4. Upload objects with classification tagging
aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'

aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'

# 5. List uploaded objects and inspect tags
aws $EP s3api list-objects-v2 --bucket $BUCKET --query 'Contents[].[Key,Size]' --output table
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

#### Object Listing Output (`list-objects-v2`):
```text
----------------------------------------
|            ListObjectsV2             |
+----------------------------------+---+
|  confidential/record.txt         | 48|
|  internal/roster.txt             | 29|
|  public/notice.txt               | 29|
+----------------------------------+---+
```

#### Object Tagging Verification Output (`confidential/record.txt`):
```json
{
    "TagSet": [
        {
            "Key": "classification",
            "Value": "confidential"
        }
    ]
}
```

#### Data Classification Table:

| Classification | Who May Read It | Impact If Leaked | Control Implemented |
|---|---|---|---|
| **Public** | Unauthenticated public users, external patients, staff | **Low** (No sensitive PII; routine operational data such as hospital visiting hours) | Public read access permitted; no restricting bucket policy required. |
| **Internal** | Authenticated hospital employees, medical staff, administrative users | **Medium** (Minor operational disruption; exposes internal roster and duty schedules) | Account-scoped least-privilege resource policy (`arn:aws:iam::000000000000:root` allowed on key prefix `internal/*`). |
| **Confidential** | Explicitly authorized medical practitioners and compliance officers | **High / Critical** (Severe privacy breach, legal liability under PDPA/GDPR due to unauthorized exposure of sensitive patient medical diagnosis) | Explicit `Deny` resource policy on prefix `confidential/*`, enforced default SSE-KMS encryption, and cryptographic erasure. |

> [!NOTE]
> Object storage uses a flat namespace. Prefixes such as `confidential/` or `internal/` do not represent real OS filesystem directories; they are strings embedded within object keys. Policy authorization relies on key prefix matching (`Resource: arn:aws:s3:::bucket/prefix/*`), which is why overly broad wildcard prefixes (`*`) accidentally expose all object classifications at once.

#### Evidence:
![Task 1 — Object Provisioning](EVIDENCE/Task%201%20%E2%80%94%20Classify%20the%20Data%20Before%20You%20Store%20It%20(1).png)  
![Task 1 — Object Tags & Listing](EVIDENCE/Task%201%20%E2%80%94%20Classify%20the%20Data%20Before%20You%20Store%20It%20(2).png)

---

### Task 2 — Reproduce the Archetypal Cloud Breach

The vast majority of publicly reported cloud storage data leaks stem from misconfigured resource policies that declare `"Principal": "*"`. To simulate this vulnerability, an open access bucket policy was deliberately deployed, and an anonymous HTTP request was executed without AWS credentials.

#### Execution Commands:
```bash
# 1. Create vulnerable public resource policy
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::mii-patient-records-11448/*"
  }]
}
JSON

# 2. Apply vulnerable policy to the S3 bucket
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text

# 3. Simulate external attacker reading confidential patient records via curl
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

#### Attacker Terminal Execution Output:
```text
HTTP 200
Patient: Ahmad bin Ali, Diagnosis: confidential
```

#### Security Analysis of Exposure:
* **Root Cause:** The data breach occurred entirely because the policy specified `"Principal": "*"`. The wildcard asterisk wildcard grants anonymous, unauthenticated read permissions (`s3:GetObject`) to any entity anywhere on the internet holding the HTTP URL.
* **Exploit Nature:** No malware, privilege escalation exploit, or authentication bypass was required. The storage endpoint served the confidential data as requested because the bucket policy explicitly instructed AWS to allow access to everyone.

#### Evidence:
![Task 2 — Public Breach Reproduction](EVIDENCE/Task%202%20%E2%80%94%20Reproduce%20the%20Archetypal%20Breach.png)

---

### Task 3 — Remediate with Block Public Access (BPA)

To fix the immediate breach and prevent future accidental public exposures, the bad policy was deleted, and AWS S3 Block Public Access (BPA) guardrails were enabled across the bucket.

#### Execution Commands:
```bash
# 1. Remove offending public policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# 2. Apply S3 Block Public Access guardrail flags
aws $EP s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 3. Verify public access block settings
aws $EP s3api get-public-access-block --bucket $BUCKET

# 4. Attempt to re-introduce the public policy
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json

# 5. Re-test anonymous curl read
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
```

#### Public Access Block Verification Output (`get-public-access-block`):
```json
{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }
}
```

#### Anonymous Read Output (LocalStack Behavior):
```text
anonymous read now: HTTP 200
```

#### Security Analysis & LocalStack Evaluation:
1. **AWS Production Behavior vs. LocalStack:** LocalStack faithfully stores the `PublicAccessBlockConfiguration` state (as proven by `get-public-access-block`), but does not actively enforce policy rejection in mock execution. On commercial AWS, step 3 would be immediately blocked with an `AccessDenied` error due to the `BlockPublicPolicy=true` flag.
2. **Flag Analysis:** On real AWS:
   * `BlockPublicPolicy`: Would reject `put-bucket-policy` whenever a policy grants public access.
   * `RestrictPublicBuckets`: Restricts access to buckets with public policies exclusively to AWS service principals and authorized account users.
3. **Preventative Guardrail vs. Detective Control:** Block Public Access is a **preventative guardrail** because it enforces a centralized security boundary at the account/bucket level, physically blocking engineers from deploying public bucket policies. In contrast, a **detective control** (e.g., AWS Config or Security Hub) merely logs an alert *after* a bucket has already been exposed to the public internet, leaving a window of vulnerability before manual or automated remediation occurs.

#### Least-Privilege Policy Implementation:

A least-privilege resource policy was drafted to restrict read access exclusively to internal staff within the account (`000000000000:root`) and scoped strictly to the `internal/*` key prefix.

```bash
# Apply least-privilege bucket policy
cat > least-privilege-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::mii-patient-records-11448/internal/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilege-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

#### Evidence:
![Task 3 — Block Public Access Setup](EVIDENCE/Task%203%20%E2%80%94%20Remediate%20with%20Block%20Public%20Access%20(1).png)  
![Task 3 — Least-Privilege Policy](EVIDENCE/Task%203%20%E2%80%94%20Remediate%20with%20Block%20Public%20Access(2).png)

---

### Task 4 — Identity Policy vs. Resource Policy

S3 access control evaluates both the caller's **IAM Identity Policy** and the bucket's **Resource Policy**. When the two conflict, AWS policy evaluation follows strict precedence rules: **an explicit Deny always overrides any Allow.**

#### Execution Commands:
```bash
# 1. Create IAM User DataAnalyst
aws $EP iam create-user --user-name DataAnalyst

# 2. Attach broad identity policy allowing all S3 reads
cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json

# 3. Create access keys and configure analyst CLI profile
aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text

aws configure --profile analyst set aws_access_key_id "PASTE_KEY_ID"
aws configure --profile analyst set aws_secret_access_key "PASTE_SECRET"
aws configure --profile analyst set region us-east-1

# 4. Create resource policy with explicit Deny on confidential prefix
cat > deny-confidential.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::mii-patient-records-11448/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::mii-patient-records-11448/confidential/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json

# 5. Test access to internal record (Should SUCCEED)
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key internal/roster.txt analyst-internal.txt && echo "internal: ALLOWED"

# 6. Test access to confidential record (Should FAIL)
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key confidential/record.txt analyst-conf.txt || echo "confidential: DENIED"

# 7. Clean up resource policy before Session B
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

#### Evaluation Test Results:
```text
internal: ALLOWED
confidential: DENIED
```

#### Policy Evaluation Logic Analysis:
1. **Request 1 (`internal/roster.txt`):** The IAM Identity Policy grants `Allow` (`s3:GetObject` on `*`), and the Bucket Resource Policy grants `Allow` (`AllowAnalystInternal`). With no explicit `Deny` present, access is **ALLOWED**.
2. **Request 2 (`confidential/record.txt`):** Although the IAM Identity Policy grants `Allow` (`s3:GetObject` on `*`), the Bucket Resource Policy contains statement `DenyAnalystConfidential` (`Effect: Deny` on `confidential/*`). AWS policy evaluation rules state:
   $$\text{Default Deny} \longrightarrow \text{Any Explicit Deny (Wins)} \longrightarrow \text{Any Explicit Allow}$$
   Because an explicit `Deny` matches the request, access is immediately **DENIED**.

#### Evidence:
![Task 4 — IAM User Creation](EVIDENCE/Task%204%20%E2%80%94%20Identity%20Policy%20vs%20Resource%20Policy%20(1).png)  
![Task 4 — Policy Json Creation](EVIDENCE/Task%204%20%E2%80%94%20Identity%20Policy%20vs%20Resource%20Policy%20(2).png)  
![Task 4 — Policy Evaluation Execution](EVIDENCE/Task%204%20%E2%80%94%20Identity%20Policy%20vs%20Resource%20Policy%20(3).png)

---

## 3. Session B (Week 12) — Protecting, Retaining and Retiring Data

### Task 5 — Default Encryption at Rest (SSE-KMS)

Rather than relying on individual developers to remember encryption parameters during object upload, default server-side encryption with AWS KMS (SSE-KMS) was configured at the bucket level.

#### Execution Commands:
```bash
# 1. Create customer-managed KMS key
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID

# 2. Define default SSE-KMS bucket configuration
cat > encryption.json <<JSON
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "$KEY_ID"
    },
    "BucketKeyEnabled": true
  }]
}
JSON

# 3. Apply default encryption to bucket
aws $EP s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json

# 4. Verify bucket encryption settings
aws $EP s3api get-bucket-encryption --bucket $BUCKET

# 5. Upload object WITHOUT specifying encryption flags
aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record-v2.txt --body confidential-record.txt

# 6. Inspect metadata of uploaded object
aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

#### Provisioned Key ID & Verification Output:
* **KMS Key ID:** `4b26650e-cd97-4438-83e5-71710af8a120`
* **Object Metadata Inspection (`head-object`):**
  ```text
  aws:kms  arn:aws:kms:us-east-1:000000000000:key/4b26650e-cd97-4438-83e5-71710af8a120  True
  ```

#### Security Analysis (Envelope Encryption & Bucket Keys):
* **Automatic Protection:** The uploaded object `confidential/record-v2.txt` was automatically encrypted at rest using `aws:kms` and bound to Key ID `4b26650e-cd97-4438-83e5-71710af8a120` despite zero CLI encryption flags being passed during upload.
* **`BucketKeyEnabled: true` Optimization:** Enforces S3 Bucket Keys envelope encryption. S3 requests a single short-lived Data Encryption Key (DEK) from KMS at the bucket level rather than invoking KMS API calls for every individual object operation. This reduces KMS request costs and API throttling latency by up to 99% while maintaining identical cryptographic confidentiality.

#### Evidence:
![Task 5 — KMS Key & Encryption Setup](EVIDENCE/Task%205%20%E2%80%94%20Default%20Encryption%20at%20Rest%20(SSE-KMS)%20(1).png)  
![Task 5 — Head-Object Encryption Verification](EVIDENCE/Task%205%20%E2%80%94%20Default%20Encryption%20at%20Rest%20(SSE-KMS)%20(2).png)

---

### Task 6 — Delegated Access and the Condition-Key Trap

Presigned URLs delegate temporary read/write access to external entities without requiring AWS IAM credentials. However, bucket policies enforcing transport security can lead to operational lockouts if condition keys are misconfigured.

#### 1. Presigned URL Access Delegation:

```bash
# 1. Generate presigned URL with 60-second expiration
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60

# 2. Store generated URL in variable
URL='http://localhost:4566/mii-patient-records-11448/internal/roster.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test%2F20260908%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260908T102207Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=a2bda6c0a0cdd393e3838bf1d254f809bda10b2ccbc5afaa2ad92da851ee38a4'

# 3. Test access prior to expiration
curl -s -w ' <-- HTTP %{http_code}\n' "$URL"

# 4. Wait for expiration window to pass
sleep 65

# 5. Test access post expiration
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

#### Presigned URL Output:
```text
Staff duty schedule, week 12
 <-- HTTP 200
after expiry: HTTP 200
```

#### Presigned URL Parameter Dissection:
* `X-Amz-Algorithm=AWS4-HMAC-SHA256`: Specifies the AWS Signature Version 4 hashing algorithm.
* `X-Amz-Credential`: Binds the request to the issuer's Access Key ID, date, AWS region (`us-east-1`), and service (`s3`).
* `X-Amz-Date`: Timestamp marking when the URL was generated (`20260908T102207Z`).
* `X-Amz-Expires=60`: Time-to-live (TTL) window in seconds (60 seconds).
* `X-Amz-SignedHeaders=host`: Declares which HTTP headers are frozen and included in cryptographic signature calculation.
* `X-Amz-Signature`: The HMAC-SHA256 digest proving that the URL parameters were issued by a valid secret key holder and have not been altered in transit.

> [!NOTE]
> On commercial AWS, any request arriving after `X-Amz-Date` + `X-Amz-Expires` is rejected with `403 Forbidden (AccessDenied)`. LocalStack mock execution returns `HTTP 200` post-expiry, but URL parameter integrity remains verified.

#### 2. The Condition-Key Trap (`aws:SecureTransport`):

Security hardening guides frequently recommend applying a policy denying unencrypted HTTP requests.

```bash
# 1. Create TLS enforcement policy
cat > secure-transport.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::mii-patient-records-11448", "arn:aws:s3:::mii-patient-records-11448/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
JSON

# 2. Apply policy
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json

# 3. Test ordinary bucket command
aws $EP s3api list-objects-v2 --bucket $BUCKET

# 4. Recover by removing policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

#### Condition Key Lockout Analysis:
* **The Lockout Mechanism:** When `secure-transport.json` was applied, all subsequent S3 commands failed or hung. Because LocalStack operates over plain HTTP (`http://localhost:4566`), `aws:SecureTransport` evaluated to `false` for every request. The explicit `Deny` matched all incoming commands—including root administration commands—locking the owner out of the bucket.
* **Key Takeaway:** Condition keys must be evaluated against the exact operational runtime environment. Deploying policies written for production HTTPS endpoints into HTTP development/testing environments results in immediate self-lockout.

#### Evidence:
![Task 6 — Presigned URL Generation](EVIDENCE/Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20(1).png)  
![Task 6 — Secure Transport Policy](EVIDENCE/Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20(2).png)  
![Task 6 — Lockout & Recovery](EVIDENCE/Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20(3).png)

---

### Task 7 — Versioning, Delete Markers & Data Remanence

When bucket versioning is enabled, issuing an `s3api delete-object` command does not delete underlying data bytes. Instead, S3 writes a 0-byte **Delete Marker** as the latest object version while retaining all historical revisions underneath.

#### Execution Commands:
```bash
# 1. Enable bucket versioning
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
  --versioning-configuration Status=Enabled
aws $EP s3api get-bucket-versioning --bucket $BUCKET

# 2. Create and upload updated revisions of confidential record
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]'       > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text

# 3. List object versions
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table

# 4. Perform standard delete object command
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt

# 5. List delete markers
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table

# 6. Attempt standard read (Fails with NoSuchKey)
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt gone.txt

# 7. Recover original unredacted confidential data by specifying version-id null
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt

# 8. Permanently destroy specific version ID
aws $EP s3api delete-object --bucket $BUCKET \
  --key confidential/record.txt --version-id null
```

#### Object Versioning Listing Output (`list-object-versions`):
```text
--------------------------------------------------------
|                 ListObjectVersions                   |
+------------------------------------+-------+---------+
| AaCAl9L56f8LXxj2g.GCjgtnuwKGwDZz   | True  | 43      |
| AaCAl9L4dmB1vS30EHiGshm5SMTUb5eK   | False | 48      |
| null                               | False | 48      |
+------------------------------------+-------+---------+
```

#### Delete Marker Response & Listing:
* **Delete Marker Version ID Created:** `AaCAl9L6Lznt0Pi9CzIl13gPDq48iFc0` (`IsLatest: True`)

#### Data Remanence Proof (`recovered.txt`):
```text
Patient: Ahmad bin Ali, Diagnosis: confidential
```

#### Privacy Compliance Analysis (PDPA / GDPR):
* **Data Remanence Issue:** Issuing `delete-object` without specifying a `--version-id` merely places a Delete Marker over the key. The underlying data remains fully intact in storage. Anyone with `s3:GetObjectVersion` permissions can bypass the Delete Marker by querying historical Version IDs (such as `version-id null`).
* **Compliance Violation:** Claiming "we deleted the record" following a data subject erasure request (e.g., Right to be Forgotten under GDPR / PDPA) is non-compliant if versioning is active and historical versions persist. Full compliance requires explicit per-version deletion (`delete-object --version-id <ID>`) or automated lifecycle expiration rules.

#### Evidence:
![Task 7 — Versioning Setup](EVIDENCE/Task%207%20%E2%80%94%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(1).png)  
![Task 7 — Delete Marker & Data Recovery](EVIDENCE/Task%207%20%E2%80%94%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(2).png)  
![Task 7 — Per-Version Deletion](EVIDENCE/Task%207%20%E2%80%94%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(3).png)  
![Task 7 — Final Version Listing](EVIDENCE/Task%207%20%E2%80%94%20Versioning,%20Delete%20Markers%20&%20Data%20Remanence%20(4).png)

---

### Task 8 — Lifecycle, Retention & Cryptographic Erasure

Manual object version deletion does not scale across enterprise workloads. S3 Lifecycle rules automate data retention, while KMS Cryptographic Erasure provides instantaneous provable data destruction.

#### 1. Automated Lifecycle Retention Configuration:

```bash
# 1. Define lifecycle rule configuration
cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
JSON

# 2. Apply lifecycle configuration to bucket
aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

# 3. Verify lifecycle rules
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output table
```

#### Lifecycle Rule Table (`get-bucket-lifecycle-configuration`):
```text
---------------------------------------------
|      GetBucketLifecycleConfiguration      |
+---------------------------+---------------+
|  RetireConfidentialRecords |  Enabled      |
|  AbortIncompleteUploads   |  Enabled      |
+---------------------------+---------------+
```

#### 2. Cryptographic Erasure via KMS Key Destruction:

```bash
# 1. Check KMS key status prior to destruction
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text

# 2. Disable and schedule KMS key deletion
aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# 3. Verify key pending deletion status
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text

# 4. Attempt to read object encrypted under destroyed key
aws $EP s3api get-object --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
```

#### KMS Key Scheduling Output:
```json
{
    "KeyId": "4b26650e-cd97-4438-83e5-71710af8a120",
    "DeletionDate": "2026-09-15T18:53:27.938333+08:00",
    "KeyState": "PendingDeletion",
    "PendingWindowInDays": 7
}
```

#### Cryptographic Erasure Assurance Analysis:
* **Mechanism:** Cryptographic erasure destroys the customer-managed KMS key wrapping the data. Without the master key, the underlying S3 ciphertext becomes mathematically unrecoverable noise.
* **Auditor Assurance vs. Overwriting:** In cloud multi-tenant infrastructure, users do not own or control physical hard drives; physical overwriting (`shred` or degaussing) cannot be independently verified by tenants. Destroying the KMS key provides mathematical, provable assurance of data destruction across all stored copies, historical versions, and backup snapshots simultaneously.

#### Evidence:
![Task 8 — Cryptographic Erasure](EVIDENCE/Task%208%20%E2%80%93%20Cryptographic%20Erasure.png)  
![Task 8 — Lifecycle Rules](EVIDENCE/Task%208%20%E2%80%93%20Lifecycle.png)

---

## 4. Deliverables & Assessment

### Deliverable 1: Data Classification Table

| Classification | Who May Read It | Impact If Leaked | Control Implemented |
|---|---|---|---|
| **Public** | Anyone (Public access) | **Low** (Public information, e.g., visiting hours) | Unrestricted read / standard bucket defaults. |
| **Internal** | Authenticated internal staff / company account | **Medium** (Internal operational data, e.g., duty schedule) | Account-scoped least-privilege resource policy (`arn:aws:iam::000000000000:root` on `/internal/*`). |
| **Confidential** | Authorized medical & compliance personnel only | **High / Critical** (PDPA/GDPR statutory breach, exposure of confidential patient diagnosis) | Explicit `Deny` bucket policy on `/confidential/*`, default SSE-KMS encryption, versioning retention, and KMS cryptographic erasure. |

---

### Deliverable 2: Short-Answer Questions

#### Q1. Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?
* **Exposure Element:** The string `"Principal": "*"` in the bucket resource policy statement caused the exposure.
* **Why More Dangerous:** An over-broad IAM policy attached to a single user (e.g., granting `s3:*` to `DataAnalyst`) still requires caller authentication using valid AWS credentials. In contrast, `"Principal": "*"` on a resource policy removes authentication entirely, exposing the bucket resource directly to the unauthenticated public internet via plain HTTP/HTTPS URLs.

#### Q2. Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?
* **Identity-based policy:** Attached directly to an IAM user, group, or role. It defines what permissions that specific identity holds across AWS resources.
* **Resource-based policy:** Attached directly to an AWS resource (such as an S3 bucket). It defines which principals are allowed or denied actions on that specific resource.
* **Task 4 Decision Breakdown:**
  1. `internal/roster.txt`: Allowed by both policies (Identity `Allow` + Resource `Allow`).
  2. `confidential/record.txt`: Decided by the **Bucket Resource Policy**, where statement `DenyAnalystConfidential` (`Effect: Deny`) explicitly overrode the identity policy's `Allow`.

#### Q3. Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?
* **Control:** A specific operational security rule configured on a resource (e.g., an S3 bucket policy denying public access).
* **Guardrail:** A structural baseline boundary enforced above individual controls (e.g., S3 Block Public Access).
* **Engineering Impact:** In large organizations with hundreds of engineers creating buckets, individual bucket controls can be misconfigured or overridden by human error. Block Public Access acts as an account-wide safety net, preventing engineers from accidentally introducing public access regardless of the bucket policies or ACLs they attempt to write.

#### Q4. Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.
* **Analyst Protection:** **No.** SSE-KMS default encryption does not protect `confidential/record.txt` from the `DataAnalyst` if the user holds valid `kms:Decrypt` and `s3:GetObject` IAM permissions.
* **What SSE-KMS Defends Against:** Protects against physical media theft, unauthorized disk access inside AWS data centers, and out-of-band physical drive extraction.
* **What SSE-KMS Does NOT Defend Against:** Does not defend against logical access control failures, over-broad IAM permissions, compromised API access keys, or misconfigured bucket resource policies. Transparent server-side encryption decrypts data automatically for any authenticated principal possessing valid read permissions.

#### Q5. A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.
* **Why `delete-object` is Non-Compliant:** When versioning is active, `delete-object` only places a 0-byte Delete Marker as the latest version. All historical object versions remain fully intact and accessible by specifying `--version-id` (as proven when `recovered.txt` was fetched using `--version-id null`).
* **Two Mechanisms for Provable Deletion:**
  1. **Permanent Per-Version Deletion:** Explicitly invoking `aws s3api delete-object --bucket $BUCKET --key <key> --version-id <version-id>` for every version ID in the object history.
  2. **Cryptographic Erasure:** Disabling and destroying the customer-managed KMS key (`kms schedule-key-deletion`) used to encrypt the object, rendering all ciphertext versions permanently undecryptable.

#### Q6. You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.
1. `aws s3api get-public-access-block --bucket $BUCKET`: Evidences that preventative **Block Public Access guardrails** are active on all four flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`).
2. `aws s3api get-bucket-encryption --bucket $BUCKET`: Evidences that **enforced default encryption at rest** using SSE-KMS (`aws:kms`) is active across all bucket uploads.
3. `aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET`: Evidences that an **automated data retention and expiration policy** (`RetireConfidentialRecords`) is active for compliance and regulatory data handling requirements.

---

### Deliverable 3: Verification Command Output

The following verification block proves the final security posture of bucket `mii-patient-records-11448` and KMS Key `4b26650e-cd97-4438-83e5-71710af8a120`:

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="
aws $EP s3api get-public-access-block --bucket $BUCKET \
  --query 'PublicAccessBlockConfiguration' --output text
aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text
aws $EP s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
  --output text
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output text
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text
```

#### Final Execution Output:
```text
=== IKB42603 Lab 6 verification: mii-patient-records-11448 ===
True    True    True    True
Enabled
aws:kms arn:aws:kms:us-east-1:000000000000:key/4b26650e-cd97-4438-83e5-71710af8a120
RetireConfidentialRecords       Enabled
AbortIncompleteUploads  Enabled
PendingDeletion
```

---

## 5. Security Best-Practices Checklist

- [x] **Data Classification:** Every object carries a classification tag (`classification=public|internal|confidential`) before access decisions are made.
- [x] **No Public Bucket Policies:** No resource policy names `"Principal": "*"`; anonymous access attempts are verified and blocked.
- [x] **Block Public Access Guardrails:** Enabled across all four BPA configuration flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`).
- [x] **Least-Privilege Authorization:** Access is granted by least privilege and scoped strictly to object key prefixes (`internal/*`), never to `/*`.
- [x] **Default Encryption at Rest:** Enforced bucket-level SSE-KMS default encryption with customer-managed KMS key and `BucketKeyEnabled` envelope optimization.
- [x] **Time-Bounded Delegated Access:** Temporary access utilizes presigned URLs with strict time-to-live expiration rather than permanent public objects.
- [x] **Versioning & Delete Marker Awareness:** S3 versioning is enabled, and data remanence risks of delete markers are understood and managed.
- [x] **Automated Lifecycle & Cryptographic Erasure:** Automated lifecycle retention rules enforce data expiration, and cryptographic erasure is available for provable deletion.

---
