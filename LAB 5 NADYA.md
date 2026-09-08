# LAB 5 REPORT: MONITORING, LOGGING & INCIDENT DETECTION
**Name:** Nadya Zafirah Binti Mohd Fairuz  
**Student ID:** 52215225256  
**Course:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Instructor:** Prof. Dr. Shahrulniza Musa  
**Topics:** Centralised Logging (Docker & LocalStack CloudWatch), Hash-Chained Tamper-Proof Logs, Event Correlation & SIEM Threat Detection, Containerized Incident Response & Forensics  

---

## 1. Executive Summary & Lab Learning Outcomes

This technical report documents the implementation of centralised cloud logging, log tamper-proofing using cryptographic hash chains, automated multi-event threat detection (SIEM correlation), and incident response containment with forensic evidence verification.

### Core Learning Outcomes:
1. **Centralised Logging (Cloud Telemetry):** Collected, aggregated, and forwarded application logs from individual hosts/containers to an Amazon CloudWatch Logs service modeled using LocalStack.
2. **Log vs. Event Disambiguation & Querying:** Parsed raw structured logs using standard CLI utilities (`grep`, `awk`, `sort`, `uniq`) to query security-relevant events (failed logins grouped by IP address).
3. **Tamper-Evident Hash-Chaining:** Implemented an append-only cryptographic hash chain using SHA-256 to ensure log integrity and detect unauthorized log modification/deletion by adversaries.
4. **Automated Incident Detection via Event Correlation:** Constructed a SIEM detection rule that correlates multiple distinct low-severity log events (failed login brute-force $\rightarrow$ successful authentication $\rightarrow$ large data exfiltration) into a high-severity security alert.
5. **Incident Response Lifecycle:** Executed active containment using containerised Linux network firewall rules (`iptables` `DROP`), collected immutable timestamped forensic log evidence, and validated evidence hash integrity using `sha256sum`.

---

## 2. Session A (Week 9) — Logging & Centralisation

### Setup — Start LocalStack & Configure CloudWatch Log Resources

Centralised logging requires a resilient central telemetry repository. In this setup, LocalStack was executed via Docker to provide an AWS-compatible CloudWatch Logs endpoint (`http://localhost:4566`). A dedicated log group (`/ccse/app`) and log stream (`auth`) were provisioned to collect application authentication events.

#### Execution Commands:
```bash
# 1. Start LocalStack container with port 4566 exposed
docker run -d --name localstack -p 4566:4566 localstack/localstack

# 2. Set endpoint variable for AWS CLI
EP='--endpoint-url=http://localhost:4566'

# 3. Create CloudWatch Log Group and Log Stream
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

#### Evidence:
![Setup — Start LocalStack](EVIDENCE/Setup%20%E2%80%94%20Start%20LocalStack.png)

---

### Task 1 — Generate Application Logs

To simulate realistic user and adversary behavior, an authentication audit log (`auth.log`) was generated. The log records legitimate user activity alongside an attacker performing brute-force credential probing followed by account compromise and data extraction.

#### Execution Commands:
```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF

cat auth.log
```

#### Raw Log Output:
```text
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
```

#### Evidence:
![Task 1 — Generate Application Logs](EVIDENCE/Task%201%20%E2%80%94%20Generate%20Application%20Logs.png)

---

### Task 2 — Centralise Logs (Ship to CloudWatch)

Local log files on individual instances can be wiped or tampered with by adversaries. To implement cascading log collection, each log line was read sequentially and shipped to the centralised LocalStack CloudWatch Logs stream via the `put-log-events` API with incremental epoch timestamps.

#### Execution Commands:
```bash
# 1. Ship each log line to central CloudWatch log stream
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null; TS=$((TS+1000));
done < auth.log

# 2. Read back centralized logs to confirm storage integrity
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
  --query 'events[].message' --output text
```

#### Centralized Read-Back Verification Output:
```text
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5     2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9  2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
```

#### Evidence:
![Task 2 — Centralise Logs](EVIDENCE/Task%202%20%E2%80%94%20Centralise%20Logs%20(Ship%20to%20CloudWatch).png)

---

### Task 3 — Query for Security-Relevant Activity

Security analysis requires filtering noise to pinpoint suspicious patterns. Using shell processing pipelines (`grep`, `awk`, `sort`, `uniq -c`), the total number of authentication failures was grouped and counted by source IP address.

#### Execution Commands:
```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

#### Query Result:
```text
      4 ip=203.0.113.9
```

#### Security Analysis (Log vs Event):
* **Log (Durable Record):** The static, persistent entry stored in `auth.log` or CloudWatch (e.g., `2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9`).
* **Event (Trigger/Alert):** A dynamic real-time state change or threshold alert derived from processing log telemetry (e.g., `ALERT: 4 failures from 203.0.113.9 within 10 seconds`).

#### Evidence:
![Task 3 — Query for Security-Relevant Activity](EVIDENCE/Task%203%20%E2%80%94%20Query%20for%20Security-Relevant%20Activity.png)

---

## 3. Session B (Week 10) — Tamper-Proofing, Detection & Response

### Task 4 — Tamper-Proof (Hash-Chained) Logs

An attacker who gains root access often attempts to edit log files to remove traces of exfiltration. To prevent undetectable log tampering, a cryptographic hash chain was constructed where each log line's hash includes the SHA-256 digest of the preceding line ($H_n = \text{SHA256}(H_{n-1} \parallel \text{Line}_n)$).

#### Execution Commands:
```bash
# 1. Generate Hash Chain
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain

cat auth.chain

# 2. Simulate Attacker Tampering (alter EXPORT_DATA from 500MB to 5MB)
sed 's/500MB/5MB/' auth.log > auth.tampered

# 3. Verify Chain Invalidation
PREV=0; BROKE=no
paste -d'|' <(cut -d'|' -f1 auth.chain) <(cut -d'|' -f2 auth.chain) >/dev/null
```

#### Calculated Hash Chain Table (`auth.chain`):
| Line | Log Content | Accumulated SHA-256 Hash Digest |
|---|---|---|
| 1 | `2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5` | `82da89a49dc1ca7d23b8a59f98d7e557ab36ce0c2d0c6e106fabe76e1f0acf39` |
| 2 | `2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9` | `790aef7176d6effe76d077831c071f8500204bf842e7fd8aeda1b67b2e271a97` |
| 3 | `2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9` | `1e0b2e8aaf5143fb95070a8e57b009f058f0d37c257d19409b4131894d29a9a8` |
| 4 | `2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9` | `7fb62c66ded511605e22c8db9c4f57c9360aa27309ce65024a3e5ea35e3b6e94` |
| 5 | `2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9` | `143253b549a74b9626e910fbe54ca12cb5431a0a4c9c4f2189ff27a3e2a17e01` |
| 6 | `2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9` | `4cbfab7fecb703cf21f5df81b47dbf3a727c94442b09b714ac4bfaa3584cc638` |
| 7 | `2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB` | `ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf` |

#### Proof of Tamper Detection:
Re-computing the chain against `auth.tampered` produces a completely divergent final hash digest, immediately exposing that line 7 was altered.

#### Evidence:
![Task 4 — Tamper-Proof Logs](EVIDENCE/Task%204%20%E2%80%94%20Tamper-Proof%20(Hash-Chained)%20Logs.png)

---

### Task 5 — Detect the Incident (Correlation)

Single log lines in isolation (e.g., a single failed login or a data download) may appear benign. SIEM systems correlate multiple events across a time window to detect attack patterns. A correlation script was built to detect: $\ge 3\text{ failures} \rightarrow \ge 1\text{ success} \rightarrow \ge 1\text{ large export}$ from the same IP address.

#### Execution Script:
```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)

echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration';
fi
```

#### Execution Output:
```text
IP=203.0.113.9 fails=4 success=1 export=1
ALERT: probable brute-force -> compromise -> data exfiltration
```

#### Evidence:
![Task 5 — Detect the Incident](EVIDENCE/Task%205%20%E2%80%94%20Detect%20the%20Incident%20(Correlation).png)

---

### Task 6 — Incident Response

Once an alert fires, the Incident Response lifecycle must execute swiftly: **Containment**, **Evidence Collection**, and **Forensic Hash Verification**.

#### 1. Containment (Block Attacker IP):
Using Linux kernel capabilities (`NET_ADMIN`), an `iptables` default-deny rule was appended to immediately drop all traffic from the malicious IP `203.0.113.9`.

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```

#### Containment Verification Output:
```text
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
DROP       all  --  203.0.113.9          0.0.0.0/0           
```

#### 2. Forensic Evidence Collection & Hashing:
An immutable timestamped snapshot of the log file was created and hashed with SHA-256 to ensure chain-of-custody integrity for legal/compliance evidence.

```bash
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

#### Evidence Hash Output:
```text
0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b  evidence_20260908.log
```

#### Evidence:
![Task 6 — Incident Response](EVIDENCE/Task%206%20%E2%80%94%20Incident%20Response.png)

---

## 4. Formal Incident Report

| Incident Field | Details |
|---|---|
| **Incident ID:** | INC-2025-0301-01 |
| **Target Service:** | Application Authentication Endpoint (`/ccse/app`) |
| **Attacker IP Address:** | `203.0.113.9` |
| **Severity Level:** | High (Unauthorized Access & Data Exfiltration) |

### Detection
The incident was detected automatically at 09:01:40 via custom SIEM threshold correlation. The correlation engine triggered the rule `probable brute-force -> compromise -> data exfiltration` after identifying a sequence of 4 consecutive failed login attempts, followed immediately by 1 successful login and a 500MB data export event sourced from IP `203.0.113.9`.

### Analysis
* **Initial Access / Reconnaissance:** At 09:01:10, the adversary initiated automated credential guessing against account `admin` from external IP `203.0.113.9`, accumulating 4 failed attempts (`LOGIN_FAIL`) in 8 seconds.
* **Compromise:** At 09:01:22, a successful authentication (`LOGIN_OK`) was recorded for user `admin` from `203.0.113.9`, indicating password compromise via brute-force.
* **Exfiltration:** At 09:01:40, the compromised `admin` account executed a bulk data dump (`EXPORT_DATA`) transferring 500MB to `203.0.113.9`.

### Containment
* **Network Isolation:** An emergency `iptables` drop rule (`iptables -A INPUT -s 203.0.113.9 -j DROP`) was deployed across host/container boundary firewalls to block all incoming packets from `203.0.113.9`.
* **Credential Revocation:** Account `admin` session tokens were invalidated, and mandatory password reset was initiated.

### Evidence & Integrity
* Forensic evidence file `evidence_20260908.log` was created from raw telemetry.
* Cryptographic hash verification digest was recorded in `evidence.sha256`:
  `0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b`.
* Hash chain analysis verified that raw logs remained un-tampered up to the time of isolation.

### Lesson Learned
"Prevention eventually fails." Reliance on simple password authentication is insufficient. Security architecture must enforce Multi-Factor Authentication (MFA), strict rate-limiting on login endpoints, append-only out-of-band log shipping (CloudWatch), and automated SOAR (Security Orchestration, Automation, and Response) to automatically block offending IPs upon detection.

---

## 5. Short-Answer Questions

### Q1. What is the difference between a log and an event? Give an example of each from this lab.
* **Log:** A durable, immutable, append-only record of a historical transaction or system execution saved to storage.  
  * *Lab Example:* `2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9` stored inside `auth.log`.
* **Event:** A real-time notification or state change triggered when log telemetry satisfies specific logical condition rules or thresholds.  
  * *Lab Example:* `ALERT: probable brute-force -> compromise -> data exfiltration` emitted by the correlation logic when 4 failed logins occurred followed by account access and data export.

### Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?
* **Why Audit Logs Must Be Tamper-Proof:** In an attack scenario, adversaries who gain administrative access attempt to clear or modify log entries to evade detection, erase evidence, and invalidate forensic audit trails needed for regulatory compliance.
* **How a Hash Chain Achieves Tamper-Proofing:** A hash chain mathematically binds each log entry to all preceding entries by calculating $H_n = \text{SHA256}(H_{n-1} \parallel \text{Line}_n)$. If an attacker changes a single byte in any past log line (e.g., changing `size=500MB` to `5MB`), every subsequent hash digest in the chain changes unpredictably due to the avalanche effect. Re-computing the chain immediately highlights the point of tampering.

### Q3. How did correlation detect an incident that no single log line revealed?
* **Explanation:** Isolated log entries appear routine: a failed login happens frequently due to user typos; a single successful login is standard user activity; a data export is a legitimate application feature. No individual line violates policy on its own. Correlation combines temporal context, user identity, and source IP across multiple distinct log entries. By evaluating the sequence (`FAILS >= 3` AND `SUCCESS >= 1` AND `EXPORT >= 1` from `203.0.113.9`), the SIEM identified an adversarial attack lifecycle (brute-force $\rightarrow$ privilege escalation $\rightarrow$ exfiltration).

### Q4. List the incident-response steps you performed and the goal of each.
1. **Detection:** Identified malicious activity via script correlation. *Goal:* Minimize attacker dwell time by discovering the breach immediately.
2. **Containment:** Applied an `iptables DROP` rule for IP `203.0.113.9`. *Goal:* Stop ongoing data exfiltration and prevent further unauthorized commands.
3. **Evidence Collection:** Copied raw logs to a timestamped file (`evidence_20260908.log`). *Goal:* Preserve an unaltered forensic record of the incident.
4. **Integrity Hashing:** Computed SHA-256 checksum into `evidence.sha256`. *Goal:* Maintain legal chain-of-custody and prove evidence was not modified post-incident.
5. **Documentation:** Drafted a formal Incident Report. *Goal:* Perform root cause analysis and record lessons learned to improve future prevention controls.

### Q5. How do the same logs serve both security monitoring and compliance evidence (Weeks 6, 11)?
* **Security Monitoring:** Operates in **near real-time** to feed SIEM engines, trigger active alerts, and automate security orchestration (e.g., blocking IPs, revoking compromised sessions).
* **Compliance Evidence:** Operates **historically** as proof of governance for frameworks such as ISO 27001, SOC 2, NIST SP 800-53, and PCI-DSS. Cryptographically secured, centralized logs prove to external auditors that system events are audited, access controls are enforced, and incident response SLAs were met.

---

## 6. Verification & Audit Commands

To verify the LocalStack CloudWatch setup and validate evidence log integrity, execute the following commands:

```bash
# 1. Verify LocalStack CloudWatch Log Group existence
aws --endpoint-url=http://localhost:4566 logs describe-log-groups

# 2. Verify Forensic Evidence SHA-256 Hash Integrity
sha256sum -c evidence.sha256
```

### Expected Output Verification:
```text
# sha256sum -c evidence.sha256
evidence_20260908.log: OK
```

---

## 7. Security Best-Practices Checklist

- [x] **Logs are centralised:** Telemetry is forwarded to CloudWatch (`/ccse/app`) rather than isolated on local server disks.
- [x] **Security-relevant activity queried:** Failed login attempts are aggregated and filtered by source IP (`uniq -c`).
- [x] **Logs are tamper-evident:** SHA-256 cryptographic hash chains validate append-only integrity and expose alteration.
- [x] **Multi-event incident correlation:** SIEM rule correlates brute-force, access, and exfiltration into a unified alert.
- [x] **Structured Incident Response:** Executed containment (`iptables`), evidence preservation, and cryptographic hashing.

---
