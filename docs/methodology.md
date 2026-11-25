# Cyber Risk & Compliance Methodology: ISO 27001:2022 Mapping

This document details the risk assessment methodology, statistical scoring algorithms, and ISO 27001:2022 Annex A control mappings implemented by the **Cloud Security Compliance Scanner**.

---

## 1. Risk Scoring Engine (5x5 Matrix)

The scanner applies a standard quantitative 5×5 risk matrix:

$$\text{Risk Score} = \text{Likelihood} \times \text{Impact}$$

Where:
- **Likelihood (1 to 5)** reflects the probability of discovery and exploitation based on exposure (e.g., internet-facing vs. internal, automated bot attacks).
- **Impact (1 to 5)** reflects the severity of data loss, compromise of confidentiality, integrity, availability, or regulatory breach.

### Severity Rating Classification

| Score Range | Risk Rating | Description & SLAs |
|---|---|---|
| **20 – 25** | **Critical** | Immediate risk of full account compromise, unauthorized public data exposure, or unconstrained privilege. Remediation SLA: < 24 hours. |
| **12 – 19** | **High** | Significant security gap (open management ports, lack of encryption in transit, MFA gaps on privileged users). Remediation SLA: < 7 days. |
| **6 – 11** | **Medium** | Defense-in-depth weakness, configuration hygiene gap, or non-optimal lifecycle settings. Remediation SLA: < 30 days. |
| **1 – 5** | **Low** | Informational gap, logging enhancement, or best-practice hardening recommendation. Remediation SLA: < 90 days. |

---

## 2. Quantitative Scoring Formulas

### 2.1 Overall Posture Score
Unlike naive checkers that calculate simple percentage passed ($N_\text{pass} / N_\text{total}$), our scanner calculates a **risk-weighted posture score**:

$$\text{Overall Posture Score} = 100 \times \left(1 - \frac{\sum \text{Risk}(\text{FAIL})}{\sum \text{Risk}(\text{Evaluated})}\right)$$

- Evaluated findings include `PASS` and `FAIL` configurations.
- A single Critical finding (e.g. Risk = 20) carries 4x the impact of a Low finding (Risk = 5).
- If all evaluated findings pass, the score is **100%**.
- If no findings exist, the default posture is **100%**.

### 2.2 Per-Control Compliance Rate
For each evaluated ISO 27001:2022 Annex A control:

$$\text{Compliance Rate (Control } C) = \frac{\text{Passed Findings in } C}{\text{Total Evaluated Findings in } C} \times 100\%$$

- **Compliant (100%)**: All checks mapped to control passed without failure.
- **Non-Compliant (< 100%)**: One or more evaluated checks produced a `FAIL`.
- **Incomplete / Gap**: Evaluations returned `ERROR` (e.g., due to insufficient auditor IAM permissions).

### 2.3 Audit Coverage Rate
To prevent false-positive inflation caused by missing permissions (e.g. `AccessDenied`), the coverage rate explicitly measures evaluation completeness:

$$\text{Audit Coverage} = \frac{\text{Successfully Executed Checks}}{\text{Total Attempted Checks}} \times 100\%$$

Errors penalize coverage rather than artificially inflating the posture score.

---

## 3. ISO 27001:2022 Annex A Control Alignments

| ISO 27001:2022 Control | Control Title | Mapped Checks | Defense Rationale |
|---|---|---|---|
| **A.5.14** | Information transfer | S3-006 | Enforces TLS cryptographic protocols for data in transit across public networks. |
| **A.5.15** | Access control | IAM-002, IAM-007, IAM-008, S3-001 | Restricts administrative credentials, ensures least privilege, and disables public bucket policies. |
| **A.5.17** | Authentication information | IAM-004, IAM-005 | Enforces password complexity, length, rotation, and lifecycle controls. |
| **A.5.18** | Access rights | IAM-005, IAM-006, IAM-008 | Prevents accumulation of dormant credentials and ensures group-based RBAC. |
| **A.5.30** | ICT readiness for business continuity | RDS-003, RDS-004 | Enforces point-in-time recovery backup retention and Multi-AZ database failover. |
| **A.5.33** | Protection of records | LOG-002 | Cryptographically validates CloudTrail log digests against tampering and deletion. |
| **A.8.2** | Privileged access rights | IAM-001, IAM-002, IAM-007 | Protects the root account and prevents wildcard `*:*` administrative policy grants. |
| **A.8.3** | Information access restriction | S3-001, S3-002, RDS-002 | Prevents public accessibility of object storage and relational database instances. |
| **A.8.5** | Secure authentication | IAM-001, IAM-003 | Enforces multi-factor authentication for root and console identity holders. |
| **A.8.9** | Configuration management | LOG-003 | Continuously tracks infrastructure baseline configurations and detects configuration drift. |
| **A.8.13** | Information backup | S3-004, RDS-003 | Enables S3 object versioning and automated multi-day database backups. |
| **A.8.14** | Redundancy of facilities | RDS-004 | Validates high-availability multi-AZ deployment topologies for database storage. |
| **A.8.15** | Logging | S3-005, NET-005, LOG-001, LOG-002 | Enforces central multi-region CloudTrail, VPC Flow Logs, and S3 access logs. |
| **A.8.16** | Monitoring activities | NET-005, LOG-004 | Deploys continuous ML threat detection (GuardDuty) and network telemetry analysis. |
| **A.8.20** | Network controls | NET-001, NET-002, RDS-002 | Prevents exposure of sensitive ports (22, 3389) and wildcard all-port internet access. |
| **A.8.22** | Segregation of networks | NET-001 | Restricts management traffic to dedicated private admin bastion CIDRs. |
| **A.8.24** | Use of cryptography | S3-003, S3-006, NET-003, NET-004, KMS-001, RDS-001 | Mandates KMS encryption at rest across S3, EBS, and RDS, plus annual key rotation. |

---

## 4. Scope & Limitations

1. **Point-in-Time Assessment:** The scanner evaluates configuration states at the moment of API query execution.
2. **Configuration Plane Only:** The scanner inspects cloud infrastructure configurations (IAM, security groups, encryption parameters). It does not inspect operating system internal filesystems, running process memory, or web application vulnerabilities.
3. **Indicative Compliance:** Mappings to ISO 27001:2022 Annex A are structured to assist risk managers and internal auditors. This report does not constitute an official accredited ISO/IEC certification audit or formal certificate.
