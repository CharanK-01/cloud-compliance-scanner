# Cloud Security Compliance Scanner (AWS & ISO 27001:2022)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Read-Only Guarantee](https://img.shields.io/badge/Security-Strictly%20Read--Only-green.svg)](#security--read-only-guarantee)
[![Compliance Standard](https://img.shields.io/badge/Compliance-ISO%2027001%3A2022-indigo.svg)](#iso-270012022-control-mappings)

A production-grade, strictly read-only Python CLI security tool that connects to an AWS account, audits configuration baselines across 25 security checks, maps each finding to **ISO 27001:2022 Annex A controls**, calculates a quantitative 5×5 risk matrix score, and generates executive-ready audit reports (self-contained HTML with interactive filtering, machine-readable JSON with SHA-256 integrity digest, and flat CSV for spreadsheet analysis).

Designed for **Cloud Security Engineers**, **Cyber Risk Analysts**, and **Compliance Auditors**, this tool acts as both an automated compliance assessment suite and a continuous CI/CD security gate.

---

## Key Highlights

- **Strictly Read-Only Guarantee:** Evaluates configurations solely via non-mutating `describe_*`, `get_*`, and `list_*` APIs. An automated AST unit test enforces that no modifying calls can ever be merged.
- **ISO 27001:2022 Annex A Alignment:** Every finding maps directly to official Annex A controls (e.g., A.5.15, A.8.20, A.8.24) with compliance rates computed per control.
- **Quantitative 5×5 Risk Scoring:** Findings are scored by $\text{Likelihood (1–5)} \times \text{Impact (1–5)}$, driving a risk-weighted **Overall Posture Score (0–100%)** rather than an unweighted pass/fail percentage.
- **Data-Driven Rules Engine:** Control definitions, risk ratings, and step-by-step remediation advice live in an external YAML file (`controls.yaml`), decoupled from code.
- **Executive & Auditor Reports:** Produces a single, self-contained HTML audit dashboard with interactive filtering, Top 5 Priority Risks, and cryptographic SHA-256 evidence verification.
- **Automated CI/CD Quality Gate:** `--fail-on [critical|high|medium|low]` enables non-zero exit codes for pipeline enforcement.

---

## Before & After Demonstration

Using our reproducible lab scripts (`lab/create_insecure_lab.py` and `lab/teardown.py`), we evaluated a test environment before and after implementing the scanner's step-by-step remediation guidance:

| Metric | Before Remediation (`before.html`) | After Remediation (`after.html`) | Impact |
|---|---|---|---|
| **Overall Posture Score** | **28.39%** (Poor) | **92.90%** (Exemplary) | **+64.51% Improvement** |
| **Critical Severity Risks** | 3 | 0 | 100% Eliminated |
| **High Severity Risks** | 8 | 0 | 100% Eliminated |
| **Audit Coverage** | 100% | 100% | Full Scope Verified |

> Sample reports are included in the repository under [`sample_output/before.html`](sample_output/before.html) and [`sample_output/after.html`](sample_output/after.html).

---

## Architecture Overview

```
CLI (scanner/cli.py) 
  ──► Session & Scope Discovery (scanner/session.py)
        ──► Check Registry (scanner/registry.py)
              ──► Read-Only Checks (scanner/checks/)
                    ──► Risk Matrix & Scoring Engine (scanner/scoring.py)
                          ├──► Self-Contained HTML Report (scanner/reports/html_report.py)
                          ├──► Evidence JSON + SHA-256 Hash (scanner/reports/exporters.py)
                          └──► Flat CSV for Audit Spreadsheet (scanner/reports/exporters.py)
```

For detailed component flow diagrams and specifications, see [docs/architecture.md](docs/architecture.md).

---

## 25 Security Checks & ISO 27001:2022 Mappings

| Check ID | Service | Title | ISO 27001:2022 Controls | Severity (Score) |
|---|---|---|---|---|
| **IAM-001** | IAM | Root account has MFA enabled | A.8.5, A.8.2 | Critical (20) |
| **IAM-002** | IAM | No root account active access keys | A.8.2, A.5.15 | High (16) |
| **IAM-003** | IAM | All console users have MFA enabled | A.8.5 | High (12) |
| **IAM-004** | IAM | Strong account password policy enforced | A.5.17 | Medium (9) |
| **IAM-005** | IAM | IAM access keys rotated within 90 days | A.5.17, A.5.18 | Medium (9) |
| **IAM-006** | IAM | No unused IAM credentials over 90 days | A.5.18 | Medium (9) |
| **IAM-007** | IAM | No wildcard `*:*` admin policies attached | A.8.2, A.5.15 | High (16) |
| **IAM-008** | IAM | Policies attached to groups/roles, not users | A.5.15, A.5.18 | Medium (6) |
| **S3-001** | S3 | Block Public Access enabled (bucket & account) | A.8.3, A.5.15 | High (15) |
| **S3-002** | S3 | No public S3 ACLs or public bucket policies | A.8.3 | Critical (20) |
| **S3-003** | S3 | Default encryption enabled (prefer SSE-KMS) | A.8.24 | Medium (6) |
| **S3-004** | S3 | S3 bucket versioning enabled | A.8.13 | Medium (6) |
| **S3-005** | S3 | S3 server access logging enabled | A.8.15 | Low (4) |
| **S3-006** | S3 | TLS enforced in transit (`aws:SecureTransport`) | A.8.24, A.5.14 | High (12) |
| **NET-001** | EC2/VPC | Security groups do not allow unrestricted SSH (22)/RDP (3389) | A.8.20, A.8.22 | High (16) |
| **NET-002** | EC2/VPC | Security groups do not allow unrestricted all-port ingress | A.8.20 | Critical (20) |
| **NET-003** | EC2/VPC | EBS default encryption enabled for account in region | A.8.24 | Medium (8) |
| **NET-004** | EC2/VPC | All attached and unattached EBS volumes encrypted | A.8.24 | Medium (8) |
| **NET-005** | EC2/VPC | VPC Flow Logs enabled for all VPCs | A.8.15, A.8.16 | Medium (9) |
| **LOG-001** | Logging | Multi-region CloudTrail enabled and actively logging | A.8.15 | High (16) |
| **LOG-002** | Logging | CloudTrail log file validation enabled | A.8.15, A.5.33 | Medium (8) |
| **LOG-003** | Logging | AWS Config configuration recorder enabled | A.8.9 | Medium (9) |
| **LOG-004** | Logging | Amazon GuardDuty detector enabled | A.8.16 | High (12) |
| **KMS-001** | KMS | Customer-managed symmetric KMS keys have annual rotation | A.8.24 | Medium (6) |
| **RDS-001** | RDS | Database instances have storage encryption enabled | A.8.24 | Medium (8) |
| **RDS-002** | RDS | RDS database instances are not publicly accessible | A.8.20, A.8.3 | High (16) |
| **RDS-003** | RDS | Automated backup retention period is $\ge 7$ days | A.8.13, A.5.30 | Medium (8) |
| **RDS-004** | RDS | Production RDS instances configured with Multi-AZ | A.8.14, A.5.30 | Medium (6) |

---

## Quick Start Guide

### 1. Prerequisites & AWS Account Setup
1. Create or use an AWS account.
2. Create an IAM identity or role for the scanner with the AWS-managed **`SecurityAudit`** policy (and optionally `ViewOnlyAccess`). Real-world external auditors utilize this exact policy.
3. Configure your AWS CLI named profile:
   ```bash
   aws configure --profile scanner
   ```

### 2. Installation
Clone the repository and install requirements:
```bash
git clone https://github.com/your-username/cloud-compliance-scanner.git
cd cloud-compliance-scanner

# Install dependencies using your Python virtual environment
pip install -r requirements.txt
```

### 3. List All Available Checks
Inspect all registered checks and their ISO 27001 alignments:
```bash
python -m scanner list-checks
```

### 4. Run an Audit Scan
Run a full scan against your AWS environment across regions:
```bash
python -m scanner scan --profile scanner --regions us-east-1,ap-south-1 \
    --services iam,s3,ec2,logging,kms,rds \
    --format html,json,csv --output ./reports
```

### 5. Run as a CI/CD Quality Gate
Block pipelines if any `critical` or `high` severity failures are detected:
```bash
python -m scanner scan --profile scanner --regions us-east-1 --fail-on high
```

---

## Repository Structure

```
cloud-compliance-scanner/
├── README.md                           # Documentation, setup & portfolio summary
├── requirements.txt                    # boto3, PyYAML, Jinja2, typer, rich, pytest, moto
├── scanner/
│   ├── __init__.py                     # Package init
│   ├── __main__.py                     # CLI launcher (python -m scanner)
│   ├── cli.py                          # Typer CLI interface with rich terminal UI
│   ├── models.py                       # Finding, CheckDefinition, ScanSummary models
│   ├── registry.py                     # @check decorator and dynamic module loader
│   ├── session.py                      # boto3 session, adaptive retry, region discovery
│   ├── scoring.py                      # 5x5 risk matrix & ISO compliance aggregator
│   ├── checks/                         # Strictly read-only check implementations
│   │   ├── iam.py                      # IAM-001 through IAM-008
│   │   ├── s3.py                       # S3-001 through S3-006
│   │   ├── ec2_vpc.py                  # NET-001 through NET-005
│   │   ├── logging_monitoring.py       # LOG-001 through LOG-004
│   │   ├── kms.py                      # KMS-001
│   │   └── rds.py                      # RDS-001 through RDS-004
│   ├── mappings/
│   │   └── controls.yaml               # Check metadata, ISO mappings, L/I risk scores
│   └── reports/
│       ├── html_report.py              # HTML generator via Jinja2
│       ├── exporters.py                # JSON evidence and CSV exporters
│       └── templates/report.html.j2    # Responsive, dark/light HTML report template
├── lab/
│   ├── create_insecure_lab.py          # Creates near-free lab resources for testing
│   └── teardown.py                     # Cleans up all lab resources safely
├── tests/                              # Comprehensive unit and integrity test suite
│   ├── test_readonly_guarantee.py      # AST analysis enforcing zero mutating calls
│   ├── test_mapping_integrity.py       # Validates all checks exist in controls.yaml
│   ├── test_iam.py                     # Moto-based unit tests for IAM
│   ├── test_s3.py                      # Moto-based unit tests for S3
│   ├── test_ec2_vpc.py                 # Moto-based unit tests for EC2 & VPC
│   └── test_scoring.py                 # Mathematical scoring formula validation
├── sample_output/                      # Portfolio artifacts
│   ├── before.html / before.json / before.csv
│   └── after.html  / after.json  / after.csv
└── docs/
    ├── architecture.md                 # Architecture flow and design principles
    └── methodology.md                  # Risk matrix formulas & ISO rationale
```

---

## Testing & Quality Assurance

Run the test suite using pytest:
```bash
pytest -v
```

### Highlights of Test Coverage:
1. **AST Read-Only Guarantee (`test_readonly_guarantee.py`):** Automatically scans check source code and fails if any boto3 method starts with `create_`, `put_`, `delete_`, `update_`, `modify_`, `attach_`, or `detach_` (with `generate_credential_report` explicitly whitelisted).
2. **Mapping Integrity (`test_mapping_integrity.py`):** Ensures 100% of registered checks have valid entries in `controls.yaml` with Likelihood/Impact between 1–5, valid ISO 27001 Annex A control prefixes, and non-empty remediation text.
3. **Moto AWS Unit Tests:** Verifies compliant and non-compliant scenarios across IAM, S3, and EC2 using in-memory AWS API mocks.

---

## Limitations & Disclaimer

- **Point-in-Time Scope:** Assesses the state of cloud configuration parameters at the exact time of scan execution.
- **Control Plane Focus:** Evaluates AWS control-plane configurations. It does not inspect operating system kernels, application code vulnerabilities, or network packet payloads.
- **Indicative Mapping:** The mapping to ISO 27001:2022 Annex A is designed for security posture assessment and internal gap analysis; it does not replace a formal audit by an accredited certification body.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
