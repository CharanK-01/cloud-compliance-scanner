# Architecture & Design

The Cloud Security Compliance Scanner follows a modular, plugin-based, and strictly read-only architecture designed for audit integrity, maintainability, and enterprise pipeline integration.

---

## Architecture Flow Diagram

```mermaid
flowchart TD
    subgraph CLI ["1. Command Line Interface (scanner/cli.py)"]
        UserCmd["CLI Command: python -m scanner scan"]
        Args["Options: --profile, --regions, --services, --format, --fail-on"]
    end

    subgraph CoreEngine ["2. Core Engine & Session (scanner/)"]
        SessionMgr["session.py: Boto3 Session & STS Caller Identity"]
        RegionDisc["session.py: Region Discovery & Client Pool"]
        ScanCtx["models.py: ScanContext (Adaptive Retry Config)"]
        Registry["registry.py: Dynamic Check Discovery & Registry"]
        ControlsMap["mappings/controls.yaml: ISO 27001 & Risk Metadata"]
    end

    subgraph CheckModules ["3. Read-Only Checks (scanner/checks/)"]
        IAMCheck["iam.py (IAM-001 - IAM-008)"]
        S3Check["s3.py (S3-001 - S3-006)"]
        EC2Check["ec2_vpc.py (NET-001 - NET-005)"]
        LogCheck["logging_monitoring.py (LOG-001 - LOG-004)"]
        KMSCheck["kms.py (KMS-001)"]
        RDSCheck["rds.py (RDS-001 - RDS-004)"]
    end

    subgraph Analytics ["4. Scoring & Compliance Engine (scanner/scoring.py)"]
        EvalLoop["Evaluate Findings (PASS, FAIL, ERROR, N/A)"]
        PostureCalc["Risk-Weighted Posture Score"]
        ISOAgg["ISO 27001 Annex A Control Compliance Aggregation"]
        CoverageCalc["Audit Coverage & Top Priority Risks"]
    end

    subgraph Reporting ["5. Exporters & Report Generation (scanner/reports/)"]
        HTMLGen["html_report.py: Self-Contained Jinja2 HTML Report"]
        JSONGen["exporters.py: JSON Evidence File & SHA-256 Digest"]
        CSVGen["exporters.py: Flat Audit Findings CSV for Excel"]
        CIGate["CI Quality Gate (--fail-on threshold)"]
    end

    UserCmd --> Args
    Args --> SessionMgr
    SessionMgr --> RegionDisc
    RegionDisc --> ScanCtx
    ControlsMap --> ScanCtx
    ScanCtx --> Registry

    Registry --> IAMCheck
    Registry --> S3Check
    Registry --> EC2Check
    Registry --> LogCheck
    Registry --> KMSCheck
    Registry --> RDSCheck

    IAMCheck --> EvalLoop
    S3Check --> EvalLoop
    EC2Check --> EvalLoop
    LogCheck --> EvalLoop
    KMSCheck --> EvalLoop
    RDSCheck --> EvalLoop

    EvalLoop --> PostureCalc
    EvalLoop --> ISOAgg
    EvalLoop --> CoverageCalc

    PostureCalc --> HTMLGen
    ISOAgg --> HTMLGen
    CoverageCalc --> HTMLGen

    PostureCalc --> JSONGen
    PostureCalc --> CSVGen
    JSONGen -. SHA-256 Digest .-> HTMLGen

    PostureCalc --> CIGate
```

---

## Architectural Principles

1. **Strictly Read-Only Enforced by AST Tests:**
   All evaluation modules use only non-mutating AWS APIs (`describe_*`, `get_*`, `list_*`). AST-level tests (`tests/test_readonly_guarantee.py`) parse python syntax trees to ensure no methods starting with `create_`, `put_`, `delete_`, `update_`, `modify_`, `attach_` or `detach_` can ever be added.

2. **Data-Driven Mappings:**
   Risk scores (Likelihood $\times$ Impact), remediation guidance, and ISO 27001:2022 Annex A control numbers reside in `scanner/mappings/controls.yaml` rather than hardcoded in Python code. Auditors can inspect and adjust compliance criteria without touching logic.

3. **Resilient & Isolated Execution:**
   Each check is wrapped in exception isolation. An `AccessDenied` or API outage on one check produces a recorded `ERROR` finding without crashing the overall audit run.

4. **Cryptographic Evidence Integrity:**
   All raw evidence gathered during a scan is serialized to JSON. The SHA-256 digest of this file is computed and stamped directly onto the HTML report footer.
