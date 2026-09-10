# Capstone design — Acme Health Patient Intake

## Primary framework: HIPAA Security Rule

The workload handles PHI, which makes HIPAA the framework that actually applies
to Acme rather than one that could be argued for. SOC 2 would describe how the
pipeline operates over time and CMMC would fit a federal pursuit Acme is not
making; neither is triggered by the facts. HIPAA's Technical Safeguards map
directly onto what the gaps are: encryption at rest and in transit, audit
controls, and access control.

OSCAL note: there is no official NIST OSCAL catalog for HIPAA. Per
FRAMEWORKS.md this component cites **NIST SP 800-66 Rev. 2** as the catalog and
carries the 164.x citations as `props` on each implemented requirement.

## Gap coverage

| Gap | HIPAA | Terraform | Policy | Note |
|---|---|---|---|---|
| GAP-01 S3 SSE-S3 not CMK | 164.312(a)(2)(iv) | yes | yes | |
| GAP-02 DynamoDB AWS key | 164.312(a)(2)(iv) | yes | yes | edits starter main.tf |
| GAP-03 no TLS-only policy | 164.312(e)(1) | yes | yes | |
| GAP-04 no versioning | 164.308(a)(7) | yes | yes | |
| GAP-05 Lambda outside VPC | 164.312(e)(1) | yes | yes | needs VPC endpoints |
| GAP-06 no DLQ/X-Ray | none | **declined** | no | no HIPAA citation |
| GAP-07 IAM wildcards | 164.312(a)(1) | yes | yes | derived from handler.py |
| GAP-08 no API access log | 164.312(b) | yes | yes | |

## Decisions

| Decision | Choice | What I gave up |
|---|---|---|
| Framework | HIPAA | Broader TSC coverage a SOC 2 pick would have given |
| Repo visibility | Public | AWS account ID visible; gained real ruleset enforcement |
| Apply | Auto on merge | Human review of the plan; gained a genuinely continuous gate |
| Object Lock | COMPLIANCE, 1 day | Realistic retention; kept the strongest tamper claim |
| Accounts | Single | Evidence outside the audited account; 5-day constraint |
| Region | us-east-1 | Nothing; no residency requirement in the scenario |

## Scope boundary

GAP-06 declined on framework grounds. No SSP, no Assessment Results. Evidence
vault is in the same account as the workload.
