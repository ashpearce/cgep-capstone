# cgep-capstone — HIPAA evidence pipeline for a patient-intake workload

CGE-P capstone submission by Ashley Pearce. Fork of `GRCEngClub/cgep-app-starter`.

**Framework:** HIPAA Security Rule, cited via NIST SP 800-66 Rev. 2
**Gaps closed:** 7 of 8 (GAP-06 declined — no HIPAA citation; see `WRITEUP.md`)
**Evidence anchor:** run `34511736584`, commit `70f782671404c324beeacabbc41d0e7813368c9d`

Full narrative, decisions and findings: **[`WRITEUP.md`](WRITEUP.md)**.

## What happens on every PR and merge

`.github/workflows/grc-gate.yml` — one job: **plan → policy gate → apply (merge only) → sign → upload → enforce**.

- Seven Rego policies (`policies/`) evaluate the Terraform plan's `planned_values`. Their exit code is the gate.
- On merge to `main`, the plan is applied.
- Every run — passing or failing — produces a signed evidence bundle (cosign keyless, Rekor-logged) in a COMPLIANCE-mode Object Lock vault, plus a `receipt.json` that pins the bundle's S3 version ID.
- A repository ruleset on `main` requires the `gate` check; merging a failing PR is not possible.

**Red PR:** [#3](https://github.com/ashpearce/cgep-capstone/pull/3) reintroduces GAP-02 and is left open unmerged. The gate fails and the merge button is disabled.

## Verify it yourself

Requires AWS credentials for account `670163018466` (profile `cgep-sandbox` in the commands below), `cosign`, `jq`, `opa`, `conftest` and `trestle`. `.devcontainer/post-create.sh` installs the tools.

```bash
# 1. Evidence chain for the apply run: integrity, authenticity, preservation
EVIDENCE_VAULT=acme-health-intake-evidence-8e35a7ab \
  bash scripts/verify-evidence.sh 34511736584 --profile cgep-sandbox
# expect: PASS integrity / PASS authenticity / PASS preservation / CHAIN INTACT

# 2. Policy suite: 35 unit tests, then the gate fails closed on the broken fixture
opa test ./policies -v
bash scripts/policy-gate.sh policies/fixtures/plan-gaps.json   # exits non-zero

# 3. OSCAL: catalog, profile and component definition validate with trestle
bash scripts/validate-oscal.sh                                 # 3 x VALID

# 4. App still works after hardening
make test AWS_PROFILE=cgep-sandbox                             # returns a submission_id
```

Any run ID from the vault works with `verify-evidence.sh`, including the red PR's failing runs — the bundle is produced before the job fails.

## Layout

| Path | What |
|---|---|
| `terraform/` | Starter workload plus `kms.tf`, `evidence-vault.tf`, `cloudtrail.tf`, `oidc-trust.tf`, `hardening.tf`, `backend.tf` (S3 state), `state-backend-iam.tf` |
| `policies/` | `gapNN_*.rego` policies, `tests/` (35 tests), `fixtures/plan-gaps.json` (the broken starter as a plan) |
| `scripts/policy-gate.sh` | `opa test` + `conftest test --all-namespaces`; exit code is the decision |
| `scripts/verify-evidence.sh` | Fetches the bundle **by S3 version ID** from the receipt and checks it |
| `scripts/oscal-fill-evidence.sh` | Fills the OSCAL evidence props from a run's `receipt.json` |
| `scripts/validate-oscal.sh` | trestle validation in a throwaway workspace |
| `oscal/` | `catalogs/hipaa-security-rule.json` → `profiles/hipaa-intake.json` → `components/acme-intake.json` |
| `evidence/` | Local proofs: post-hardening `make test`, gate-proof on both fixtures |
| `GAPS.md`, `FRAMEWORKS.md`, `DESIGN.md` | Starter brief, framework rules, design notes |

## Do not tear down

Infrastructure stays up until graded. The grader pulls a run and verifies it against the live vault.
