# CGE-P Capstone — Write-up

**Repository:** https://github.com/ashpearce/cgep-capstone
**Framework:** HIPAA Security Rule (45 CFR 164 Subpart C), cited via NIST SP 800-66 Rev. 2
**Evidence anchor:** GitHub Actions run `34511736584`, commit `70f782671404c324beeacabbc41d0e7813368c9d`, verified `CHAIN INTACT`

---

## 1. What this is

The starter is a serverless patient-intake workload (API Gateway → Lambda → DynamoDB + S3) with eight documented compliance gaps. This submission:

1. Establishes a GRC baseline (customer-managed KMS key, Object-Locked evidence vault, CloudTrail, OIDC trust for CI).
2. Closes seven of the eight gaps in Terraform.
3. Encodes each closure as a Rego policy evaluated against the Terraform plan.
4. Wires plan → policy gate → apply-on-merge → sign → upload into one GitHub Actions workflow, enforced by a repository ruleset.
5. Describes the result in OSCAL (catalog, profile, component definition), trestle-validated.

The chain a grader can follow: `GAPS.md` → `policies/gapNN_*.rego` → `oscal/components/acme-intake.json` (cites the policy and the real Terraform addresses) → `oscal/profiles/hipaa-intake.json` → `oscal/catalogs/hipaa-security-rule.json` → NIST SP 800-66r2. Every evidence reference is pinned to an S3 object version.

## 2. Framework choice

HIPAA Security Rule, because the workload handles PHI and the starter's `FRAMEWORKS.md` frames Acme as a covered entity. HIPAA has no official NIST OSCAL catalog, so — per `FRAMEWORKS.md` — NIST SP 800-66 Rev. 2 is the catalog `source` and each implemented requirement carries its `164.x` citation as a prop. A small project-authored catalog (`oscal/catalogs/hipaa-security-rule.json`) holds only the five sections this workload implements, with paraphrased statements and links to the DOI and eCFR text.

## 3. Gap coverage

Pass bar was five. Seven closed, one declined with a reason.

| Gap | What was wrong | HIPAA | Status | Policy |
|---|---|---|---|---|
| GAP-01 | `aws_s3_bucket.uploads` used SSE-S3, not the CMK | 164.312(a)(2)(iv) | Closed | `gap01` |
| GAP-02 | `aws_dynamodb_table.intake` used the AWS-owned key | 164.312(a)(2)(iv) | Closed | `gap02` |
| GAP-03 | No `aws:SecureTransport` deny on uploads bucket | 164.312(e)(1) | Closed | `gap03` |
| GAP-04 | No versioning on uploads bucket | 164.308(a)(7) | Closed | `gap04` |
| GAP-05 | Lambda not in the VPC | 164.312(e)(1) | Closed | `gap05` |
| GAP-06 | No reserved concurrency / DLQ / X-Ray | none | **Declined** | — |
| GAP-07 | Lambda role had `dynamodb:*` and `s3:*` | 164.312(a)(1) | Closed | `gap07` |
| GAP-08 | No API Gateway access logging | 164.312(b) | Closed | `gap08` |

**GAP-06 declined.** It has no HIPAA citation; its natural home is a resilience or observability control from another framework. `FRAMEWORKS.md` forbids a policy whose primary control is from an undeclared framework. Declining it is the honest reading of the rule, not a shortcut — the change itself is a few lines of Terraform.

35 Rego unit tests, all passing. `policies/fixtures/plan-gaps.json` is a hand-built plan representing the original broken starter; all seven policies fire against it, and `scripts/policy-gate.sh` exits non-zero on it and zero on the hardened plan (`evidence/gate-proof.txt`).

## 4. Declared decisions and trade-offs

| Decision | Choice | Trade-off |
|---|---|---|
| Framework | HIPAA Security Rule | Right fit for PHI; costs the official OSCAL catalog, so a project catalog stands in for it |
| Repo visibility | Public | GitHub rulesets only enforce on public repos at this plan tier; costs the risk of leaking state or secrets, mitigated by never committing state (verified) and using OIDC, not static keys |
| Apply | Auto-apply on merge to `main` | The pipeline deploys rather than just checks (brief requirement); costs a human approval step, mitigated by the required status check |
| Object Lock | COMPLIANCE mode, 1-day retention | Immutable even to the account root, which is the chain-of-custody guarantee; 1 day keeps the sandbox cleanable, a real deployment would use years |
| Accounts | Single account | Simpler OIDC and KMS story; costs blast-radius separation between the workload and the evidence vault |
| Region | us-east-1 | Where the starter lives; costs nothing here but is the one region with a `LocationConstraint` quirk on bucket creation |

Two smaller decisions worth recording: the **evidence vault is SSE-S3, not the CMK** (bundles hold plan JSON, not PHI, and a CMK grant would add a KMS dependency to the verifier), and **Terraform state lives in a separate versioned bucket**, not the vault (state is rewritten every apply; an Object-Locked state bucket would be a mess and would muddy the custody story).

## 5. Pipeline

`.github/workflows/grc-gate.yml`, one job:

1. **Plan** — `terraform init` against an S3 backend, `plan -out`, `show -json`.
2. **Policy gate** — `scripts/policy-gate.sh`: `opa test` then `conftest test --all-namespaces` over `planned_values`. Exit code is the decision.
3. **Apply** — only on `push` to `main`, only if the gate passed.
4. **Sign** — `always()`: bundle plan JSON, gate outcome and commit SHA; SHA-256; cosign keyless sign-blob with a Sigstore bundle.
5. **Upload** — bundle, digest and signature to the vault; then a `receipt.json` carrying the bundle's S3 `VersionId`, uploaded last because the version only exists once the object is in the vault.
6. **Enforce** — `always()`: fail the job if the gate did not pass, so evidence exists for failing runs but a failing run still fails.

Enforcement is a GitHub ruleset on `main`: `gate` is a required status check (source: GitHub Actions), branches must be up to date, force pushes blocked. A direct push to `main` was rejected with `GH013`.

`scripts/verify-evidence.sh <RUN_ID>` reads the receipt, fetches the bundle **by version ID**, and checks integrity (SHA-256 matches the receipt), authenticity (cosign verify, identity pinned to this repository's workflow, Rekor-logged), and preservation (Object Lock retention present).

**Red PR #3** (left open, unmerged) reintroduces GAP-02. The gate fails, the required check is red, and the merge button is disabled. Its first commit is the subject of finding 8.

## 6. Findings

These came from real failures, in the order I hit them.

**1. Object Lock protects versions, not keys.** Commonly described as preventing overwrites. It doesn't — a PUT to a locked key creates a new version that becomes latest; the locked original survives underneath and cannot be deleted. The guarantee is real but narrower: *the specific version named in the receipt* is immutable. That is why every evidence reference in this project is version-pinned.

**2. The verifier had the matching defect, and I fixed it.** The starter's `verify-evidence.sh` resolved by key with `aws s3 cp`, fetching whatever is latest. Mine reads `version_id` from the receipt and uses `get-object --version-id`. It also pins the signing identity to this repository instead of `--certificate-identity-regexp '.*'`.

**3. Encryption-enabled is not encryption-controlled.** DynamoDB has three states: AWS-owned, AWS-managed, customer-managed. A check asking "is encryption on" passes all three. Only the third satisfies HIPAA key custody, so `gap02` checks for the key ARN, not for encryption.

**4. Closing GAP-05 breaks the workload unless you also add VPC endpoints.** The starter's private subnets have no NAT and no route table association. Moving the Lambda in severs its path to DynamoDB and S3. Gateway endpoints fix it for free and are a better transmission-security posture than a NAT, since traffic never leaves the AWS backbone.

**5. Federated trust must be validated against a real token.** My GitHub tokens use the immutable-ID `sub` format (`repo:ashpearce@<id>/cgep-capstone@<id>:...`), so `repo:OWNER/REPO:*` does not match. The same class of failure hit me on AWS in Lab 4.3 and on GCP Workload Identity Federation in Lab 5.4; on both clouds the symptom is an opaque permission denial naming neither the claim nor the expected value. Pinning to the exact observed claim is *also* wrong — it broke PR runs, which present `:pull_request`. `StringLike` on `repo:ashpearce@*/cgep-capstone@*:*` is the working shape.

**6. Control implementation needs sequencing, not a checklist.** GAP-01/02 (CMK encryption) and GAP-07 (least-privilege role) are each individually correct and break the app if applied in the wrong order, because encryption without `kms:GenerateDataKey` fails every write — and the error surfaces in CloudWatch, not Terraform.

**7. CI planning without shared state produces false violations.** Before the S3 backend existed, CI planned from scratch: every cross-resource value was `(known after apply)`, and in `planned_values` that is indistinguishable from *absent*. The gate reported five false violations on correct infrastructure. A policy gate is only as meaningful as the fidelity of the plan it evaluates.

**8. A plan-based gate can only see what the provider chooses to surface.** The red PR's first attempt deleted `kms_key_arn` from the DynamoDB `server_side_encryption` block and left `enabled = true`. The gate passed. It was right to: `kms_key_arn` is Optional+Computed in the AWS provider, so Terraform back-filled it from state, the resource planned as `no-op`, and `planned_values` still showed the CMK. The regression never reached the plan. Setting `enabled = false` produces a real diff and the gate fails as intended. The limit is structural: removing a computed attribute is invisible to plan-time policy. Catching it needs drift detection against live configuration, not a better Rego rule.

**9. A required status check has to be named for the job, not the workflow.** The workflow is `grc-gate` and its job is `gate`; GitHub reports the check as `grc-gate / gate`, and the check-run name the ruleset matches on is `gate`. I initially required `grc-gate`, which never reported, so every PR sat at "Expected — waiting" and the merge button stayed disabled for the wrong reason. The symptom looks like enforcement working.

**10. An unterminated heredoc is a warning, not an error, even under `set -euo pipefail`.** A truncated paste cut the workflow off mid-`cat <<-EOF`. Bash warned, wrote an empty `receipt.json`, uploaded nothing for it, and exited 0. The run was green with no receipt in the vault. `verify-evidence.sh` caught it — which is the argument for a verifier that reads the receipt rather than trusting the run status.

## 7. Policy authoring lessons

- **Scope by data, not by resource type.** The first GAP-01 flagged my own evidence and CloudTrail buckets, which are deliberately SSE-S3. S3 policies filter on `.uploads`; GAP-07 filters to `.lambda_inline`.
- **Read `planned_values`, not `resource_changes`.** The diff has `after: null` for no-ops and deletes, so a pre-existing bad state never matches. `planned_values` is the post-apply world.
- **A policy that matches nothing passes.** The most dangerous failure mode; it looks identical to success. Every policy is tested against a fixture representing the broken state.
- **Guard `null` before `count()`.** `count(null)` errors, and an erroring Rego expression silently doesn't fire.
- **The interesting failures are half-configured, not absent.** Three policies catch a control that is present and inert: DynamoDB `enabled = true` with no `kms_key_arn`; S3 versioning `Suspended`; access logging with a format that omits `sourceIp`.
- **A rewound config is not an unhardened plan.** Checking out the pre-hardening `main.tf` and planning against remediated infrastructure produced `no-op`, because the provider treats an absent block as unmanaged. Purpose-built fixtures are the only reliable way to test a policy suite.

## 8. Verification

```bash
# App works after all seven closures
make test AWS_PROFILE=cgep-sandbox

# Policy unit tests (35) and the gate on both fixtures
opa test ./policies -v
bash scripts/policy-gate.sh policies/fixtures/plan-gaps.json   # non-zero
bash scripts/policy-gate.sh /tmp/plan-hardened.json            # zero

# Evidence chain for the apply run
EVIDENCE_VAULT=acme-health-intake-evidence-8e35a7ab \
  bash scripts/verify-evidence.sh 34511736584 --profile cgep-sandbox   # CHAIN INTACT

# OSCAL
bash scripts/validate-oscal.sh                                 # 3 x VALID
```

## 9. What I did not reach

- **State locking.** The CI Terraform is 1.9.8, which predates S3-native `use_lockfile`; no DynamoDB lock table was added. Concurrent applies are avoided by process (one apply path, on merge), not by a lock.
- **`gap02` empty-string hardening.** The third rule uses `not sse.kms_key_arn`; in Rego `not ""` is false, so an explicit empty string would slip through. `object.get(sse, "kms_key_arn", "") == ""` covers both; not applied because no fixture exercises it yet.
- **Drift detection.** Finding 8 shows plan-time policy cannot see a removed computed attribute. A scheduled `terraform plan -refresh-only` or AWS Config rule against the live table is the missing control.
- **State bucket under the CMK.** The state bucket is SSE-S3 for the same reason as the vault; a stricter posture would encrypt it with the CMK and grant the gate role in the key policy.
- **Retention.** One-day Object Lock is a sandbox setting. The verifier reports the retention date so a grader can see it; a production deployment would set years and a legal hold policy.
- **GAP-06.** Declined for framework reasons, not difficulty. If a second framework were declared (SOC 2 A1.2 or NIST 800-53 CP-10), it is a small change.
- **Patient data lifecycle.** Deletion and export of a patient's submission (DynamoDB item plus S3 attachment) are out of the starter's scope and not implemented. Under HIPAA this is a documentation and process control today; a technical control would be a lifecycle rule plus a deletion Lambda with its own audit trail.
- **API-layer authentication.** The endpoint is unauthenticated by design of the starter. Cognito or an API key on the stage is the named extension; not attempted.
