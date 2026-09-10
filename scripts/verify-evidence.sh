#!/usr/bin/env bash
# Verify one run's evidence bundle: authenticity, integrity, preservation.
# Resolves by S3 object VERSION, not by key. See WRITEUP.md → Findings.
set -uo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--profile P]}"
shift || true
PROFILE=""
[ "${1:-}" = "--profile" ] && PROFILE="--profile $2"

VAULT="${EVIDENCE_VAULT:?set EVIDENCE_VAULT}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "Vault:  $VAULT"
echo "Run:    $RUN_ID"
echo

# --- receipt -------------------------------------------------------
aws s3 cp "s3://${VAULT}/runs/${RUN_ID}/receipt.json" "$WORK/receipt.json" $PROFILE >/dev/null || {
  echo "FAIL: no receipt for run $RUN_ID"; exit 1; }

BUNDLE_KEY=$(jq -r '.bundle_key' "$WORK/receipt.json")
VERSION_ID=$(jq -r '.version_id' "$WORK/receipt.json")
RECORDED=$(jq -r '.sha256'     "$WORK/receipt.json")

if [ -z "$VERSION_ID" ] || [ "$VERSION_ID" = "null" ]; then
  echo "FAIL: receipt has no version_id; cannot pin the artifact"
  exit 1
fi

echo "Key:     $BUNDLE_KEY"
echo "Version: $VERSION_ID"
echo

# --- 1. INTEGRITY: fetch the PINNED version, not the latest --------
aws s3api get-object \
  --bucket "$VAULT" --key "$BUNDLE_KEY" --version-id "$VERSION_ID" \
  $PROFILE "$WORK/bundle.tar.gz" >/dev/null || {
  echo "FAIL: could not fetch the pinned version"; exit 1; }

COMPUTED=$(sha256sum "$WORK/bundle.tar.gz" | cut -d' ' -f1)
if [ "$COMPUTED" != "$RECORDED" ]; then
  echo "FAIL: SHA mismatch"
  echo "  recorded: $RECORDED"
  echo "  computed: $COMPUTED"
  exit 1
fi
echo "PASS  integrity   — SHA-256 matches the receipt"

# --- 2. AUTHENTICITY: Sigstore signature + Rekor -------------------
aws s3 cp "s3://${VAULT}/${BUNDLE_KEY}.sig.bundle" "$WORK/sig.bundle" $PROFILE >/dev/null

cosign verify-blob \
  --bundle "$WORK/sig.bundle" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/ashpearce/cgep-capstone/' \
  "$WORK/bundle.tar.gz" >/dev/null 2>&1 || {
  echo "FAIL: signature did not verify"; exit 1; }
echo "PASS  authenticity — signed by this repository's workflow, logged in Rekor"

# --- 3. PRESERVATION: Object Lock still in force -------------------
RETAIN=$(aws s3api head-object \
  --bucket "$VAULT" --key "$BUNDLE_KEY" --version-id "$VERSION_ID" \
  $PROFILE --query ObjectLockRetainUntilDate --output text 2>/dev/null)

if [ -z "$RETAIN" ] || [ "$RETAIN" = "None" ]; then
  echo "FAIL: no Object Lock retention on this version"
  exit 1
fi
echo "PASS  preservation — Object Lock retention until $RETAIN"

echo
echo "CHAIN INTACT"
