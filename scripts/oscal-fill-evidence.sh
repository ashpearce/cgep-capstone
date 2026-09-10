#!/usr/bin/env bash
# Fill the evidence placeholders in oscal/components/acme-intake.json from the
# pipeline's receipt.json for a given run. Values come from the vault, not from
# a human retyping a version ID.
#
# Usage: bash scripts/oscal-fill-evidence.sh <RUN_ID> [--profile <aws-profile>]
set -euo pipefail

RUN_ID="${1:?usage: oscal-fill-evidence.sh <RUN_ID> [--profile <aws-profile>]}"
shift
PROFILE=""
[[ "${1:-}" == "--profile" ]] && PROFILE="--profile $2"

VAULT="${EVIDENCE_VAULT:-acme-health-intake-evidence-8e35a7ab}"
TARGET="oscal/components/acme-intake.json"
[[ -f "$TARGET" ]] || { echo "FAIL: $TARGET not found - run from the repo root"; exit 1; }

WORK="$(mktemp -d)"
aws s3 cp "s3://${VAULT}/runs/${RUN_ID}/receipt.json" "$WORK/receipt.json" $PROFILE >/dev/null \
  || { echo "FAIL: no receipt for run $RUN_ID"; exit 1; }

COMMIT=$(jq -r '.commit'      "$WORK/receipt.json")
KEY=$(jq -r '.bundle_key'     "$WORK/receipt.json")
VERSION=$(jq -r '.version_id' "$WORK/receipt.json")
SHA=$(jq -r '.sha256'         "$WORK/receipt.json")
EVENT=$(jq -r '.event'        "$WORK/receipt.json")
OUTCOME=$(jq -r '.gate_outcome' "$WORK/receipt.json")

[[ "$EVENT" == "push" ]]       || echo "WARN: run $RUN_ID is a '$EVENT' run, not a push to main"
[[ "$OUTCOME" == "success" ]]  || echo "WARN: run $RUN_ID gate outcome is '$OUTCOME'"
[[ -n "$VERSION" && "$VERSION" != "null" ]] || { echo "FAIL: receipt has no version_id"; exit 1; }

sed -i \
  -e "s|__RUN_ID__|${RUN_ID}|g" \
  -e "s|__COMMIT__|${COMMIT}|g" \
  -e "s|__BUNDLE_KEY__|${KEY}|g" \
  -e "s|__VERSION_ID__|${VERSION}|g" \
  -e "s|__SHA256__|${SHA}|g" \
  "$TARGET"

# Resolve the real Rego filenames so the OSCAL never cites a file that doesn't exist.
for g in gap01 gap02 gap03 gap04 gap05 gap07 gap08; do
  f=$(ls policies/${g}_*.rego 2>/dev/null | head -1)
  [[ -n "$f" ]] || { echo "FAIL: no policy file matches policies/${g}_*.rego"; exit 1; }
  sed -i "s|__POLICY_${g}__|${f}|g" "$TARGET"
done

if grep -q "__[A-Za-z0-9_]*__" "$TARGET"; then
  echo "FAIL: placeholders remain in $TARGET"; grep -n "__[A-Za-z0-9_]*__" "$TARGET"; exit 1
fi

echo "Filled $TARGET from run $RUN_ID"
echo "  commit:     $COMMIT"
echo "  bundle_key: $KEY"
echo "  version_id: $VERSION"
echo "  sha256:     $SHA"
