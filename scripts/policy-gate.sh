#!/usr/bin/env bash
# HIPAA policy gate. Exit code is the gate decision — do not swallow it.
set -uo pipefail

PLAN_JSON="${1:?usage: policy-gate.sh <plan.json>}"
POLICY_DIR="${POLICY_DIR:-policies}"

if [ ! -f "$PLAN_JSON" ]; then
  echo "FAIL: plan file not found: $PLAN_JSON"
  exit 2
fi

echo "== Rego unit tests =="
opa test "$POLICY_DIR" || {
  echo "FAIL: policy unit tests did not pass"
  exit 3
}

echo
echo "== Policy evaluation against $PLAN_JSON =="
conftest test --all-namespaces -p "$POLICY_DIR" "$PLAN_JSON"
RESULT=$?

echo
if [ "$RESULT" -eq 0 ]; then
  echo "GATE PASS: no HIPAA policy violations in this plan"
else
  echo "GATE FAIL: policy violations above must be resolved before merge"
fi

exit "$RESULT"
