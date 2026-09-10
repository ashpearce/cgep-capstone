#!/usr/bin/env bash
# Validate the OSCAL catalog, profile and component definition with trestle.
# trestle only validates models inside a trestle workspace, so this creates a
# throwaway one, imports the three files (which schema-checks them) and runs
# validate -a. Exit code is the result.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(mktemp -d)"
trap 'rm -rf "$WS"' EXIT

cd "$WS"
trestle init >/dev/null

trestle import -f "$ROOT/oscal/catalogs/hipaa-security-rule.json" -o hipaa-security-rule >/dev/null
trestle import -f "$ROOT/oscal/profiles/hipaa-intake.json"        -o hipaa-intake        >/dev/null
trestle import -f "$ROOT/oscal/components/acme-intake.json"       -o acme-intake         >/dev/null

trestle validate -a
