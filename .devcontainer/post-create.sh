#!/usr/bin/env bash
# No 'set -e' on purpose: one failure must not skip the rest.

echo "== terraform =="
curl -fsSL -o /tmp/tf.zip https://releases.hashicorp.com/terraform/1.9.8/terraform_1.9.8_linux_amd64.zip \
  && sudo unzip -o -q /tmp/tf.zip -d /usr/local/bin && echo "  ok" || echo "  FAILED"

echo "== aws cli =="
curl -fsSL -o /tmp/aws.zip "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" \
  && unzip -o -q /tmp/aws.zip -d /tmp && sudo /tmp/aws/install --update && echo "  ok" || echo "  FAILED"

echo "== opa =="
sudo curl -fsSL -o /usr/local/bin/opa \
  https://github.com/open-policy-agent/opa/releases/download/v0.63.0/opa_linux_amd64_static \
  && sudo chmod +x /usr/local/bin/opa && echo "  ok" || echo "  FAILED"

echo "== conftest =="
curl -fsSL https://github.com/open-policy-agent/conftest/releases/download/v0.50.0/conftest_0.50.0_Linux_x86_64.tar.gz \
  | sudo tar -xz -C /usr/local/bin conftest && echo "  ok" || echo "  FAILED"

echo "== cosign =="
sudo curl -fsSL -o /usr/local/bin/cosign \
  https://github.com/sigstore/cosign/releases/download/v2.2.4/cosign-linux-amd64 \
  && sudo chmod +x /usr/local/bin/cosign && echo "  ok" || echo "  FAILED"

echo "== trestle =="
pip install --break-system-packages compliance-trestle && echo "  ok" || echo "  FAILED"

echo "== summary =="
for t in terraform aws gh opa conftest cosign trestle jq; do
  printf '  %-10s %s\n' "$t" "$(command -v $t || echo MISSING)"
done
