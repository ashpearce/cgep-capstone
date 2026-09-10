# METADATA
# title: GAP-02 — Submissions table must be encrypted with a customer CMK
# description: >
#   DynamoDB has three encryption states: AWS-owned (the default, no customer
#   custody), AWS-managed (enabled with no key ARN), and customer-managed
#   (enabled with a kms_key_arn). Only the third satisfies HIPAA key custody,
#   so this policy checks for the key ARN rather than for encryption. A check
#   asking only "is encryption enabled" passes on all three.
#   Evaluated against planned_values, so a pre-existing bad state is caught as
#   well as a bad change.
# custom:
#   framework: hipaa
#   gap: GAP-02
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
package compliance.hipaa.gap02

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

resources[r] {
	r := input.planned_values.root_module.child_modules[_].resources[_]
}

# No server_side_encryption block at all — the AWS-owned key.
deny[msg] {
	t := resources[_]
	t.type == "aws_dynamodb_table"
	count(object.get(t.values, "server_side_encryption", [])) == 0
	msg := sprintf("GAP-02 [164.312(a)(2)(iv)]: %s has no server_side_encryption block; PHI defaults to the AWS-owned key with no customer custody", [t.address])
}

# Block present but turned off.
deny[msg] {
	t := resources[_]
	t.type == "aws_dynamodb_table"
	sse := t.values.server_side_encryption[_]
	sse.enabled == false
	msg := sprintf("GAP-02 [164.312(a)(2)(iv)]: %s has server_side_encryption disabled", [t.address])
}

# Enabled with no key ARN is the AWS-managed key, not customer custody.
deny[msg] {
	t := resources[_]
	t.type == "aws_dynamodb_table"
	sse := t.values.server_side_encryption[_]
	sse.enabled == true
	not sse.kms_key_arn
	msg := sprintf("GAP-02 [164.312(a)(2)(iv)]: %s is encrypted with the AWS-managed key; kms_key_arn is required for customer key custody", [t.address])
}