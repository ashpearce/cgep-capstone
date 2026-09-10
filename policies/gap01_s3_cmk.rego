# METADATA
# title: GAP-01 — PHI uploads bucket must use SSE-KMS with a customer CMK
# description: >
#   AWS-managed SSE-S3 leaves key custody with AWS. HIPAA requires the covered
#   entity to control encryption of PHI at rest. Evaluated against
#   planned_values (the post-apply world), not resource_changes (the diff),
#   so a pre-existing bad state is caught as well as a bad change. Scoped to
#   the PHI store; the evidence and CloudTrail buckets hold no PHI and are
#   deliberately SSE-S3.
# custom:
#   framework: hipaa
#   gap: GAP-01
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
package compliance.hipaa.gap01

# Every resource that will exist after this plan is applied.
resources[r] {
	r := input.planned_values.root_module.resources[_]
}

resources[r] {
	r := input.planned_values.root_module.child_modules[_].resources[_]
}

# The PHI bucket exists but nothing encrypts it.
deny[msg] {
	b := resources[_]
	b.type == "aws_s3_bucket"
	endswith(b.address, ".uploads")
	count([c |
		c := resources[_]
		c.type == "aws_s3_bucket_server_side_encryption_configuration"
		endswith(c.address, ".uploads")
	]) == 0
	msg := sprintf("GAP-01 [164.312(a)(2)(iv)]: %s has no server-side encryption configuration; PHI at rest is not under customer key custody", [b.address])
}

# Encrypted, but not with KMS.
deny[msg] {
	c := resources[_]
	c.type == "aws_s3_bucket_server_side_encryption_configuration"
	endswith(c.address, ".uploads")
	d := c.values.rule[_].apply_server_side_encryption_by_default[_]
	d.sse_algorithm != "aws:kms"
	msg := sprintf("GAP-01 [164.312(a)(2)(iv)]: %s uses %s; the PHI bucket requires aws:kms with a customer CMK", [c.address, d.sse_algorithm])
}

# aws:kms with no key ARN resolves to the AWS-managed key, not yours.
deny[msg] {
	c := resources[_]
	c.type == "aws_s3_bucket_server_side_encryption_configuration"
	endswith(c.address, ".uploads")
	d := c.values.rule[_].apply_server_side_encryption_by_default[_]
	d.sse_algorithm == "aws:kms"
	not d.kms_master_key_id
	msg := sprintf("GAP-01 [164.312(a)(2)(iv)]: %s declares aws:kms without kms_master_key_id, which resolves to the AWS-managed key", [c.address])
}