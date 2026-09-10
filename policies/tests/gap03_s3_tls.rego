# METADATA
# title: GAP-03 — PHI bucket must deny non-TLS requests
# description: >
#   S3 accepts both HTTP and HTTPS unless a bucket policy forbids the former.
#   HIPAA transmission security requires PHI to be protected in transit, so
#   the bucket must carry an explicit Deny on aws:SecureTransport=false. An
#   explicit Deny wins over any Allow in IAM evaluation, which is why this is
#   a deny-on-condition rather than an allow-on-TLS.
#   Evaluated against planned_values. Scoped to the PHI store; the evidence
#   and CloudTrail buckets are not internet-facing PHI stores.
# custom:
#   framework: hipaa
#   gap: GAP-03
#   controls:
#     - "164.312(e)(1)"
#   severity: high
package compliance.hipaa.gap03

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

resources[r] {
	r := input.planned_values.root_module.child_modules[_].resources[_]
}

# The PHI bucket exists with no bucket policy at all.
deny[msg] {
	b := resources[_]
	b.type == "aws_s3_bucket"
	endswith(b.address, ".uploads")
	count([p |
		p := resources[_]
		p.type == "aws_s3_bucket_policy"
		endswith(p.address, ".uploads")
	]) == 0
	msg := sprintf("GAP-03 [164.312(e)(1)]: %s has no bucket policy; PHI can be read or written over plain HTTP", [b.address])
}

# A policy exists but never mentions the TLS condition.
deny[msg] {
	p := resources[_]
	p.type == "aws_s3_bucket_policy"
	endswith(p.address, ".uploads")
	is_string(p.values.policy)
	not contains(p.values.policy, "aws:SecureTransport")
	msg := sprintf("GAP-03 [164.312(e)(1)]: %s does not reference aws:SecureTransport; non-TLS requests are not denied", [p.address])
}

# It mentions the condition but does not Deny on it.
deny[msg] {
	p := resources[_]
	p.type == "aws_s3_bucket_policy"
	endswith(p.address, ".uploads")
	is_string(p.values.policy)
	contains(p.values.policy, "aws:SecureTransport")
	not contains(p.values.policy, "\"Deny\"")
	msg := sprintf("GAP-03 [164.312(e)(1)]: %s references aws:SecureTransport without an explicit Deny", [p.address])
}