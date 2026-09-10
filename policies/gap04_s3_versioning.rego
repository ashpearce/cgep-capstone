# METADATA
# title: GAP-04 — PHI bucket must have versioning enabled
# description: >
#   Without versioning, an overwrite or delete of a PHI object is
#   unrecoverable. HIPAA contingency planning requires the ability to restore
#   exact copies of ePHI, which a single-version bucket cannot satisfy.
#   Evaluated against planned_values. Scoped to the PHI store.
# custom:
#   framework: hipaa
#   gap: GAP-04
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
package compliance.hipaa.gap04

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

resources[r] {
	r := input.planned_values.root_module.child_modules[_].resources[_]
}

# The PHI bucket exists with no versioning resource at all.
deny[msg] {
	b := resources[_]
	b.type == "aws_s3_bucket"
	endswith(b.address, ".uploads")
	count([v |
		v := resources[_]
		v.type == "aws_s3_bucket_versioning"
		endswith(v.address, ".uploads")
	]) == 0
	msg := sprintf("GAP-04 [164.308(a)(7)]: %s has no versioning configuration; a PHI overwrite would be unrecoverable", [b.address])
}

# Versioning resource exists but is Suspended or Disabled.
deny[msg] {
	v := resources[_]
	v.type == "aws_s3_bucket_versioning"
	endswith(v.address, ".uploads")
	vc := v.values.versioning_configuration[_]
	vc.status != "Enabled"
	msg := sprintf("GAP-04 [164.308(a)(7)]: %s versioning status is %s, not Enabled", [v.address, vc.status])
}