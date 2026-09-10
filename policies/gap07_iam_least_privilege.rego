# METADATA
# title: GAP-07 — No wildcard actions on PHI data stores
# description: >
#   The starter grants the intake Lambda dynamodb:* and s3:*, roughly 160
#   actions between them. Reading handler.py shows the code makes exactly two
#   calls: put_item and put_object. HIPAA access control requires access
#   rights limited to what is necessary, so the grant is derived from the code
#   rather than assumed. Scoped to the workload role; the pipeline's own gate
#   role is separately documented as broad.
#   Evaluated against planned_values.
# custom:
#   framework: hipaa
#   gap: GAP-07
#   controls:
#     - "164.312(a)(1)"
#   severity: high
package compliance.hipaa.gap07

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

resources[r] {
	r := input.planned_values.root_module.child_modules[_].resources[_]
}

# Inline policies attached to the workload Lambda role.
workload_policy[p] {
	p := resources[_]
	p.type == "aws_iam_role_policy"
	endswith(p.address, ".lambda_inline")
	is_string(p.values.policy)
}

deny[msg] {
	p := workload_policy[_]
	contains(p.values.policy, "\"dynamodb:*\"")
	msg := sprintf("GAP-07 [164.312(a)(1)]: %s grants dynamodb:* on PHI storage; handler.py calls only put_item", [p.address])
}

deny[msg] {
	p := workload_policy[_]
	contains(p.values.policy, "\"s3:*\"")
	msg := sprintf("GAP-07 [164.312(a)(1)]: %s grants s3:* on PHI storage; handler.py calls only put_object", [p.address])
}

# Action:"*" or Action:["*"] — total access.
deny[msg] {
	p := workload_policy[_]
	contains(p.values.policy, "\"Action\":\"*\"")
	msg := sprintf("GAP-07 [164.312(a)(1)]: %s grants Action:* on PHI storage", [p.address])
}

deny[msg] {
	p := workload_policy[_]
	contains(p.values.policy, "\"Action\":[\"*\"]")
	msg := sprintf("GAP-07 [164.312(a)(1)]: %s grants Action:[*] on PHI storage", [p.address])
}

# Any other service wildcard, e.g. kms:* or logs:*.
deny[msg] {
	p := workload_policy[_]
	regex.match(`"[a-z0-9-]+:\*"`, p.values.policy)
	not contains(p.values.policy, "\"dynamodb:*\"")
	not contains(p.values.policy, "\"s3:*\"")
	msg := sprintf("GAP-07 [164.312(a)(1)]: %s contains a service-level wildcard action", [p.address])
}