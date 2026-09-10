# METADATA
# title: GAP-05 — PHI-handling Lambda must run inside the VPC
# description: >
#   A Lambda outside a VPC reaches DynamoDB and S3 across the public AWS
#   network. Placing it in private subnets with gateway endpoints keeps PHI
#   traffic on the AWS backbone and off any internet-routable path, which is
#   a stronger transmission-security posture than encryption in transit alone.
#   Evaluated against planned_values. Not address-scoped: every Lambda in this
#   account handles intake data, so all are in scope.
# custom:
#   framework: hipaa
#   gap: GAP-05
#   controls:
#     - "164.312(e)(1)"
#   severity: medium
package compliance.hipaa.gap05

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

resources[r] {
	r := input.planned_values.root_module.child_modules[_].resources[_]
}

# No vpc_config block at all.
deny[msg] {
	f := resources[_]
	f.type == "aws_lambda_function"
	not has_vpc_config(f)
	msg := sprintf("GAP-05 [164.312(e)(1)]: %s has no vpc_config; PHI traffic traverses the public AWS network", [f.address])
}

has_vpc_config(f) {
	vc := object.get(f.values, "vpc_config", [])
	is_array(vc)
	count(vc) > 0
}

# vpc_config present but no subnets, which attaches it to nothing.
deny[msg] {
	f := resources[_]
	f.type == "aws_lambda_function"
	vc := f.values.vpc_config[_]
	count(object.get(vc, "subnet_ids", [])) == 0
	msg := sprintf("GAP-05 [164.312(e)(1)]: %s declares vpc_config with no subnet_ids", [f.address])
}

# vpc_config present but no security group.
deny[msg] {
	f := resources[_]
	f.type == "aws_lambda_function"
	vc := f.values.vpc_config[_]
	count(object.get(vc, "security_group_ids", [])) == 0
	msg := sprintf("GAP-05 [164.312(e)(1)]: %s declares vpc_config with no security_group_ids", [f.address])
}