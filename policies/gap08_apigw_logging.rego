# METADATA
# title: GAP-08 — API stage must emit access logs
# description: >
#   CloudTrail records who changed the infrastructure. It does not record who
#   called the PHI intake endpoint. Without stage access logging there is no
#   answer to "who submitted or retrieved patient data, from where, and when",
#   which is the question HIPAA audit controls exist to answer.
#   Evaluated against planned_values.
# custom:
#   framework: hipaa
#   gap: GAP-08
#   controls:
#     - "164.312(b)"
#   severity: high
package compliance.hipaa.gap08

resources[r] {
	r := input.planned_values.root_module.resources[_]
}

resources[r] {
	r := input.planned_values.root_module.child_modules[_].resources[_]
}

# No access_log_settings block at all.
deny[msg] {
	s := resources[_]
	s.type == "aws_apigatewayv2_stage"
	not has_access_logging(s)
	msg := sprintf("GAP-08 [164.312(b)]: %s has no access_log_settings; PHI endpoint activity is unrecorded", [s.address])
}

has_access_logging(s) {
	als := object.get(s.values, "access_log_settings", [])
	is_array(als)
	count(als) > 0
}

# Block present but pointing nowhere.
deny[msg] {
	s := resources[_]
	s.type == "aws_apigatewayv2_stage"
	als := s.values.access_log_settings[_]
	not als.destination_arn
	msg := sprintf("GAP-08 [164.312(b)]: %s access logging has no destination_arn", [s.address])
}

# Logging on, but the format records no caller identity.
deny[msg] {
	s := resources[_]
	s.type == "aws_apigatewayv2_stage"
	als := s.values.access_log_settings[_]
	is_string(als.format)
	not contains(als.format, "sourceIp")
	msg := sprintf("GAP-08 [164.312(b)]: %s access log format omits the caller IP; the record cannot attribute PHI access", [s.address])
}