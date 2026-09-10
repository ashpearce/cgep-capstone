package compliance.hipaa.gap08

# --- failing fixtures ---

test_denies_stage_with_no_access_logging {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"values": {"name": "$default", "auto_deploy": true},
	}]}}}
}

test_denies_access_log_settings_null {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"values": {
			"name": "$default",
			"access_log_settings": null,
		},
	}]}}}
}

test_denies_logging_with_no_destination {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"values": {
			"name": "$default",
			"access_log_settings": [{"format": "{\"requestId\":\"$context.requestId\",\"ip\":\"$context.identity.sourceIp\"}"}],
		},
	}]}}}
}

# Logging is on and delivering, but the record cannot attribute PHI access
# to anyone. Satisfies "logging enabled" and implements no audit control.
test_denies_format_without_caller_identity {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"values": {
			"name": "$default",
			"access_log_settings": [{
				"destination_arn": "arn:aws:logs:us-east-1:670163018466:log-group:/aws/apigateway/acme-health-intake-8e35a7ab",
				"format": "{\"requestId\":\"$context.requestId\",\"status\":\"$context.status\",\"responseLength\":\"$context.responseLength\"}",
			}],
		},
	}]}}}
}

# --- passing fixture ---

test_allows_logging_with_caller_identity {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"values": {
			"name": "$default",
			"access_log_settings": [{
				"destination_arn": "arn:aws:logs:us-east-1:670163018466:log-group:/aws/apigateway/acme-health-intake-8e35a7ab",
				"format": "{\"requestId\":\"$context.requestId\",\"ip\":\"$context.identity.sourceIp\",\"requestTime\":\"$context.requestTime\",\"httpMethod\":\"$context.httpMethod\",\"routeKey\":\"$context.routeKey\",\"status\":\"$context.status\"}",
			}],
		},
	}]}}}
}