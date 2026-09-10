package compliance.hipaa.gap05

# --- failing fixtures ---

test_denies_lambda_with_no_vpc_config {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"values": {"function_name": "acme-health-intake-handler-8e35a7ab"},
	}]}}}
}

# vpc_config present but null — the shape that made an earlier version of
# this policy silently not match.
test_denies_vpc_config_null {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"values": {
			"function_name": "acme-health-intake-handler-8e35a7ab",
			"vpc_config": null,
		},
	}]}}}
}

test_denies_vpc_config_with_no_subnets {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"values": {
			"function_name": "acme-health-intake-handler-8e35a7ab",
			"vpc_config": [{
				"subnet_ids": [],
				"security_group_ids": ["sg-0123456789abcdef0"],
			}],
		},
	}]}}}
}

test_denies_vpc_config_with_no_security_group {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"values": {
			"function_name": "acme-health-intake-handler-8e35a7ab",
			"vpc_config": [{
				"subnet_ids": ["subnet-02624fd7c537d7587", "subnet-08af4fb261c9fb215"],
				"security_group_ids": [],
			}],
		},
	}]}}}
}

# --- passing fixture ---

test_allows_lambda_in_private_subnets {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"values": {
			"function_name": "acme-health-intake-handler-8e35a7ab",
			"vpc_config": [{
				"subnet_ids": ["subnet-02624fd7c537d7587", "subnet-08af4fb261c9fb215"],
				"security_group_ids": ["sg-0123456789abcdef0"],
			}],
		},
	}]}}}
}