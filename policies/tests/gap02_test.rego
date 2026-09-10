package compliance.hipaa.gap02

# --- failing fixtures ---

test_denies_table_with_no_sse_block {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {"name": "acme-health-intake-submissions-8e35a7ab"},
	}]}}}
}

test_denies_sse_disabled {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {
			"name": "acme-health-intake-submissions-8e35a7ab",
			"server_side_encryption": [{"enabled": false}],
		},
	}]}}}
}

# The realistic half-fix: encrypted, but with the AWS-managed key.
# This is what the red PR reintroduces.
test_denies_enabled_without_key_arn {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {
			"name": "acme-health-intake-submissions-8e35a7ab",
			"server_side_encryption": [{"enabled": true}],
		},
	}]}}}
}

# --- passing fixture ---

test_allows_customer_cmk {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {
			"name": "acme-health-intake-submissions-8e35a7ab",
			"server_side_encryption": [{
				"enabled": true,
				"kms_key_arn": "arn:aws:kms:us-east-1:670163018466:key/4001bb87-dca3-43ee-9006-c7870469bf04",
			}],
		},
	}]}}}
}