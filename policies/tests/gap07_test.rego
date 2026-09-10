package compliance.hipaa.gap07

# --- failing fixtures: the starter's original grants ---

test_denies_dynamodb_wildcard {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"type": "aws_iam_role_policy",
		"values": {
			"name": "intake-data-access",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"arn:aws:dynamodb:us-east-1:670163018466:table/acme-health-intake-submissions-8e35a7ab\"}]}",
		},
	}]}}}
}

test_denies_s3_wildcard {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"type": "aws_iam_role_policy",
		"values": {
			"name": "intake-data-access",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::acme-health-intake-uploads-8e35a7ab/*\"}]}",
		},
	}]}}}
}

test_denies_total_wildcard {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"type": "aws_iam_role_policy",
		"values": {
			"name": "intake-data-access",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
		},
	}]}}}
}

# A wildcard on a service the starter never used — caught by shape, not by name.
test_denies_unanticipated_service_wildcard {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"type": "aws_iam_role_policy",
		"values": {
			"name": "intake-data-access",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"kms:*\",\"Resource\":\"arn:aws:kms:us-east-1:670163018466:key/4001bb87-dca3-43ee-9006-c7870469bf04\"}]}",
		},
	}]}}}
}

# --- passing fixtures ---

# The two calls handler.py actually makes, plus the KMS operations the CMK
# encryption requires.
test_allows_derived_least_privilege {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"type": "aws_iam_role_policy",
		"values": {
			"name": "intake-data-access",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"WriteSubmissions\",\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\"],\"Resource\":\"arn:aws:dynamodb:us-east-1:670163018466:table/acme-health-intake-submissions-8e35a7ab\"},{\"Sid\":\"WriteUploads\",\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\"],\"Resource\":\"arn:aws:s3:::acme-health-intake-uploads-8e35a7ab/*\"},{\"Sid\":\"UseCmkForPhiAtRest\",\"Effect\":\"Allow\",\"Action\":[\"kms:Encrypt\",\"kms:Decrypt\",\"kms:GenerateDataKey\",\"kms:DescribeKey\"],\"Resource\":\"arn:aws:kms:us-east-1:670163018466:key/4001bb87-dca3-43ee-9006-c7870469bf04\"}]}",
		},
	}]}}}
}

# The pipeline's own gate role is deliberately broad and documented as such.
# This proves the policy is scoped to the workload, not to a resource type.
test_ignores_pipeline_gate_role {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.gate_iam",
		"type": "aws_iam_role_policy",
		"values": {
			"name": "iam-for-workload",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"iam:*\",\"Resource\":\"arn:aws:iam::670163018466:role/acme-health-intake-*\"}]}",
		},
	}]}}}
}