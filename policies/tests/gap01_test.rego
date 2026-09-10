package compliance.hipaa.gap01

# --- failing fixtures ---

test_denies_bucket_with_no_encryption_resource {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
	}]}}}
}

test_denies_sse_s3 {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
		},
	]}}}
}

test_denies_kms_without_key_arn {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
		},
	]}}}
}

# --- passing fixtures ---

test_allows_customer_cmk {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"values": {"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": "aws:kms",
				"kms_master_key_id": "arn:aws:kms:us-east-1:670163018466:key/4001bb87-dca3-43ee-9006-c7870469bf04",
			}]}]},
		},
	]}}}
}

# The evidence and CloudTrail buckets are deliberately SSE-S3 and hold no PHI.
# This proves the policy is scoped to the PHI store, not to a resource type.
test_ignores_non_phi_buckets {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.evidence",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
	}]}}}
}