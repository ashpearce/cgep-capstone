package compliance.hipaa.gap03

# --- failing fixtures ---

test_denies_bucket_with_no_policy {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
	}]}}}
}

test_denies_policy_without_secure_transport {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowLambdaWrite\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::670163018466:role/acme-health-intake-lambda\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::acme-health-intake-uploads-8e35a7ab/*\"}]}"},
		},
	]}}}
}

# The condition is present but attached to an Allow, which enforces nothing.
test_denies_secure_transport_without_deny {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowOverTls\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::acme-health-intake-uploads-8e35a7ab/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"true\"}}}]}"},
		},
	]}}}
}

# --- passing fixtures ---

test_allows_explicit_deny_on_insecure_transport {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::acme-health-intake-uploads-8e35a7ab\",\"arn:aws:s3:::acme-health-intake-uploads-8e35a7ab/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"},
		},
	]}}}
}

# The trail and evidence buckets are not PHI stores and are out of scope.
test_ignores_non_phi_buckets {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.trail",
		"type": "aws_s3_bucket",
		"values": {"bucket": "acme-health-intake-cloudtrail-8e35a7ab"},
	}]}}}
}