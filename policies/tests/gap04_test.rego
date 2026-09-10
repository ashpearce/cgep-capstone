package compliance.hipaa.gap04

# --- failing fixtures ---

test_denies_bucket_with_no_versioning_resource {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
	}]}}}
}

# Suspended keeps old versions but silently stops creating new ones.
# The console still shows the bucket as versioned.
test_denies_versioning_suspended {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"values": {"versioning_configuration": [{"status": "Suspended"}]},
		},
	]}}}
}

test_denies_versioning_disabled {
	count(deny) > 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"values": {"versioning_configuration": [{"status": "Disabled"}]},
		},
	]}}}
}

# --- passing fixtures ---

test_allows_versioning_enabled {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"values": {"bucket": "acme-health-intake-uploads-8e35a7ab"},
		},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"values": {"versioning_configuration": [{"status": "Enabled"}]},
		},
	]}}}
}

test_ignores_non_phi_buckets {
	count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket.trail",
		"type": "aws_s3_bucket",
		"values": {"bucket": "acme-health-intake-cloudtrail-8e35a7ab"},
	}]}}}
}