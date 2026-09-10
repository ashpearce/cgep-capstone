# terraform/hardening.tf
# Gap closures that attach to the starter's resources from outside.

##############################################################
# GAP-01 — SSE-KMS with the customer CMK on the uploads bucket.
# HIPAA 164.312(a)(2)(iv). Replaces the AWS-managed SSE-S3 default.
##############################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

##############################################################
# GAP-04 — versioning, so a PHI overwrite is recoverable.
# HIPAA 164.308(a)(7) — contingency plan / data backup.
##############################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

##############################################################
# GAP-03 — deny any request that isn't over TLS.
# HIPAA 164.312(e)(1) — transmission security.
##############################################################

data "aws_iam_policy_document" "uploads_tls" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.uploads.arn,
      "${aws_s3_bucket.uploads.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads_tls.json
}

##############################################################
# GAP-05 — Lambda inside the VPC, with a private path to data.
# HIPAA 164.312(e)(1) — transmission security.
#
# The starter's private subnets have no route table and no NAT.
# Gateway endpoints give S3 and DynamoDB a private path at no cost.
##############################################################

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = { Name = "${local.name_prefix}-s3-endpoint" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

# Egress-only security group. The Lambda initiates; nothing calls it.
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Intake Lambda egress to AWS services via gateway endpoints"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS service endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

##############################################################
# GAP-08 — API Gateway access logging.
# HIPAA 164.312(b) — audit controls: record and examine activity
# in systems containing PHI.
##############################################################

resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 90
}
