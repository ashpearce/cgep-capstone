# CAPSTONE: explicit least-privilege state access for the CI gate role.
# PowerUserAccess already permits this; the statement documents intent.
resource "aws_iam_role_policy" "grc_gate_state" {
  name = "terraform-state-access"
  role = "acme-health-intake-grc-gate"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListStateBucket"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::acme-health-intake-tfstate-8e35a7ab"
      },
      {
        Sid    = "ReadWriteStateObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::acme-health-intake-tfstate-8e35a7ab/capstone/terraform.tfstate",
          "arn:aws:s3:::acme-health-intake-tfstate-8e35a7ab/capstone/terraform.tfstate.tflock"
        ]
      }
    ]
  })
}