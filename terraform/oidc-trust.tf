# terraform/oidc-trust.tf
# Keyless CI identity. No static AWS credentials exist anywhere.
# HIPAA 164.312(d) — person or entity authentication.

# The provider already exists in this account (created in Lab 4.3).
# Data source, not resource: one provider per issuer per account.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "gate_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    # StringLike, because the immutable-ID format puts numeric IDs
    # in the middle of the claim. Confirm against the decoded token.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:ashpearce@*/cgep-capstone@*:*"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gate" {
  name               = "${local.name_prefix}-grc-gate"
  assume_role_policy = data.aws_iam_policy_document.gate_trust.json
}

# Broad, and named as such in the write-up. Apply-on-merge needs to
# manage the whole workload; scoping this properly is post-capstone work.
resource "aws_iam_role_policy_attachment" "gate_power" {
  role       = aws_iam_role.gate.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# PowerUserAccess excludes IAM, which apply needs for the Lambda role.
resource "aws_iam_role_policy" "gate_iam" {
  name = "iam-for-workload"
  role = aws_iam_role.gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetRole", "iam:PassRole", "iam:CreateRole", "iam:DeleteRole",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:GetRolePolicy", "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies", "iam:TagRole",
          "iam:ListInstanceProfilesForRole"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"
      },
      {
        Sid    = "ReadOidcProvider"
        Effect = "Allow"
        Action = [
          "iam:ListOpenIDConnectProviders",
          "iam:GetOpenIDConnectProvider"
        ]
        Resource = "*"
      }
    ]
  })
}

output "gate_role_arn" {
  value       = aws_iam_role.gate.arn
  description = "Set this as the AWS_ROLE_ARN repo variable."
}
