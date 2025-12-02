# CloudGoat - IAM Privilege Escalation by Rollback Scenario
# This scenario demonstrates IAM privilege escalation through policy version rollback

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cgid" {
  description = "CloudGoat ID"
  type        = string
}

# IAM User with limited initial permissions
resource "aws_iam_user" "target_user" {
  name = "cloudgoat-target-user-${var.cgid}"
  path = "/"
}

resource "aws_iam_access_key" "target_user_key" {
  user = aws_iam_user.target_user.name
}

# IAM Policy with intentionally insecure configuration
resource "aws_iam_policy" "vulnerable_policy" {
  name        = "cloudgoat-vulnerable-policy-${var.cgid}"
  description = "Vulnerable policy for privilege escalation demonstration"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:SetDefaultPolicyVersion",
          "iam:CreatePolicyVersion"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.target_bucket.arn,
          "${aws_s3_bucket.target_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "target_user_policy" {
  user       = aws_iam_user.target_user.name
  policy_arn = aws_iam_policy.vulnerable_policy.arn
}

# S3 Bucket with sensitive data
resource "aws_s3_bucket" {
  bucket = "cloudgoat-sensitive-data-${var.cgid}"
}

resource "aws_s3_bucket_versioning" "target_bucket_versioning" {
  bucket = aws_s3_bucket.target_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "target_bucket_pab" {
  bucket = aws_s3_bucket.target_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_object" "secret_file" {
  bucket = aws_s3_bucket.target_bucket.id
  key    = "secret-flag.txt"
  content = "cg-secret-${var.cgid}-flag"
}

# Output credentials for testing
output "target_user_access_key_id" {
  value = aws_iam_access_key.target_user_key.id
}

output "target_user_secret_access_key" {
  value     = aws_iam_access_key.target_user_key.secret
  sensitive = true
}

output "s3_bucket_name" {
  value = aws_s3_bucket.target_bucket.id
}