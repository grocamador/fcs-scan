# CloudGoat - Lambda Privilege Escalation Scenario
# This scenario demonstrates privilege escalation through Lambda functions

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

# Lambda execution role with excessive permissions
resource "aws_iam_role" "lambda_execution_role" {
  name = "cloudgoat-lambda-role-${var.cgid}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Overly permissive policy attached to Lambda role
resource "aws_iam_role_policy" "lambda_policy" {
  name = "cloudgoat-lambda-policy-${var.cgid}"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:*",
          "lambda:*",
          "s3:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM User with permission to invoke Lambda
resource "aws_iam_user" "lambda_invoker" {
  name = "cloudgoat-lambda-invoker-${var.cgid}"
  path = "/"
}

resource "aws_iam_access_key" "lambda_invoker_key" {
  user = aws_iam_user.lambda_invoker.name
}

resource "aws_iam_user_policy" "lambda_invoker_policy" {
  name = "cloudgoat-lambda-invoker-policy-${var.cgid}"
  user = aws_iam_user.lambda_invoker.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunction"
        ]
        Resource = aws_lambda_function.vulnerable_lambda.arn
      }
    ]
  })
}

# Vulnerable Lambda function
resource "aws_lambda_function" "vulnerable_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "cloudgoat-vulnerable-lambda-${var.cgid}"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime         = "python3.9"
  timeout         = 60

  environment {
    variables = {
      SECRET_FLAG = "cg-lambda-secret-${var.cgid}"
    }
  }
}

# Lambda function code
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "/tmp/lambda_function.zip"
  source {
    content = <<EOF
import json
import boto3
import os

def handler(event, context):
    # Vulnerable function that can be exploited for privilege escalation

    if 'command' in event:
        # Dangerous: executing user input without validation
        if event['command'] == 'get_flag':
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'flag': os.environ.get('SECRET_FLAG', 'flag not found')
                })
            }
        elif event['command'] == 'create_user':
            # Create IAM user with admin permissions (privilege escalation)
            iam = boto3.client('iam')
            try:
                username = event.get('username', 'escalated-user')

                # Create user
                iam.create_user(UserName=username)

                # Create access key
                response = iam.create_access_key(UserName=username)

                # Attach admin policy
                iam.attach_user_policy(
                    UserName=username,
                    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
                )

                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': 'User created with admin access',
                        'access_key': response['AccessKey']['AccessKeyId'],
                        'secret_key': response['AccessKey']['SecretAccessKey']
                    })
                }
            except Exception as e:
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': str(e)})
                }

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'CloudGoat Lambda Function',
            'usage': 'Send command parameter: get_flag or create_user'
        })
    }
EOF
    filename = "index.py"
  }
}

# S3 bucket for sensitive data
resource "aws_s3_bucket" "lambda_data" {
  bucket = "cloudgoat-lambda-data-${var.cgid}"
}

resource "aws_s3_object" "sensitive_data" {
  bucket = aws_s3_bucket.lambda_data.id
  key    = "sensitive/admin-credentials.txt"
  content = "Admin credentials: cg-admin-${var.cgid}"
}

# Outputs
output "lambda_invoker_access_key_id" {
  value = aws_iam_access_key.lambda_invoker_key.id
}

output "lambda_invoker_secret_access_key" {
  value     = aws_iam_access_key.lambda_invoker_key.secret
  sensitive = true
}

output "lambda_function_name" {
  value = aws_lambda_function.vulnerable_lambda.function_name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.lambda_data.id
}