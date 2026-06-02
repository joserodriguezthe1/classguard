/**
 * IAM role for the ClassGuard Lambda function.
 * 
 * Permissions:
 *   - S3: Read from ingest, Write to classified/quarantine
 *   - DynamoDB: Write audit records
 *   - SNS: Publish alerts
 *   - KMS: Decrypt/encrypt for S3 and DynamoDB
 *   - CloudWatch: Write logs
 */

resource "aws_iam_role" "lambda" {
  name               = "${local.common_name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.common_name}-lambda-role"
  }
}

# CloudWatch Logs policy (Lambda needs to write logs)
resource "aws_iam_role_policy" "lambda_logs" {
  name   = "${local.common_name}-lambda-logs"
  role   = aws_iam_role.lambda.id
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
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/lambda/${local.common_name}-*"
      }
    ]
  })
}

# S3 policy: read from ingest, write to classified/quarantine
resource "aws_iam_role_policy" "lambda_s3" {
  name   = "${local.common_name}-lambda-s3"
  role   = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadIngest"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.ingest.arn}/*"
      },
      {
        Sid    = "WriteClassified"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectTagging",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.classified.arn}/*"
      },
      {
        Sid    = "WriteQuarantine"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.quarantine.arn}/*"
      },
      {
        Sid    = "DeleteIngest"
        Effect = "Allow"
        Action = [
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.ingest.arn}/*"
      }
    ]
  })
}

# DynamoDB policy: write audit records
resource "aws_iam_role_policy" "lambda_dynamodb" {
  name   = "${local.common_name}-lambda-dynamodb"
  role   = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.audit.arn
      }
    ]
  })
}

# SNS policy: publish alerts
resource "aws_iam_role_policy" "lambda_sns" {
  name   = "${local.common_name}-lambda-sns"
  role   = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

# KMS policy: decrypt S3 objects and encrypt/decrypt DynamoDB items
resource "aws_iam_role_policy" "lambda_kms" {
  name   = "${local.common_name}-lambda-kms"
  role   = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.s3.arn
      }
    ]
  })
}
