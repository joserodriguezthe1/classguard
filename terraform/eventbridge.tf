/**
 * EventBridge rule that fires the Lambda whenever an object is created in the ingest bucket.
 * 
 * This replaces the older S3 event notification mechanism with EventBridge, which is
 * more flexible and integrates better with other AWS services.
 */

# Enable EventBridge notifications on the ingest bucket
resource "aws_s3_bucket_notification" "ingest" {
  bucket      = aws_s3_bucket.ingest.id
  eventbridge = true
}

# EventBridge rule: match S3:ObjectCreated events in the ingest bucket
resource "aws_cloudwatch_event_rule" "s3_ingest" {
  name        = "${local.common_name}-s3-ingest"
  description = "Trigger ClassGuard Lambda on S3 object creation in ingest bucket"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = {
        name = [aws_s3_bucket.ingest.id]
      }
    }
  })

  tags = {
    Name = "${local.common_name}-s3-ingest-rule"
  }
}

# EventBridge target: invoke the Lambda
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.s3_ingest.name
  target_id = "ClassGuardLambda"
  arn       = aws_lambda_function.classifier.arn

  # The event will be passed to Lambda as the 'event' parameter in the handler
  role_arn = aws_iam_role.eventbridge.arn
}

# IAM role for EventBridge to invoke Lambda
resource "aws_iam_role" "eventbridge" {
  name = "${local.common_name}-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.common_name}-eventbridge-role"
  }
}

# Policy for EventBridge to invoke Lambda
resource "aws_iam_role_policy" "eventbridge_lambda" {
  name = "${local.common_name}-eventbridge-lambda"
  role = aws_iam_role.eventbridge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.classifier.arn
      }
    ]
  })
}
