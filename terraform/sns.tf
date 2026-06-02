/**
 * SNS topic for alerts when classification fails or objects are quarantined.
 * 
 * If alert_email is set in variables, creates a subscription so alerts go to email.
 */

resource "aws_sns_topic" "alerts" {
  name = "${local.common_name}-alerts"

  tags = {
    Name = "${local.common_name}-alerts"
  }
}

# Optional: email subscription (only if alert_email is provided)
resource "aws_sns_topic_subscription" "alerts_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SNS topic policy: allow Lambda to publish
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}
