/**
 * Lambda function for the ClassGuard classifier.
 * 
 * The code is packaged from src/classifier/ (rules.py, bedrock.py, classify.py, handler.py)
 * and dependencies are installed before zipping.
 */

# Get the current AWS account ID
data "aws_caller_identity" "current" {}

# Archive the classifier source code + dependencies
data "archive_file" "lambda_code" {
  type        = "zip"
  source_dir  = local.classifier_src
  output_path = "${path.module}/lambda_deployment.zip"

  # Force re-zip if any .py file changes
  depends_on = [
    # You can list files here if needed, but source_dir watches all files
  ]
}

# The Lambda function
resource "aws_lambda_function" "classifier" {
  filename            = data.archive_file.lambda_code.output_path
  function_name       = "${local.common_name}-classifier"
  role                = aws_iam_role.lambda.arn
  handler             = local.lambda_handler
  source_code_hash    = data.archive_file.lambda_code.output_base64sha256
  runtime             = "python3.12"
  timeout             = 60
  memory_size         = 512

  environment {
    variables = local.lambda_env
  }

  tags = {
    Name = "${local.common_name}-classifier"
  }

  depends_on = [
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_s3,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_sns,
    aws_iam_role_policy.lambda_kms,
  ]
}

# CloudWatch log group for the Lambda (explicit, for cleaner cleanup)
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.classifier.function_name}"
  retention_in_days = 7

  tags = {
    Name = "${local.common_name}-lambda-logs"
  }
}

# Permission for EventBridge to invoke the Lambda
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.classifier.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/${local.common_name}-s3-ingest"
}
