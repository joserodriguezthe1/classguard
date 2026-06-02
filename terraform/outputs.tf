/**
 * Outputs: printed after terraform apply succeeds.
 * 
 * These tell you the resource names and ARNs for reference, testing, and documentation.
 */

output "ingest_bucket_name" {
  description = "Name of the ingest bucket where files are uploaded"
  value       = aws_s3_bucket.ingest.id
}

output "ingest_bucket_arn" {
  description = "ARN of the ingest bucket"
  value       = aws_s3_bucket.ingest.arn
}

output "classified_bucket_name" {
  description = "Name of the classified bucket (where files go after tagging)"
  value       = aws_s3_bucket.classified.id
}

output "classified_bucket_arn" {
  description = "ARN of the classified bucket"
  value       = aws_s3_bucket.classified.arn
}

output "quarantine_bucket_name" {
  description = "Name of the quarantine bucket (where failed objects go)"
  value       = aws_s3_bucket.quarantine.id
}

output "quarantine_bucket_arn" {
  description = "ARN of the quarantine bucket"
  value       = aws_s3_bucket.quarantine.arn
}

output "lambda_function_name" {
  description = "Name of the ClassGuard Lambda function"
  value       = aws_lambda_function.classifier.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.classifier.arn
}

output "lambda_log_group" {
  description = "CloudWatch log group for the Lambda (view logs here after uploads)"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "audit_table_name" {
  description = "DynamoDB table for classification audit ledger"
  value       = aws_dynamodb_table.audit.name
}

output "audit_table_arn" {
  description = "ARN of the audit table"
  value       = aws_dynamodb_table.audit.arn
}

output "sns_topic_arn" {
  description = "SNS topic for alerts (if alerts are enabled)"
  value       = aws_sns_topic.alerts.arn
}

output "kms_key_id" {
  description = "KMS key ID for S3 bucket encryption"
  value       = aws_kms_key.s3.id
}

output "eventbridge_rule_name" {
  description = "EventBridge rule that triggers the Lambda"
  value       = aws_cloudwatch_event_rule.s3_ingest.name
}

output "next_steps" {
  description = "What to do now that infrastructure is deployed"
  value = <<-EOT
    ✓ Infrastructure deployed successfully!

    Next steps:

    1. SUBSCRIBE TO ALERTS (if you set alert_email):
       Check your email for the SNS subscription confirmation and click the link.

    2. TEST THE PIPELINE:
       Upload a test file to the ingest bucket:
       
       aws s3 cp test.txt s3://${aws_s3_bucket.ingest.id}/

    3. MONITOR EXECUTION:
       View Lambda logs:
       aws logs tail ${aws_cloudwatch_log_group.lambda.name} --follow

    4. VERIFY CLASSIFICATION:
       Check the classified bucket for tagged objects:
       aws s3api list-objects-v2 --bucket ${aws_s3_bucket.classified.id} --query 'Contents[0]'
       aws s3api get-object-tagging --bucket ${aws_s3_bucket.classified.id} --key <object-key>

    5. ENABLE BEDROCK (optional):
       Once you have Bedrock model access in your account:
       - Edit terraform.tfvars: set bedrock_enabled = true, bedrock_model_id = "us.anthropic.claude-..."
       - Run: terraform apply
       - Lambda will now use AI to augment the rules-based classification

    6. AUDIT TRAIL:
       Query the DynamoDB audit table:
       aws dynamodb scan --table-name ${aws_dynamodb_table.audit.name}
  EOT
}
