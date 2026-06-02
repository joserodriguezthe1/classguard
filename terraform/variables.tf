variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name, used for resource naming and tagging"
  type        = string
  default     = "classguard"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "ingest_bucket_name" {
  description = "Name of the ingest bucket (must be globally unique)"
  type        = string
  # default = "classguard-ingest-YOUR-ACCOUNT-ID" -- you must customize this
}

variable "classified_bucket_name" {
  description = "Name of the classified bucket (must be globally unique)"
  type        = string
  # default = "classguard-classified-YOUR-ACCOUNT-ID"
}

variable "quarantine_bucket_name" {
  description = "Name of the quarantine bucket (must be globally unique)"
  type        = string
  # default = "classguard-quarantine-YOUR-ACCOUNT-ID"
}

variable "audit_table_name" {
  description = "Name of the DynamoDB audit ledger table"
  type        = string
  default     = "classification-audit"
}

variable "alert_email" {
  description = "Email address for SNS alerts when classification fails"
  type        = string
  default     = ""
}

variable "bedrock_enabled" {
  description = "Enable the Bedrock AI classification layer (requires model access in your account)"
  type        = bool
  default     = false
}

variable "bedrock_model_id" {
  description = "Bedrock model ID to use (e.g., us.anthropic.claude-opus-4-20250805). Leave empty if bedrock_enabled=false"
  type        = string
  default     = ""
}

variable "ai_confidence_threshold" {
  description = "Minimum confidence (0.0-1.0) for AI to auto-upgrade classification; below this, flags for human review"
  type        = number
  default     = 0.6
}

variable "max_object_size_bytes" {
  description = "Maximum file size to process (larger files quarantined)"
  type        = number
  default     = 1048576  # 1 MB
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project  = "ClassGuard"
    Managed  = "Terraform"
    Purpose  = "Data Classification & Labeling"
  }
}
