terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment to use S3 backend for state (requires bucket created first)
  # backend "s3" {
  #   bucket         = "YOUR-TERRAFORM-STATE-BUCKET"
  #   key            = "classguard/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      var.tags,
      {
        Environment = var.environment
      }
    )
  }
}

locals {
  common_name = "${var.project_name}-${var.environment}"

  # Lambda handler function name (must match src/classifier/handler.py lambda_handler)
  lambda_handler = "handler.handler"

  # Path to the classifier source code (relative to terraform directory)
  classifier_src = "${path.module}/../src/classifier"

  # Lambda environment variables (passed to the handler at runtime)
  lambda_env = {
    INGEST_BUCKET              = var.ingest_bucket_name
    CLASSIFIED_BUCKET          = var.classified_bucket_name
    QUARANTINE_BUCKET          = var.quarantine_bucket_name
    AUDIT_TABLE                = var.audit_table_name
    BEDROCK_ENABLED            = tostring(var.bedrock_enabled)
    BEDROCK_MODEL_ID           = var.bedrock_model_id
    BEDROCK_REGION             = var.aws_region
    AI_CONFIDENCE_THRESHOLD    = tostring(var.ai_confidence_threshold)
    MAX_OBJECT_SIZE            = tostring(var.max_object_size_bytes)
  }
}
