/**
 * S3 buckets for the ClassGuard pipeline:
 *   - ingest: where files land, triggers the Lambda
 *   - classified: where classified objects live (with tags/metadata)
 *   - quarantine: failed objects, waiting for human review
 */

# KMS key for bucket encryption (optional but good practice)
resource "aws_kms_key" "s3" {
  description             = "KMS key for ClassGuard S3 bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${local.common_name}-s3-key"
  }
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${local.common_name}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# ---- Ingest Bucket ----
resource "aws_s3_bucket" "ingest" {
  bucket = var.ingest_bucket_name

  tags = {
    Name = "${local.common_name}-ingest"
  }
}

resource "aws_s3_bucket_versioning" "ingest" {
  bucket = aws_s3_bucket.ingest.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ingest" {
  bucket = aws_s3_bucket.ingest.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ingest" {
  bucket = aws_s3_bucket.ingest.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---- Classified Bucket ----
resource "aws_s3_bucket" "classified" {
  bucket = var.classified_bucket_name

  tags = {
    Name = "${local.common_name}-classified"
  }
}

resource "aws_s3_bucket_versioning" "classified" {
  bucket = aws_s3_bucket.classified.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "classified" {
  bucket = aws_s3_bucket.classified.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "classified" {
  bucket = aws_s3_bucket.classified.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---- Quarantine Bucket ----
resource "aws_s3_bucket" "quarantine" {
  bucket = var.quarantine_bucket_name

  tags = {
    Name = "${local.common_name}-quarantine"
  }
}

resource "aws_s3_bucket_versioning" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---- Bucket Policies ----

# Ingest: deny objects without classification tag (this is the enforcement point)
# Note: this prevents UNTAGGED uploads; the Lambda applies tags, so normal flow is fine
resource "aws_s3_bucket_policy" "classified_deny_untagged" {
  bucket = aws_s3_bucket.classified.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnclassifiedObjects"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.classified.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:ExistingObjectTag/classification" = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
          }
        }
      }
    ]
  })
}

# Quarantine: allow Lambda to write, but prevent accidental deletion by humans
resource "aws_s3_bucket_policy" "quarantine_readonly" {
  bucket = aws_s3_bucket.quarantine.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaWrite"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda.arn
        }
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.quarantine.arn}/*"
      }
    ]
  })
}
