/**
 * DynamoDB table for the classification audit ledger.
 * 
 * Records every classification decision: object key, tier, findings, AI result,
 * confidence, rationale. This is your forensic trail for compliance.
 */

resource "aws_dynamodb_table" "audit" {
  name           = var.audit_table_name
  billing_mode   = "PAY_PER_REQUEST"  # On-demand pricing (free tier friendly)
  hash_key       = "object_key"
  range_key      = "timestamp"

  attribute {
    name = "object_key"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  tags = {
    Name = "${local.common_name}-audit"
  }
}
