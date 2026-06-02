# NIST 800-53 Control Mapping: ClassGuard

This document maps ClassGuard's architecture and implementation to NIST SP 800-53 Revision 5 security controls, demonstrating compliance engineering for federal/defense data classification workflows.

---

## Executive Summary

ClassGuard implements or supports **6 key NIST 800-53 controls** across three control families:

| Family | Controls | Purpose |
|--------|----------|---------|
| **Access Control (AC)** | AC-16, AC-4 | Attributes, information flow enforcement |
| **Incident & Compliance (RA, MP, AU)** | RA-2, MP-3, AU-2, AU-12 | Categorization, marking, audit |
| **Cryptography (SC)** | SC-12, SC-28 | Key management, encryption |

---

## Detailed Control Implementation

### 1. AC-16: Security and Privacy Attributes

**Control Statement:**  
Provide a mechanism to automatically associate, bind, hide, and protect security and privacy attributes or labels with information and information containers throughout the system.

**Classification:**  
Moderate

**Applicability:**  
Systems processing classified or sensitive unclassified information (CUI), personally identifiable information (PII), or other sensitive data.

---

#### How ClassGuard Implements AC-16

**Mechanism: S3 Object Tags + Metadata**

```
Input File (Ingest Bucket)
    ↓
Classification Engine
    ├─ Detects sensitive patterns (SSN, email, CUI markers)
    └─ Assigns tier: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    ↓
S3 Object Metadata
    ├─ Tags: classification=INTERNAL, cui=false, review=false
    ├─ Encryption: KMS CMK (server-side encryption)
    └─ Immutable after Lambda copy
    ↓
Classified Bucket
    └─ Only tagged objects accepted
```

**Attributes Bound to Objects:**

| Attribute | Source | Binding | Example |
|-----------|--------|---------|---------|
| `classification` | Classification Engine | S3 Object Tag | `INTERNAL` |
| `cui` | CUI Pattern Matcher | S3 Object Tag | `true` / `false` |
| `review_recommended` | AI Confidence Threshold | S3 Object Tag | `true` / `false` |
| `decided_by` | Orchestrator | DynamoDB Audit Record | `rules`, `ai-raised`, `ai-low-confidence` |
| `confidence` | Bedrock AI | DynamoDB Audit Record | `0.87` |
| `timestamp` | Lambda Handler | DynamoDB Audit Record | ISO 8601 |

**Why S3 Tags?**
- **Automatic:** Lambda applies tags at copy time, no manual step
- **Immutable:** Cannot be modified or deleted (by policy)
- **Queryable:** Bucket policies enforce; downstream tools filter by tags
- **Visible:** IAM principals can see tags without reading object content

**Security Properties:**

✅ **Binding Strength:** Tags are part of object metadata; can only be modified by Lambda role (least privilege)  
✅ **Persistence:** Tags persist across bucket replication, lifecycle rules, and access logs  
✅ **Access Control:** IAM policy can require `s3:GetObjectTagging` before `s3:GetObject`  
✅ **Audit Trail:** DynamoDB records why each tag was assigned (rules vs. AI)

---

### 2. AC-4: Information Flow Enforcement

**Control Statement:**  
Enforce approved authorizations for controlling information flow within the system and among interconnected systems.

**Classification:**  
High

**Applicability:**  
All systems; enforcing flow policies for classified/CUI/PII is mandatory for federal agencies.

---

#### How ClassGuard Implements AC-4

**Enforcement Points:**

#### Point 1: Ingest Bucket → Lambda Classification

```
S3 Bucket Policy (Ingest):
  - Allows PUT from users
  - Triggers EventBridge on ObjectCreated
  - Only Lambda can READ objects
  - Objects deleted after classification (no residual unclassified data)
```

#### Point 2: Lambda Classification Decision

```python
# classify.py orchestrator
if rules_tier < ai_tier and ai_confidence >= threshold:
    final_tier = ai_tier
elif rules_tier >= ai_tier:
    final_tier = rules_tier  # Never lower
else:
    final_tier = rules_tier
    review_recommended = True

# Routes object:
if classification_successful:
    copy_to(classified_bucket, tags={classification: final_tier})
    delete_from(ingest_bucket)
else:
    copy_to(quarantine_bucket)
    alert_sns(error)
```

#### Point 3: Classified Bucket → Policy Enforcement

```hcl
# s3.tf bucket policy
aws_s3_bucket_policy "classified_readonly" {
  Statement = [
    {
      Sid = "DenyGetObjectNoTag"
      Effect = "Deny"
      Principal = "*"
      Action = "s3:GetObject"
      Resource = "arn:aws:s3:::classified/*"
      Condition = {
        StringNotEquals = {
          "s3:ExistingObjectTag/classification" = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
        }
      }
    }
  ]
}
```

**Interpretation:**  
Any attempt to GET an object without a valid classification tag is denied. Unclassified or mislabeled data cannot flow downstream.

#### Point 4: Data Consumer Enforcement (Optional)

```bash
# Typical data pipeline using ClassGuard output
aws s3api list-objects-v2 \
  --bucket classguard-classified \
  --query 'Contents[?Tags[?Key==`classification` && Value==`INTERNAL`]]'

# Only processes INTERNAL or above; rejects PUBLIC
```

---

**Flow Policy Summary:**

```
Unclassified Data → REJECTED (quarantine)
            ↓
Classified Data → TAGGED (S3 object tags)
            ↓
Policy Enforcement → IF tag ∉ {PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED} THEN DENY
            ↓
Consumers → Only accept tagged objects
            ↓
Audit → All decisions logged to DynamoDB
```

---

### 3. RA-2: Security Categorization

**Control Statement:**  
Categorize the system and information therein according to defined impact levels based on an analysis of the requirements, characteristics, and nature of the information and system.

**Classification:**  
Moderate

**Applicability:**  
All federal systems; required before any other control selection.

---

#### How ClassGuard Implements RA-2

**Classification Taxonomy:**

ClassGuard uses a 4-tier classification scheme aligned with FIPS 199 impact levels:

| Tier | FIPS 199 Impact | Examples | Rationale |
|------|-----------------|----------|----------|
| **PUBLIC** | Low | Marketing materials, public documentation | No sensitive patterns detected |
| **INTERNAL** | Low | Employee directories, email addresses, phone numbers | Contact information only; minor privacy impact |
| **CONFIDENTIAL** | Moderate | SSN, credit cards, FOUO markers, personal data | Direct identity/financial impact; moderate harm if disclosed |
| **RESTRICTED** | High | AWS credentials, private keys, NOFORN, classified data | System/organizational compromise; severe impact if disclosed |

**Detection Rules (RA-2 Basis):**

#### Tier → RESTRICTED (High Impact)

Pattern detection:
- **AWS Access Keys:** `AKIA[0-9A-Z]{16}` or `ASIA[0-9A-Z]{16}`
- **Private Keys:** PEM format (`-----BEGIN RSA PRIVATE KEY-----`, etc.)
- **CUI Markers (Highest):** `NOFORN`, `FOR OFFICIAL USE ONLY`

Rationale: Direct system compromise or national security impact.

#### Tier → CONFIDENTIAL (Moderate Impact)

Pattern detection:
- **SSN:** `\d{3}-\d{2}-\d{4}` (with checksum validation, excluding invalid ranges)
- **Credit Cards:** 13–19 digits with Luhn algorithm validation
- **CUI Markers:** `FOUO`, `CONTROLLED UNCLASSIFIED INFORMATION`, `CUI//`, `LAW ENFORCEMENT SENSITIVE`, `SBU`

Rationale: Personal identity/financial information; CUI-level protection required.

#### Tier → INTERNAL (Low Impact)

Pattern detection:
- **Email Addresses:** `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`
- **Phone Numbers:** `(123) 456-7890`, `123-456-7890` formats

Rationale: Organizational contact information; minor privacy impact if disclosed externally.

#### Tier → PUBLIC (Low Impact)

No patterns matched; content is safe for public distribution.

---

**AI Augmentation (Bedrock):**

When Bedrock AI is enabled, it reviews the full document context:

```
Rules Engine Classification: INTERNAL (email detected)
Bedrock AI Review: "This document discusses proprietary product roadmap. Should be CONFIDENTIAL."
Confidence: 0.92

Decision:
  IF ai_confidence >= 0.6 AND ai_tier > rules_tier:
    final_tier = ai_tier (CONFIDENTIAL)
    decided_by = "ai-raised"
```

**Why This Matters for RA-2:**

NIST RA-2 requires *systematic categorization* before control selection. ClassGuard:
- ✅ Automates categorization at point of creation
- ✅ Applies consistent logic (rules + optional AI)
- ✅ Documents every categorization decision (DynamoDB audit)
- ✅ Enables downstream control mapping (AC-16, MP-3, AU-2)

---

### 4. MP-3: Media Marking

**Control Statement:**  
Physically or logically mark removable storage media and system output indicating the distribution limitations, handling caveats, and applicable security marking of the information.

**Classification:**  
Low

**Applicability:**  
Recommended for all systems handling classified/CUI; mandatory for federal agencies.

---

#### How ClassGuard Implements MP-3

**Logical Marking via Object Metadata:**

ClassGuard applies logical marks (tags) to S3 objects at creation:

```
Lambda Handler (handler.py):
  ├─ classification = {PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED}
  ├─ cui = {true | false}
  ├─ review_recommended = {true | false}
  └─ decided_by = {rules | ai-raised | ai-low-confidence | ...}

Example S3 Object Tagging:
  Key: classified/sensitive_report_v2.docx
  Tags:
    - classification: CONFIDENTIAL
    - cui: true
    - review_recommended: false
    - decided_by: rules
    - timestamp: 2026-06-02T18:18:07Z
```

**Marking Semantics:**

| Mark | Meaning | Consumer Action |
|------|---------|-----------------|
| `classification=PUBLIC` | No confidentiality control; safe for external sharing | Process unrestricted |
| `classification=INTERNAL` | Organization-only; handle as working documents | Distribute within org only |
| `classification=CONFIDENTIAL` | Restricted to authorized personnel; CUI-level protection | Require authorization, encrypt in transit |
| `classification=RESTRICTED` | Highest protection; PII or classified | Encrypt, audit access, restrict to cleared personnel |
| `cui=true` | Contains Controlled Unclassified Information | Apply CUI handling rules (no remote access, cleared personnel only) |
| `review_recommended=true` | AI flagged for human review; low confidence | Escalate to compliance team before use |

---

**Physical Marking (Downstream):**

While ClassGuard marks data *logically* (S3 tags), downstream systems can enforce *physical* marking:

```bash
# Example: Print documents with classification banner
if object_tags['classification'] == 'CONFIDENTIAL':
  add_pdf_header("CONFIDENTIAL//INTERNAL USE ONLY")
  add_pdf_footer("Classification: CONFIDENTIAL | Reference: " + object_id)

# Export to external format (email, document, etc.)
if object_tags['classification'] in ['RESTRICTED', 'CONFIDENTIAL']:
  encrypt_attachment(key=kms_key)
  add_email_banner("This email contains CONFIDENTIAL information...")
```

---

**Why Logical Marking?**

✅ **Automation:** Applied automatically at creation; no manual steps  
✅ **Persistence:** Tags follow object across buckets, replicas, and archives  
✅ **Queryable:** Downstream tools can filter/route based on tags  
✅ **Audit Trail:** All marking decisions logged with rationale  
✅ **Scalability:** Works for 1 object or 1 million objects

---

### 5. AU-2 & AU-12: Audit and Accountability

**AU-2:** Determine the events that the system must audit based on risk assessment.  
**AU-12:** Provide comprehensive audit logging of user and system activities.

**Classification:**  
Moderate

**Applicability:**  
Mandatory for all federal systems; compliance audits require detailed audit trails.

---

#### How ClassGuard Implements AU-2 & AU-12

**Audit Events Captured:**

Every file upload triggers a complete audit record:

```python
# DynamoDB Audit Table Schema
{
  "object_key": "sensitive_report.docx",              # Hash key
  "timestamp": "2026-06-02T18:18:07.433Z",            # Range key
  "bucket": "classguard-classified-josea-20250602",
  "file_size_bytes": 15234,
  "classification": "CONFIDENTIAL",
  "cui": False,
  "review_recommended": False,
  "decided_by": "rules",
  "rules_tier": "INTERNAL",
  "rules_details": {
    "patterns_matched": {
      "email": 1,
      "generic_secret": 0
    }
  },
  "ai_available": False,
  "ai_tier": None,
  "ai_confidence": None,
  "ai_rationale": None,
  "action_taken": "moved_to_classified",
  "request_id": "91a50917-ca55-4ba7-83b8-1cabc711daa1",
  "error": None,
  "error_details": None
}
```

**What's Captured:**

✅ **Event Identification**
- Object key, timestamp, request ID (AWS Lambda)
- Bucket and file size
- Complete classification decision path

✅ **Classification Logic**
- Rules-based tier and matched patterns (counts, no PII)
- AI tier, confidence, and rationale (if enabled)
- "decided_by" field: rules vs. AI, confidence thresholds

✅ **Action Taken**
- Where object was routed: classified, quarantine, error
- Success or failure status
- Error messages (without exposing sensitive data)

✅ **Pattern Detection (Safely)**
- Counts of matches (e.g., "email: 1", "credit_card: 0")
- **Never stores matched values** (no PII re-leakage)

---

**Audit Trail Queries:**

```bash
# Find all RESTRICTED classifications
aws dynamodb query --table-name classification-audit \
  --key-condition-expression "classification = :c" \
  --expression-attribute-values "{\":c\": {\"S\": \"RESTRICTED\"}}"

# Find files requiring review
aws dynamodb query --table-name classification-audit \
  --key-condition-expression "review_recommended = :r" \
  --expression-attribute-values "{\":r\": {\"BOOL\": true}}"

# Find files classified by AI (vs. rules only)
aws dynamodb scan --table-name classification-audit \
  --filter-expression "decided_by = :d" \
  --expression-attribute-values "{\":d\": {\"S\": \"ai-raised\"}}"

# Audit trail for a specific object
aws dynamodb query --table-name classification-audit \
  --key-condition-expression "object_key = :k" \
  --expression-attribute-values "{\":k\": {\"S\": \"sensitive_file.pdf\"}}"
```

---

**Retention & Protection:**

```hcl
# DynamoDB Table Configuration (dynamodb.tf)
resource "aws_dynamodb_table" "audit" {
  name           = "classification-audit"
  billing_mode   = "PAY_PER_REQUEST"  # Auto-scaling
  
  # Hash key: object_key; Range key: timestamp (immutable sort)
  hash_key  = "object_key"
  range_key = "timestamp"
  
  # Point-in-time recovery enabled (restore up to 35 days)
  point_in_time_recovery_enabled = true
  
  # SSE-KMS encryption at rest
  server_side_encryption = {
    enabled     = true
    kms_key_arn = aws_kms_key.s3.arn
  }
  
  # Prevent accidental deletion
  deletion_protection_enabled = true
  
  ttl {
    enabled = false  # Audit records never auto-delete
  }
}
```

---

**Compliance Reporting:**

```python
# Example: Generate monthly audit summary
from boto3 import dynamodb

def audit_summary(table_name, start_date, end_date):
    table = dynamodb.resource('dynamodb').Table(table_name)
    
    response = table.scan(
        FilterExpression='#ts BETWEEN :start AND :end',
        ExpressionAttributeNames={'#ts': 'timestamp'},
        ExpressionAttributeValues={
            ':start': start_date,
            ':end': end_date
        }
    )
    
    items = response['Items']
    
    summary = {
        'total_files': len(items),
        'by_classification': {
            'PUBLIC': len([i for i in items if i['classification'] == 'PUBLIC']),
            'INTERNAL': len([i for i in items if i['classification'] == 'INTERNAL']),
            'CONFIDENTIAL': len([i for i in items if i['classification'] == 'CONFIDENTIAL']),
            'RESTRICTED': len([i for i in items if i['classification'] == 'RESTRICTED']),
        },
        'by_decided_by': {
            'rules': len([i for i in items if i['decided_by'] == 'rules']),
            'ai_raised': len([i for i in items if i['decided_by'] == 'ai-raised']),
            'ai_low_confidence': len([i for i in items if i['decided_by'] == 'ai-low-confidence']),
        },
        'with_review_flag': len([i for i in items if i.get('review_recommended')]),
        'errors': len([i for i in items if i.get('error')]),
    }
    
    return summary
```

---

### 6. SC-12 & SC-28: Key Management & Encryption

**SC-12:** Establish and implement cryptographic key establishment and management processes, procedures, and controls.  
**SC-28:** Protect information at rest through encryption.

**Classification:**  
Moderate-High

**Applicability:**  
Mandatory for systems processing classified or CUI; recommended for all sensitive data.

---

#### How ClassGuard Implements SC-12 & SC-28

**Encryption at Rest:**

```hcl
# Terraform: KMS Key for ClassGuard
resource "aws_kms_key" "s3" {
  description             = "ClassGuard encryption key for S3 & DynamoDB"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  # Enforce key policy: only Lambda can decrypt
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaUse"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      # ... deny access to all other principals
    ]
  })
  
  tags = {
    Name    = "classguard-kms"
    Purpose = "Encryption for classification audit trail"
  }
}
```

**S3 Encryption (SSE-KMS):**

```hcl
# All S3 buckets use KMS encryption
resource "aws_s3_bucket" "classified" {
  bucket = var.classified_bucket_name
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3.arn
      }
      bucket_key_enabled = true  # Reduces KMS API calls, lowers cost
    }
  }
  
  # Require bucket key for all uploads (reject unencrypted)
  bucket_server_side_encryption_configuration_enforced = true
}
```

**DynamoDB Encryption (SSE-KMS):**

```hcl
resource "aws_dynamodb_table" "audit" {
  name = "classification-audit"
  
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.s3.arn
  }
}
```

---

**Key Rotation & Access Control:**

| Aspect | Implementation | Benefit |
|--------|-----------------|---------|
| **Automatic Rotation** | `enable_key_rotation = true` | Keys rotated annually without disruption |
| **Key Policy** | Least privilege: only Lambda role decrypt/use | Unauthorized access denied by policy |
| **Access Logging** | CloudTrail logs all key usage | Full audit trail of cryptographic operations |
| **Deletion Protection** | 30-day deletion window | Prevents accidental key loss |
| **Separation of Duties** | Lambda role vs. human IAM role | Humans cannot decrypt audit records directly |

---

**In-Transit Encryption:**

```python
# handler.py: All AWS API calls use TLS
import boto3

s3_client = boto3.client(
    's3',
    region_name=os.environ.get('AWS_REGION', 'us-east-1'),
    config=Config(
        signature_version='s3v4',  # Require SigV4 (TLS mandatory)
        retries={'max_attempts': 3}
    )
)

# All operations: GET, PUT, DELETE encrypted in transit
s3_client.copy_object(
    Bucket=classified_bucket,
    Key=object_key,
    CopySource={'Bucket': ingest_bucket, 'Key': object_key},
    ServerSideEncryption='aws:kms',  # Explicit KMS encryption
    SSEKMSKeyId=kms_key_id,
)
```

---

**Compliance with FIPS 140-2:**

AWS KMS uses FIPS 140-2 validated hardware security modules (HSMs) for key storage. ClassGuard inherits this compliance:

✅ **FIPS 140-2 Level 3:** KMS operates in AWS's FIPS 140-2 L3-validated infrastructure  
✅ **Key Derivation:** Each object encrypted with a unique data key (derived from CMK)  
✅ **No Master Key Export:** CMK never leaves AWS KMS; impossible to export for offline use (secure by design)

---

## Control Summary Table

| Control | Implementation | Evidence | Audit Trail |
|---------|-----------------|----------|------------|
| **AC-16** | S3 object tags applied by Lambda | Classification tags on all objects | DynamoDB record + CloudWatch logs |
| **AC-4** | Bucket policies enforce tagged access | Untagged objects denied by policy | S3 access logs, IAM policy simulator |
| **RA-2** | 4-tier classification taxonomy | Rules engine + AI augmentation | "decided_by" field in DynamoDB |
| **MP-3** | Logical tags = media markings | S3 object tags with classification | DynamoDB audit record per object |
| **AU-2 & AU-12** | Comprehensive audit logging | DynamoDB immutable ledger | Queryable by object, date, tier, AI flag |
| **SC-12 & SC-28** | KMS encryption, key rotation | SSE-KMS on S3/DynamoDB | CloudTrail logs of key operations |

---

## Compliance Checklist

- [ ] **AC-16:** Verify all objects in classified bucket have classification tags
  ```bash
  aws s3api head-object --bucket classguard-classified --key <object>
  # Tags should include: classification, cui, review_recommended
  ```

- [ ] **AC-4:** Test bucket policy enforcement
  ```bash
  # Attempt to get untagged object → should be DENIED
  aws s3api head-object --bucket classguard-classified --key untagged-file.txt
  # Expected: AccessDenied
  ```

- [ ] **RA-2:** Verify classification tiers are assigned
  ```bash
  aws dynamodb scan --table-name classification-audit \
    --projection-expression "classification, decided_by, #conf" \
    --expression-attribute-names {'#conf': 'confidence'}
  ```

- [ ] **MP-3:** Check object tags persist across operations
  ```bash
  # Copy object to archive
  aws s3api copy-object --bucket archive --copy-source classified/<object> --key <object>
  # Verify tags copied
  aws s3api get-object-tagging --bucket archive --key <object>
  ```

- [ ] **AU-2/12:** Query audit trail
  ```bash
  aws dynamodb scan --table-name classification-audit --limit 10
  # Verify: timestamp, classification, decided_by, error (if applicable)
  ```

- [ ] **SC-12/28:** Verify encryption
  ```bash
  aws s3api head-bucket --bucket classguard-classified
  # Verify: ServerSideEncryption = aws:kms
  aws dynamodb describe-table --table-name classification-audit \
    --query 'Table.SSEDescription'
  ```

---

## References

- **NIST SP 800-53 Revision 5:** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **NIST SP 800-125:** Security Recommendations for Data Classification
- **FedRAMP Security Control Baseline:** https://www.fedramp.gov/
- **AWS Security Reference Architecture:** https://aws.amazon.com/architecture/security-identity-compliance/
- **FIPS 140-2 Validation:** https://csrc.nist.gov/projects/cryptographic-module-validation-program/

---

## Questions & Feedback

For questions on control implementation or compliance mapping:

**Jose Rodriguez** — Federal Cybersecurity Professional | GRC Engineering  
Email: jarodriguez1836@gmail.com  
LinkedIn: linkedin.com/in/jarodriguez

---

*Last Updated: June 2, 2026*  
*Control Mapping Version: 1.0*
