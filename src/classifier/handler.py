"""
Lambda handler for ClassGuard: triggered when an object lands in the ingest bucket.

Flow:
  1. Read the object (with size/type checks).
  2. Classify it using the rules + AI engine.
  3. Copy to classified bucket with tags and metadata.
  4. Write audit record to DynamoDB.
  5. On any error: move to quarantine, publish SNS alert.

Design principle: fail-closed. An object always moves away from ingest (either to
classified or quarantine), never stays in ingest even on error.
"""

import json
import logging
import os
import datetime
from urllib.parse import quote

import boto3
from botocore.exceptions import ClientError

from classify import classify

log = logging.getLogger()
log.setLevel(logging.INFO)

# Configuration from environment (set by Lambda / Terraform)
INGEST_BUCKET = os.environ.get("INGEST_BUCKET", "classguard-ingest")
CLASSIFIED_BUCKET = os.environ.get("CLASSIFIED_BUCKET", "classguard-classified")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "classguard-quarantine")
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "classification-audit")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")
MAX_OBJECT_SIZE = int(os.environ.get("MAX_OBJECT_SIZE", "1048576"))  # 1 MB default
SKIP_EXTENSIONS = set(os.environ.get("OBJECT_SKIP_EXTENSIONS", ".zip,.exe,.bin,.pdf").split(","))

_region = os.environ.get("AWS_REGION", "us-east-1")
s3_client = boto3.client("s3", region_name=_region)
dynamodb = boto3.resource("dynamodb", region_name=_region)
sns_client = boto3.client("sns", region_name=_region)

audit_table = dynamodb.Table(AUDIT_TABLE)


def _read_object(bucket, key):
    """Read object with safety checks: size cap, extension filter, UTF-8 decode."""
    try:
        resp = s3_client.head_object(Bucket=bucket, Key=key)
        size = resp["ContentLength"]
        if size > MAX_OBJECT_SIZE:
            return None, f"Object too large: {size} bytes > {MAX_OBJECT_SIZE} limit"

        _, ext = os.path.splitext(key)
        if ext.lower() in SKIP_EXTENSIONS:
            return None, f"File extension {ext} skipped (not text-analyzable)"

        resp = s3_client.get_object(Bucket=bucket, Key=key)
        content = resp["Body"].read()

        try:
            text = content.decode("utf-8")
            return text, None
        except UnicodeDecodeError:
            return None, "File is not UTF-8 decodable (likely binary)"

    except ClientError as e:
        return None, f"S3 read failed: {str(e)}"


def _tags_to_s3_format(tags_dict):
    """Convert Classification.as_tags() dict to S3 tag string (key1=value1&key2=value2)."""
    return "&".join(f"{k}={v}" for k, v in tags_dict.items())


def _move_to_classified(key, classification):
    """Copy object from ingest to classified bucket with tags and metadata."""
    try:
        tags = classification.as_tags()
        tag_string = _tags_to_s3_format(tags)

        metadata = {
            "x-amz-meta-classification": classification.tier,
            "x-amz-meta-impact": classification.impact,
            "x-amz-meta-cui": "true" if classification.cui else "false",
            "x-amz-meta-decided-by": classification.decided_by,
        }

        s3_client.copy_object(
            CopySource=f"{INGEST_BUCKET}/{key}",
            Bucket=CLASSIFIED_BUCKET,
            Key=key,
            Tagging=tag_string,
            TaggingDirective="REPLACE",
            MetadataDirective="REPLACE",
            Metadata=metadata,
        )

        # Delete from ingest (move, not copy)
        s3_client.delete_object(Bucket=INGEST_BUCKET, Key=key)

        log.info(f"Moved {key} to {CLASSIFIED_BUCKET}: tier={classification.tier}")

    except ClientError as e:
        raise RuntimeError(f"Failed to move to classified bucket: {str(e)}")


def _write_audit(key, classification):
    """Write classification record to DynamoDB audit ledger (non-fatal if it fails)."""
    try:
        audit_table.put_item(
            Item={
                "object_key": key,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "tier": classification.tier,
                "impact": classification.impact,
                "cui": classification.cui,
                "categories": ",".join(classification.categories),
                "findings": json.dumps(classification.findings),
                "ai_available": classification.ai_available,
                "ai_tier": classification.ai_tier or "N/A",
                "ai_confidence": f"{classification.ai_confidence:.2f}",
                "ai_rationale": classification.ai_rationale,
                "review_recommended": classification.review_recommended,
                "decided_by": classification.decided_by,
            }
        )
        log.info(f"Audit record written: {key}")

    except ClientError as e:
        # Non-fatal: object is safely in classified bucket; we just didn't log it.
        log.warning(f"Failed to write audit for {key}: {str(e)}")


def _quarantine(key, reason):
    """Move object to quarantine bucket and send alert."""
    try:
        s3_client.copy_object(
            CopySource=f"{INGEST_BUCKET}/{key}",
            Bucket=QUARANTINE_BUCKET,
            Key=key,
        )
        s3_client.delete_object(Bucket=INGEST_BUCKET, Key=key)

        log.warning(f"QUARANTINED {key}: {reason}")

        if ALERT_TOPIC_ARN:
            sns_client.publish(
                TopicArn=ALERT_TOPIC_ARN,
                Subject=f"ClassGuard: Classification failed for {key}",
                Message=f"Object: {key}\nReason: {reason}\n\nCheck CloudWatch logs and quarantine bucket.",
            )
    except ClientError as e:
        log.error(f"Failed to quarantine {key}: {str(e)}")


def handler(event, context):
    """Lambda handler triggered by S3 Object Created event via EventBridge."""
    try:
        # Parse EventBridge event from S3
        bucket = event["detail"]["bucket"]["name"]
        key = event["detail"]["object"]["key"]

        log.info(f"ClassGuard: processing {bucket}/{key}")

        # ---- Read ----
        text, read_error = _read_object(bucket, key)
        if read_error:
            log.error(f"Read error: {read_error}")
            _quarantine(key, read_error)
            return {"statusCode": 400, "body": read_error}

        # ---- Classify ----
        try:
            classification = classify(text)
        except Exception as e:
            error_msg = f"Classification failed: {str(e)}"
            log.error(error_msg)
            _quarantine(key, error_msg)
            return {"statusCode": 500, "body": error_msg}

        # ---- Move to classified + audit ----
        try:
            _move_to_classified(key, classification)
            _write_audit(key, classification)
        except RuntimeError as e:
            log.error(str(e))
            _quarantine(key, str(e))
            return {"statusCode": 500, "body": str(e)}

        # ---- Success ----
        log.info(
            f"SUCCESS: {key} -> {classification.tier} "
            f"(decided_by={classification.decided_by}, review={classification.review_recommended})"
        )
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "key": key,
                    "tier": classification.tier,
                    "decided_by": classification.decided_by,
                    "review_recommended": classification.review_recommended,
                }
            ),
        }

    except KeyError as e:
        log.error(f"Malformed event (missing key {e})")
        return {"statusCode": 400, "body": f"Malformed event: missing {e}"}

    except Exception as e:
        log.error(f"Unexpected error: {str(e)}")
        return {"statusCode": 500, "body": str(e)}
