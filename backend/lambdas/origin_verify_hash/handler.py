"""
santi-bank :: CloudFormation CUSTOM RESOURCE :: Origin-Verify SHA-256 digests

Feeds the Gateway WAF rule with the SHA-256 DIGEST of the origin-verify secret,
so the WAF configuration NEVER stores the secret itself.

How the origin cloaking works after this change:
1. Secrets Manager holds a random 64-char secret (CloudFormation generates it).
2. CloudFront injects the PLAIN secret as the "X-Origin-Verify" origin header
   (dynamic reference pinned to the secret VersionId returned here).
3. The WAF rule applies the SHA256 text transformation to the incoming header
   and compares it (EXACTLY) with the digest returned here. WAF console/API,
   CloudTrail (UpdateWebACL) and CloudFormation only see a one-way hash.

Why a custom resource? CloudFormation cannot compute a SHA-256 of a dynamic
reference, so this Lambda reads the secret at deploy time and returns ONLY
non-sensitive values (base64 digests + VersionId). The secret value is never
logged nor returned.

ROTATION (zero downtime, forward only):
- Bump "origin_verify_rotation_id" in cdk.json -> on UPDATE this Lambda creates
  a new random version (idempotent: deterministic ClientRequestToken), so the
  old value becomes AWSPREVIOUS.
- With "origin_verify_accept_previous_secret": true the WAF accepts BOTH digests
  while CloudFront propagates the new header. Then set it to false and deploy
  again to stop accepting the old value.

CREATE/UPDATE: (rotate if RotationId changed) + return digests.
DELETE: no-op (the secret is owned by CloudFormation).

Second mode ("Mode": "WafPropagationWait"): sleeps N seconds AFTER the WebACL
update and BEFORE CloudFront switches to a new header value. Real finding of
this demo: CloudFormation marks the WebACL UPDATE_COMPLETE before every WAF
host has the new rule, while some CloudFront edges pick up the new header in
seconds, so one request got a 403 during the first migration.
"""

# Built-in imports
import base64
import hashlib
import json
import os
import time
import uuid

# External imports
import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
SECRET_LENGTH = int(os.environ.get("SECRET_LENGTH", "64"))

secrets_client = boto3.client("secretsmanager", region_name=REGION)


def sha256_b64(value: str) -> str:
    """Base64 of the RAW (binary) SHA-256 digest: the format WAF SearchString expects."""
    return base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")


def short(digest_b64: str) -> str:
    """Digest prefix for logs (the digest is not sensitive, but keep logs minimal)."""
    return f"{digest_b64[:8]}..."


def get_version(secret_id: str, stage: str):
    """Return (secret_string, version_id) for a staging label, or (None, None) if absent."""
    try:
        response = secrets_client.get_secret_value(SecretId=secret_id, VersionStage=stage)
        return response["SecretString"], response["VersionId"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None, None
        raise


def rotation_version_id(secret_id: str, rotation_id: str) -> str:
    """Deterministic VersionId per RotationId, so retries never rotate twice."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{secret_id}#origin-verify#{rotation_id}"))


def rotate_secret(secret_id: str, rotation_id: str) -> None:
    """Create a NEW random AWSCURRENT version (old one becomes AWSPREVIOUS)."""
    version_id = rotation_version_id(secret_id, rotation_id)
    existing_versions = secrets_client.describe_secret(SecretId=secret_id).get("VersionIdsToStages", {})
    if version_id in existing_versions:
        print(f"[ORIGIN-VERIFY] Version for RotationId '{rotation_id}' already exists -> no new rotation")
        return

    new_value = secrets_client.get_random_password(
        PasswordLength=SECRET_LENGTH,
        ExcludePunctuation=True,
        IncludeSpace=False,
    )["RandomPassword"]
    secrets_client.put_secret_value(
        SecretId=secret_id,
        ClientRequestToken=version_id,
        SecretString=new_value,
    )
    print(f"[ORIGIN-VERIFY] ✅ Rotated secret: new AWSCURRENT version for RotationId '{rotation_id}'")


def build_digests(secret_id: str, rotation_id: str) -> dict:
    """Read AWSCURRENT (+ AWSPREVIOUS) and return ONLY non-sensitive values."""
    current_value, current_version = get_version(secret_id, "AWSCURRENT")
    if not current_value:
        raise RuntimeError("Origin-verify secret has no AWSCURRENT value")
    if len(current_value) < 32:
        # Low entropy secrets make the SHA-256 digest brute-forceable offline
        raise RuntimeError("Origin-verify secret must have at least 32 characters")

    previous_value, previous_version = get_version(secret_id, "AWSPREVIOUS")
    current_digest = sha256_b64(current_value)
    # No previous version yet (fresh deploy): reuse the current digest
    previous_digest = sha256_b64(previous_value) if previous_value else current_digest

    print(
        f"[ORIGIN-VERIFY] AWSCURRENT version={current_version} sha256={short(current_digest)} | "
        f"AWSPREVIOUS version={previous_version} sha256={short(previous_digest)}"
    )
    return {
        "CurrentSha256B64": current_digest,
        "PreviousSha256B64": previous_digest,
        "CurrentVersionId": current_version,
        "HasPrevious": "true" if previous_value else "false",
        "RotationId": rotation_id,
    }


def lambda_handler(event, context):
    """CloudFormation Custom Resource entrypoint (CDK Provider Framework)."""
    print("=" * 80)
    # Safe to log: the event only carries the secret ARN and the RotationId
    print(f"[ORIGIN-VERIFY] Received CloudFormation event: {json.dumps(event, default=str)}")

    request_type = event.get("RequestType", "Create")
    props = event.get("ResourceProperties", {})
    old_props = event.get("OldResourceProperties", {}) or {}

    if props.get("Mode") == "WafPropagationWait":
        physical_id = event.get("PhysicalResourceId") or "waf-propagation-wait"
        if request_type in ("Create", "Update"):
            seconds = int(props.get("Seconds", "60"))
            print(f"[ORIGIN-VERIFY] Waiting {seconds}s so every WAF host has the new rule before CloudFront changes")
            time.sleep(seconds)
        return {"PhysicalResourceId": physical_id}

    secret_id = props["SecretArn"]
    rotation_id = str(props.get("RotationId", "v1"))
    physical_id = event.get("PhysicalResourceId") or f"origin-verify-sha256-{secret_id.split(':')[-1]}"

    if request_type == "Delete":
        print("[ORIGIN-VERIFY] DELETE -> no-op (secret owned by CloudFormation)")
        return {"PhysicalResourceId": physical_id}

    if request_type == "Update" and str(old_props.get("RotationId")) != rotation_id:
        print(f"[ORIGIN-VERIFY] RotationId changed '{old_props.get('RotationId')}' -> '{rotation_id}'")
        rotate_secret(secret_id, rotation_id)

    return {"PhysicalResourceId": physical_id, "Data": build_digests(secret_id, rotation_id)}
