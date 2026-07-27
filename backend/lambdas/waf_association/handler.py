"""
santi-bank :: CloudFormation CUSTOM RESOURCE :: WAF <-> AgentCore Gateway Association

Associates the origin-cloaking WAF WebACL DIRECTLY to the AgentCore Gateway.

Why a custom Lambda (and not a plain SDK call)?
1. AWS::WAFv2::WebACLAssociation (CloudFormation) does not document support for
   bedrock-agentcore Gateway ARNs yet -> we call the wafv2 API directly.
2. The association can fail with WAFUnavailableEntityException ("AWS WAF
   couldn't retrieve the resource... Retry your request") when the Gateway's
   underlying infrastructure has not been provisioned for WAF yet. The FIX
   (discovered empirically) is to perform a NO-OP UpdateGateway (which
   re-provisions the gateway data plane) and retry the association.

CREATE/UPDATE: associate (with retries + gateway refresh fallback).
DELETE: disassociate (best effort).
"""

# Built-in imports
import json
import os
import time

# External imports
import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
MAX_ATTEMPTS = 10
SLEEP_SECONDS = 15
REFRESH_AFTER_ATTEMPT = 2  # After this many failed attempts, refresh the gateway infra

wafv2_client = boto3.client("wafv2", region_name=REGION)


def refresh_gateway_infrastructure(gateway_id: str) -> None:
    """NO-OP UpdateGateway to re-provision the gateway so WAF can 'see' it."""
    try:
        agentcore_client = boto3.client("bedrock-agentcore-control", region_name=REGION)
    except Exception as e:
        print(f"[WAF-ASSOC] WARNING: bedrock-agentcore-control client unavailable ({e}). Skipping refresh.")
        return

    print(f"[WAF-ASSOC] Refreshing gateway infrastructure via NO-OP UpdateGateway: {gateway_id}")
    gw = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
    update_params = {
        "gatewayIdentifier": gateway_id,
        "name": gw["name"],
        "roleArn": gw["roleArn"],
        "protocolType": gw["protocolType"],
        "authorizerType": gw["authorizerType"],
        "authorizerConfiguration": gw["authorizerConfiguration"],
    }
    # Optional fields: only include when present to keep the update a NO-OP
    for key in ["description", "protocolConfiguration", "interceptorConfigurations", "exceptionLevel"]:
        if gw.get(key) is not None:
            update_params[key] = gw[key]

    print(f"[WAF-ASSOC] UpdateGateway params keys: {sorted(update_params.keys())}")
    agentcore_client.update_gateway(**update_params)

    # Wait until the gateway is READY again
    for i in range(60):
        status = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)["status"]
        print(f"[WAF-ASSOC] Gateway status after refresh [{i + 1}/60]: {status}")
        if status == "READY":
            print("[WAF-ASSOC] Gateway READY after refresh")
            return
        if status == "FAILED":
            raise RuntimeError("Gateway entered FAILED state after NO-OP update")
        time.sleep(5)
    raise RuntimeError("Timeout waiting for gateway READY after refresh")


def associate_with_retries(web_acl_arn: str, gateway_arn: str, gateway_id: str) -> None:
    """Associate the WebACL to the Gateway with retries + infra refresh fallback."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            print(f"[WAF-ASSOC] Attempt {attempt}/{MAX_ATTEMPTS}: associating WebACL to gateway...")
            wafv2_client.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=gateway_arn)
            print("[WAF-ASSOC] ✅ Association SUCCEEDED")
            return
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            print(f"[WAF-ASSOC] Attempt {attempt} failed: {error_code}: {e}")
            if error_code != "WAFUnavailableEntityException":
                raise
            if attempt == REFRESH_AFTER_ATTEMPT:
                print("[WAF-ASSOC] WAF cannot see the gateway yet -> refreshing gateway infrastructure")
                refresh_gateway_infrastructure(gateway_id)
            time.sleep(SLEEP_SECONDS)
    raise RuntimeError(f"WAF association failed after {MAX_ATTEMPTS} attempts")


def lambda_handler(event, context):
    """CloudFormation Custom Resource entrypoint (CDK Provider Framework)."""
    print("=" * 80)
    print(f"[WAF-ASSOC] Received CloudFormation event: {json.dumps(event, default=str)}")

    request_type = event.get("RequestType", "Create")
    props = event.get("ResourceProperties", {})
    web_acl_arn = props["WebAclArn"]
    gateway_arn = props["GatewayArn"]
    gateway_id = props["GatewayIdentifier"]
    physical_id = f"waf-association-{gateway_id}"

    if request_type in ("Create", "Update"):
        associate_with_retries(web_acl_arn, gateway_arn, gateway_id)
        try:
            current = wafv2_client.get_web_acl_for_resource(ResourceArn=gateway_arn)
            print(f"[WAF-ASSOC] Verified association: {current.get('WebACL', {}).get('Name')}")
        except ClientError as e:
            print(f"[WAF-ASSOC] Verification skipped (non-fatal): {e}")
    elif request_type == "Delete":
        try:
            print(f"[WAF-ASSOC] Disassociating WebACL from gateway {gateway_arn}")
            wafv2_client.disassociate_web_acl(ResourceArn=gateway_arn)
            print("[WAF-ASSOC] Disassociation OK")
        except ClientError as e:
            print(f"[WAF-ASSOC] Disassociation failed (best effort, continuing): {e}")

    return {"PhysicalResourceId": physical_id}
