"""
santi-bank :: FINE-GRAINED ACCESS CONTROL (FGAC) Lambda Interceptor

Single AgentCore Gateway Lambda Interceptor that enforces per-user tool
permissions (stored in the "santi-bank-fine-grained-access-mapping" DynamoDB
table) at BOTH interception points:

1) REQUEST interceptor (tools/call):
   - Extracts the username from the Cognito JWT (Authorization header).
   - Queries DynamoDB for the allowed tools of that user.
   - If the tool is NOT allowed -> SHORT-CIRCUITS the request by returning a
     "transformedGatewayResponse" (the Gateway responds immediately and the
     target Lambda is NEVER invoked). This covers the case:
     "Si puedes VER la tool, pero NO ejecutarla" and also armed/forged
     tool calls for tools that were revoked or never listed.

2) RESPONSE interceptor (tools/list):
   - Filters the aggregated tools list so the user only SEES allowed tools.

Security note (per AWS guidance): NEVER trust custom headers (X-Client-ID,
etc.) for authorization decisions - they are easily spoofed. The ONLY trusted
identity source is the JWT, whose signature was already validated by the
Gateway inbound authorizer (Cognito CUSTOM_JWT) BEFORE this interceptor runs.

DynamoDB permissions model (single-table design):
    PK = "USER#<username>"    SK = "TOOL#<tool_name>"    Allowed = true|false
Absence of the item OR Allowed=false  ==>  DENY (fail-closed).
"""

# Built-in imports
import base64
import json
import os
from typing import Any, Dict, List, Optional

# External imports
import boto3
from botocore.exceptions import ClientError

FGAC_TABLE_NAME = os.environ.get("FGAC_TABLE_NAME", "santi-bank-fine-grained-access-mapping")
# DENY_MODE: "mcp_error" (MCP tool result with isError=true, agent-friendly)
#            "jsonrpc_error" (JSON-RPC error object, protocol-level)
DENY_MODE = os.environ.get("DENY_MODE", "mcp_error")

dynamodb = boto3.resource("dynamodb")
fgac_table = dynamodb.Table(FGAC_TABLE_NAME)

# Headers that must NEVER reach CloudWatch Logs in clear text. With
# passRequestHeaders=true the interceptor receives ALL request headers,
# including the origin cloaking secret injected by CloudFront.
SENSITIVE_LOG_HEADERS = {"x-origin-verify"}


def sanitize_for_logging(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the interceptor event with sensitive headers redacted."""
    safe_event = json.loads(json.dumps(event, default=str))
    for section in ("gatewayRequest", "gatewayResponse"):
        headers = ((safe_event.get("mcp") or {}).get(section) or {}).get("headers")
        if isinstance(headers, dict):
            for key in list(headers):
                if key.lower() in SENSITIVE_LOG_HEADERS:
                    headers[key] = "***REDACTED***"
    return safe_event


# ------------------------------------------------------------------------
# JWT HELPERS
# ------------------------------------------------------------------------
def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decode the JWT payload (signature already validated by the Gateway)."""
    try:
        if token.startswith("Bearer "):
            token = token[7:]
        parts = token.split(".")
        if len(parts) != 3:
            print(f"[FGAC][JWT] Invalid JWT format: expected 3 parts, got {len(parts)}")
            return None
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        print(f"[FGAC][JWT] Error decoding JWT payload: {e}")
        return None


def extract_identity(request_headers: Dict[str, str]) -> Dict[str, Optional[str]]:
    """Extract username + client_id from the Authorization header JWT."""
    auth_header = None
    for key, value in (request_headers or {}).items():
        if key.lower() == "authorization":
            auth_header = value
            break

    print(f"[FGAC][JWT] Authorization header present: {bool(auth_header)}")
    if not auth_header:
        return {"username": None, "client_id": None}

    payload = decode_jwt_payload(auth_header)
    if not payload:
        return {"username": None, "client_id": None}

    username = payload.get("username") or payload.get("cognito:username")
    client_id = payload.get("client_id")
    token_use = payload.get("token_use")
    print(
        f"[FGAC][JWT] Extracted identity -> username: '{username}' | "
        f"client_id: '{client_id}' | token_use: '{token_use}' | scope: '{payload.get('scope')}'"
    )
    return {"username": username, "client_id": client_id}


# ------------------------------------------------------------------------
# DYNAMODB PERMISSIONS (FGAC data store)
# ------------------------------------------------------------------------
def get_allowed_tools(username: str) -> List[str]:
    """Query DynamoDB for all ALLOWED tools of a user (fail-closed on error)."""
    try:
        print(f"[FGAC][DDB] Querying table '{FGAC_TABLE_NAME}' for PK=USER#{username}")
        response = fgac_table.query(
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": f"USER#{username}"},
        )
        items = response.get("Items", [])
        print(f"[FGAC][DDB] Raw permission items: {json.dumps(items, default=str)}")
        allowed = [
            item["SK"].replace("TOOL#", "")
            for item in items
            if item.get("Allowed", False) is True
        ]
        print(f"[FGAC][DDB] ALLOWED tools for '{username}': {allowed}")
        return allowed
    except ClientError as e:
        print(f"[FGAC][DDB] ClientError querying permissions (DENY ALL): {e}")
        return []
    except Exception as e:
        print(f"[FGAC][DDB] Unexpected error querying permissions (DENY ALL): {e}")
        return []


def extract_base_tool_name(gateway_tool_name: str) -> str:
    """Gateway exposes tools as '<target-name>___<tool_name>'. Extract the base name."""
    if "___" in gateway_tool_name:
        return gateway_tool_name.split("___")[1]
    return gateway_tool_name


# ------------------------------------------------------------------------
# REQUEST INTERCEPTOR (tools/call enforcement -> InvokeTool validation)
# ------------------------------------------------------------------------
def handle_request_interception(mcp_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate tools/call invocations BEFORE they reach the target Lambda."""
    gateway_request = mcp_data.get("gatewayRequest", {})
    request_headers = gateway_request.get("headers", {})
    request_body = gateway_request.get("body", {}) or {}
    mcp_method = request_body.get("method", "unknown")
    request_id = request_body.get("id", 1)

    print(f"[FGAC][REQUEST] MCP method: '{mcp_method}' | request id: {request_id}")

    # Only enforce on tools/call. Everything else (initialize, tools/list,
    # ping, notifications) passes through (tools/list is filtered on RESPONSE).
    if mcp_method != "tools/call":
        print("[FGAC][REQUEST] Not a tools/call -> PASS THROUGH")
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {"body": request_body}},
        }

    requested_tool_full = (request_body.get("params") or {}).get("name", "")
    requested_tool = extract_base_tool_name(requested_tool_full)
    print(f"[FGAC][REQUEST] tools/call requested tool: '{requested_tool_full}' (base: '{requested_tool}')")

    identity = extract_identity(request_headers)
    username = identity.get("username")

    # Fail-closed: no identity -> deny
    if not username:
        print("[FGAC][REQUEST] DENY - could not extract username from JWT (fail-closed)")
        return build_deny_response(
            request_id=request_id,
            message=(
                "ACCESO DENEGADO por santi-bank FGAC: no fue posible identificar el "
                "usuario en el token JWT. Verifica que el Access Token de Cognito sea valido."
            ),
            username="unknown",
            tool=requested_tool,
            allowed_tools=[],
        )

    allowed_tools = get_allowed_tools(username)

    if requested_tool in allowed_tools:
        print(f"[FGAC][REQUEST] ALLOW - user '{username}' CAN execute tool '{requested_tool}' -> PASS THROUGH")
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {"body": request_body}},
        }

    # DENY: short-circuit -> the Gateway responds immediately, target Lambda is NEVER invoked
    print(
        f"[FGAC][REQUEST] DENY - user '{username}' tried to execute tool "
        f"'{requested_tool}' WITHOUT permission. Short-circuiting request!"
    )
    return build_deny_response(
        request_id=request_id,
        message=(
            f"ACCESO DENEGADO por santi-bank FGAC: el usuario '{username}' NO tiene "
            f"permiso para EJECUTAR la tool '{requested_tool}'. "
            f"(Puede que la tool sea visible en tools/list de otro usuario, o que el permiso "
            f"haya sido revocado en DynamoDB, pero la invocacion esta bloqueada). "
            f"Tools permitidas para '{username}': {sorted(allowed_tools)}"
        ),
        username=username,
        tool=requested_tool,
        allowed_tools=allowed_tools,
    )


def build_deny_response(
    request_id: Any,
    message: str,
    username: str,
    tool: str,
    allowed_tools: List[str],
) -> Dict[str, Any]:
    """
    Build the short-circuit DENY response for a blocked tools/call.

    IMPORTANT (learning for the santi-bank team): if we return an HTTP status
    code != 200, many MCP clients show a GENERIC transport error and the rich
    message gets lost. Returning HTTP 200 with a well-formed MCP/JSON-RPC
    payload keeps the DETAILED deny reason visible to the agent/client.
    """
    if DENY_MODE == "jsonrpc_error":
        # Protocol-level error (JSON-RPC error object)
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32003,
                "message": message,
                "data": {
                    "fgac": "santi-bank",
                    "decision": "DENY",
                    "username": username,
                    "tool": tool,
                    "allowed_tools": sorted(allowed_tools),
                },
            },
        }
    else:
        # MCP tool-result error (agent-friendly: LLMs can read and react to it)
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": f"🚫 {message}"}],
                "isError": True,
            },
        }

    print(f"[FGAC][REQUEST] DENY response body: {json.dumps(body, default=str)}")
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 200,
                "body": body,
            }
        },
    }


# ------------------------------------------------------------------------
# RESPONSE INTERCEPTOR (tools/list filtering -> ListTools validation)
# ------------------------------------------------------------------------
def handle_response_interception(mcp_data: Dict[str, Any]) -> Dict[str, Any]:
    """Filter the tools/list response so users only SEE their allowed tools."""
    gateway_request = mcp_data.get("gatewayRequest", {}) or {}
    gateway_response = mcp_data.get("gatewayResponse", {}) or {}
    request_headers = gateway_request.get("headers", {})
    response_body = gateway_response.get("body", {}) or {}
    status_code = gateway_response.get("statusCode", 200)

    request_body = gateway_request.get("body", {}) or {}
    mcp_method = request_body.get("method", "unknown")
    print(f"[FGAC][RESPONSE] Original MCP method: '{mcp_method}' | statusCode: {status_code}")

    # Only transform tools/list responses. Anything else passes through
    # (including DENY short-circuits coming from the REQUEST interceptor).
    is_tools_list = isinstance(response_body, dict) and "tools" in (response_body.get("result") or {})
    if not is_tools_list:
        print("[FGAC][RESPONSE] Not a tools/list response -> PASS THROUGH unchanged")
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayResponse": {
                    "statusCode": status_code,
                    "body": response_body,
                }
            },
        }

    identity = extract_identity(request_headers)
    username = identity.get("username")

    original_tools = response_body["result"].get("tools", [])
    print(f"[FGAC][RESPONSE] Original tools count: {len(original_tools)}")
    print(f"[FGAC][RESPONSE] Original tool names: {[t.get('name') for t in original_tools]}")

    if not username:
        print("[FGAC][RESPONSE] DENY ALL - could not extract username from JWT (fail-closed)")
        filtered_tools = []
    else:
        allowed_tools = get_allowed_tools(username)
        filtered_tools = [
            tool
            for tool in original_tools
            if extract_base_tool_name(tool.get("name", "")) in set(allowed_tools)
        ]
        removed = [
            tool.get("name")
            for tool in original_tools
            if extract_base_tool_name(tool.get("name", "")) not in set(allowed_tools)
        ]
        print(f"[FGAC][RESPONSE] User '{username}' -> filtered {len(original_tools)} tools down to {len(filtered_tools)}")
        print(f"[FGAC][RESPONSE] Tools REMOVED from listing: {removed}")

    filtered_body = dict(response_body)
    filtered_body["result"] = dict(response_body["result"])
    filtered_body["result"]["tools"] = filtered_tools

    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": status_code,
                "body": filtered_body,
            }
        },
    }


# ------------------------------------------------------------------------
# MAIN HANDLER (routes REQUEST vs RESPONSE interception points)
# ------------------------------------------------------------------------
def lambda_handler(event, context):
    """Main handler for the santi-bank FGAC Gateway Interceptor."""
    print("=" * 80)
    print("[FGAC] Received interceptor event (sensitive headers redacted):")
    print(json.dumps(sanitize_for_logging(event), default=str))

    try:
        mcp_data = event.get("mcp", {})

        # RESPONSE interception point: 'gatewayResponse' is present
        if mcp_data.get("gatewayResponse") is not None:
            print("[FGAC] Interception point detected: RESPONSE (ListTools filtering)")
            result = handle_response_interception(mcp_data)
        else:
            print("[FGAC] Interception point detected: REQUEST (InvokeTool enforcement)")
            result = handle_request_interception(mcp_data)

        print(f"[FGAC] Interceptor output: {json.dumps(result, default=str)}")
        return result

    except Exception as e:
        import traceback

        print(f"[FGAC] FATAL ERROR in interceptor: {type(e).__name__}: {e}")
        print(f"[FGAC] Traceback: {traceback.format_exc()}")

        # Fail-closed: deny everything with an explanatory (but safe) message
        return {
            "interceptorOutputVersion": "1.0",
            "mcp": {
                "transformedGatewayResponse": {
                    "statusCode": 200,
                    "body": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": "🚫 santi-bank FGAC: error interno del interceptor (fail-closed, acceso denegado).",
                                }
                            ],
                            "isError": True,
                        },
                    },
                }
            },
        }
