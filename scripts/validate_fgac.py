#!/usr/bin/env python3
"""
santi-bank :: E2E Fine-Grained Access Control Validation Script

Validates the AgentCore Gateway FGAC deployment end-to-end:
1. Reads CloudFormation outputs (Gateway URL, custom domain, Cognito IDs).
2. Gets Cognito JWT Access Tokens for santi / jimmy / joacho (USER_PASSWORD_AUTH).
3. HYPOTHESIS 1 (ListTools):  tools/list is filtered per-user by the RESPONSE interceptor.
4. HYPOTHESIS 1 (InvokeTool): tools/call is blocked per-user by the REQUEST interceptor
   ("you can SEE the tool but NOT execute it" + forged calls to hidden tools).
5. HYPOTHESIS 2 (Errors): empty/invalid tokens produce meaningful error responses.

Zero external dependencies (stdlib + AWS CLI for Cognito auth).

Usage:
    python3 scripts/validate_fgac.py [--url-mode gateway|domain|both]
"""

import argparse
import json
import subprocess
import sys
import urllib.request
import urllib.error

STACK_NAME = "santi-bank-fine-access-dev"
REGION = "us-east-1"
PASSWORD = "Testing123."

# Expected permissions matrix (must match the Custom Resource seeding)
EXPECTED_PERMISSIONS = {
    "santi": ["consulta_saldo", "consulta_tarjetas", "consulta_canales", "consulta_preferencias"],
    "jimmy": ["consulta_saldo", "consulta_tarjetas", "consulta_preferencias"],  # NO canales
    "joacho": ["consulta_saldo", "consulta_canales"],  # NO tarjetas, NO preferencias
}

# Denied tool to attempt per user (forged/armed tools/call)
DENIED_TOOL_ATTEMPTS = {
    "jimmy": "consulta_canales",
    "joacho": "consulta_tarjetas",
}

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"  ✅ PASS: {name} {detail}")
    else:
        FAILED.append(name)
        print(f"  ❌ FAIL: {name} {detail}")


def _aws(args: list) -> str:
    result = subprocess.run(["aws"] + args + ["--region", REGION], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def get_stack_outputs() -> dict:
    result = subprocess.run(
        ["aws", "cloudformation", "describe-stacks", "--stack-name", STACK_NAME,
         "--region", REGION, "--query", "Stacks[0].Outputs", "--output", "json"],
        capture_output=True, text=True, check=True,
    )
    raw_outputs = json.loads(result.stdout)
    if raw_outputs:
        outputs = {o["OutputKey"]: o["OutputValue"] for o in raw_outputs}
    else:
        # Fallback: stack still deploying -> discover live resources directly
        print("WARNING: stack outputs not ready, discovering resources directly...")
        gateway_id = _aws(["bedrock-agentcore-control", "list-gateways",
                           "--query", "items[?name=='santi-bank-gateway-dev'].gatewayId", "--output", "text"])
        gateway_url = _aws(["bedrock-agentcore-control", "get-gateway",
                            "--gateway-identifier", gateway_id, "--query", "gatewayUrl", "--output", "text"])
        pool_id = _aws(["cognito-idp", "list-user-pools", "--max-results", "20",
                        "--query", "UserPools[?Name=='santi-bank-user-pool-dev'].Id", "--output", "text"])
        client_id = _aws(["cognito-idp", "list-user-pool-clients", "--user-pool-id", pool_id,
                          "--query", "UserPoolClients[0].ClientId", "--output", "text"])
        outputs = {
            "GatewayUrl": gateway_url,
            "CognitoAppClientId": client_id,
            "CustomDomainMcpUrl": "https://santi-bank-fine-access.cb.events.genai.aws.dev/mcp",
        }
    print("Stack outputs:")
    for k, v in outputs.items():
        print(f"  {k}: {v}")
    return outputs


def get_token(client_id: str, username: str) -> str:
    result = subprocess.run(
        ["aws", "cognito-idp", "initiate-auth", "--region", REGION,
         "--auth-flow", "USER_PASSWORD_AUTH", "--client-id", client_id,
         "--auth-parameters", f"USERNAME={username},PASSWORD={PASSWORD}",
         "--query", "AuthenticationResult.AccessToken", "--output", "text"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def mcp_request(url: str, token: str, payload: dict, timeout: int = 60):
    """POST an MCP JSON-RPC request. Returns (status_code, parsed_body_or_text)."""
    data = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode()
            status = response.status
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        status = e.code

    # Handle SSE-formatted responses (text/event-stream)
    if body.startswith("event:") or "\ndata:" in body or body.startswith("data:"):
        for line in body.splitlines():
            if line.startswith("data:"):
                body = line[len("data:"):].strip()
                break
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body


def extract_tool_names(list_response: dict) -> list:
    tools = (list_response.get("result") or {}).get("tools", [])
    return sorted(
        t["name"].split("___")[1] if "___" in t["name"] else t["name"] for t in tools
    )


def test_user(url: str, username: str, token: str):
    print(f"\n{'=' * 70}")
    print(f"USER: {username}  (endpoint: {url})")
    print(f"{'=' * 70}")

    # --- HYPOTHESIS 1A: tools/list filtered by RESPONSE interceptor ---
    status, body = mcp_request(url, token, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    actual_tools = extract_tool_names(body) if isinstance(body, dict) else []
    expected_tools = sorted(EXPECTED_PERMISSIONS[username])
    print(f"  tools/list -> HTTP {status} | tools: {actual_tools}")
    check(
        f"[{username}] tools/list filtered correctly",
        actual_tools == expected_tools,
        f"(expected {expected_tools})",
    )

    # --- Allowed tools/call must succeed ---
    allowed_tool = EXPECTED_PERMISSIONS[username][0]  # consulta_saldo for everyone
    call_payload = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": f"{allowed_tool.replace('_', '-')}___{allowed_tool}",
            "arguments": {"username": username} if allowed_tool != "consulta_canales" else {},
        },
    }
    status, body = mcp_request(url, token, call_payload)
    result = body.get("result", {}) if isinstance(body, dict) else {}
    is_error = result.get("isError", False) or (isinstance(body, dict) and "error" in body)
    content_text = json.dumps(result.get("content", ""), ensure_ascii=False)[:300]
    print(f"  tools/call {allowed_tool} (ALLOWED) -> HTTP {status} | isError: {is_error}")
    print(f"    content: {content_text}")
    check(f"[{username}] ALLOWED tools/call '{allowed_tool}' executed OK", status == 200 and not is_error)

    # --- HYPOTHESIS 1B: forged/armed tools/call for a DENIED tool is blocked ---
    if username in DENIED_TOOL_ATTEMPTS:
        denied_tool = DENIED_TOOL_ATTEMPTS[username]
        call_payload = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": f"{denied_tool.replace('_', '-')}___{denied_tool}",
                "arguments": {"username": username} if denied_tool != "consulta_canales" else {},
            },
        }
        status, body = mcp_request(url, token, call_payload)
        result = body.get("result", {}) if isinstance(body, dict) else {}
        is_error = result.get("isError", False) or (isinstance(body, dict) and "error" in body)
        deny_text = json.dumps(body, ensure_ascii=False)[:400]
        print(f"  tools/call {denied_tool} (DENIED) -> HTTP {status} | isError: {is_error}")
        print(f"    deny response: {deny_text}")
        blocked_with_message = (
            status == 200 and is_error and "ACCESO DENEGADO" in json.dumps(body, ensure_ascii=False)
        )
        check(
            f"[{username}] DENIED tools/call '{denied_tool}' blocked by REQUEST interceptor with clear message",
            blocked_with_message,
        )


def test_error_handling(url: str):
    """HYPOTHESIS 2: error handling for empty/invalid tokens."""
    print(f"\n{'=' * 70}")
    print(f"ERROR HANDLING TESTS (Hypothesis 2)  (endpoint: {url})")
    print(f"{'=' * 70}")

    payload = {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}

    status, body = mcp_request(url, token=None, payload=payload)
    print(f"  NO token -> HTTP {status} | body: {json.dumps(body, ensure_ascii=False)[:300]}")
    check("[errors] Request WITHOUT token is rejected (401/403)", status in (401, 403))

    status, body = mcp_request(url, token="invalid.jwt.token", payload=payload)
    print(f"  INVALID token -> HTTP {status} | body: {json.dumps(body, ensure_ascii=False)[:300]}")
    check("[errors] Request with INVALID token is rejected (401/403)", status in (401, 403))


def test_waf_origin_cloaking(gateway_url: str, domain_url: str, token: str):
    """
    ORIGIN CLOAKING test: with a VALID Cognito token,
    - DIRECT Gateway URL invocation -> BLOCKED by the Gateway WAF (no X-Origin-Verify header)
    - Custom domain (CloudFront injects the secret header) -> ALLOWED
    """
    print(f"\n{'=' * 70}")
    print("WAF ORIGIN CLOAKING TESTS (solo CloudFront puede llegar al Gateway)")
    print(f"{'=' * 70}")
    payload = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}

    status, body = mcp_request(gateway_url, token, payload)
    body_str = json.dumps(body, ensure_ascii=False) if isinstance(body, dict) else str(body)
    print(f"  DIRECT Gateway URL (token valido) -> HTTP {status} | body: {body_str[:300]}")
    blocked = status == 403 or (isinstance(body, dict) and body.get("error", {}).get("code") == -32002)
    check(
        "[waf] Invocacion DIRECTA al Gateway BLOQUEADA por WAF (aunque el JWT sea valido)",
        blocked,
        f"(HTTP {status})",
    )

    status, body = mcp_request(domain_url, token, payload)
    tools = extract_tool_names(body) if isinstance(body, dict) else []
    print(f"  Via CUSTOM DOMAIN (CloudFront) -> HTTP {status} | tools: {tools}")
    check(
        "[waf] Invocacion via CloudFront (X-Origin-Verify inyectado) PERMITIDA",
        status == 200 and len(tools) > 0,
        f"(HTTP {status}, {len(tools)} tools)",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url-mode", choices=["gateway", "domain", "both"], default="domain")
    parser.add_argument("--skip-waf-test", action="store_true", help="Skip the origin cloaking test")
    args = parser.parse_args()

    outputs = get_stack_outputs()
    client_id = outputs["CognitoAppClientId"]

    urls = []
    if args.url_mode in ("gateway", "both"):
        urls.append(("Gateway URL", outputs["GatewayUrl"]))
    if args.url_mode in ("domain", "both"):
        urls.append(("Custom Domain", outputs["CustomDomainMcpUrl"]))

    tokens = {}
    for username in EXPECTED_PERMISSIONS:
        print(f"\nGetting Cognito token for '{username}'...")
        tokens[username] = get_token(client_id, username)
        print(f"  Token OK (len={len(tokens[username])})")

    for label, url in urls:
        print(f"\n\n{'#' * 70}")
        print(f"# TESTING ENDPOINT: {label} -> {url}")
        print(f"{'#' * 70}")
        for username in EXPECTED_PERMISSIONS:
            test_user(url, username, tokens[username])
        test_error_handling(url)

    if not args.skip_waf_test:
        test_waf_origin_cloaking(
            gateway_url=outputs["GatewayUrl"],
            domain_url=outputs["CustomDomainMcpUrl"],
            token=tokens["santi"],
        )

    print(f"\n\n{'=' * 70}")
    print(f"SUMMARY: {len(PASSED)} passed, {len(FAILED)} failed")
    print(f"{'=' * 70}")
    for name in FAILED:
        print(f"  ❌ {name}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
