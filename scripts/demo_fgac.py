#!/usr/bin/env python3
"""
santi-bank :: INTERACTIVE STEP-BY-STEP DEMO for AgentCore Gateway FGAC

Guided, "live" walkthrough of the Fine-Grained Access Control demo, designed to
be shown to customers. It explains WHAT happens at each step and shows the REAL
requests/responses:

  STEP 0  Discover the deployment (CloudFormation outputs: Gateway, CloudFront, Cognito).
  STEP 1  Select the demo user (santi / jimmy / joacho) and see the expected permissions.
  STEP 2  AUTH: get a Cognito JWT (USER_PASSWORD_AUTH) and decode its claims.
  STEP 3  MCP handshake: `initialize` against the Gateway (how an MCP client "connects").
  STEP 4  MCP `tools/list`: which tools the user SEES (RESPONSE interceptor filtering).
  STEP 5  Interactive menu: USE the tools (`tools/call`), try a FORGED call to a hidden
          tool (REQUEST interceptor short-circuit), re-list after DynamoDB changes,
          switch user, error handling and origin cloaking (WAF) demos.

Zero external dependencies (stdlib + AWS CLI for Cognito auth), same approach as
`scripts/validate_fgac.py`.

Usage:
    python3 scripts/demo_fgac.py                       # interactive (custom domain via CloudFront)
    python3 scripts/demo_fgac.py --user jimmy          # pre-select the user
    python3 scripts/demo_fgac.py --no-pause            # do not wait for ENTER between steps
    python3 scripts/demo_fgac.py --url-mode gateway    # direct Gateway URL (WAF blocks it on purpose)
    python3 scripts/demo_fgac.py --no-color            # plain output (e.g. when piping)
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

STACK_NAME = "santi-bank-fine-access-dev"
REGION = "us-east-1"
DEFAULT_PASSWORD = os.environ.get("SANTI_BANK_PASSWORD", "Testing123.")
MCP_PROTOCOL_VERSION = "2025-03-26"

# Full tool catalog exposed by the Gateway (4 Lambda targets)
ALL_TOOLS = {
    "consulta_saldo": "Saldo (balance) de un usuario",
    "consulta_tarjetas": "Tarjetas de credito/debito de un usuario",
    "consulta_canales": "Estado de TODOS los canales del banco (sin parametros)",
    "consulta_preferencias": "Preferencias de la app de un usuario",
}

# Expected permissions matrix (must match the Custom Resource seeding)
EXPECTED_PERMISSIONS = {
    "santi": ["consulta_saldo", "consulta_tarjetas", "consulta_canales", "consulta_preferencias"],
    "jimmy": ["consulta_saldo", "consulta_tarjetas", "consulta_preferencias"],  # NO canales
    "joacho": ["consulta_saldo", "consulta_canales"],  # NO tarjetas, NO preferencias
}

PAUSE_ENABLED = True
LAST_RAW_RESPONSE = None


# ------------------------------------------------------------------------
# PRESENTATION HELPERS (colors, banners, pauses)
# ------------------------------------------------------------------------
class C:
    """ANSI colors (disabled with --no-color, NO_COLOR env or non-tty)."""

    enabled = True
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = (
        "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m", "\033[37m",
    )

    @classmethod
    def paint(cls, text: str, *styles: str) -> str:
        if not cls.enabled:
            return text
        return "".join(styles) + text + cls.RESET


def bold(t): return C.paint(t, C.BOLD)
def dim(t): return C.paint(t, C.DIM)
def ok(t): return C.paint(t, C.GREEN)
def warn(t): return C.paint(t, C.YELLOW)
def bad(t): return C.paint(t, C.RED)
def info(t): return C.paint(t, C.CYAN)
def accent(t): return C.paint(t, C.MAGENTA, C.BOLD)


def banner():
    print(accent("=" * 78))
    print(accent("  santi-bank 🏦🛡️  AgentCore Gateway :: Fine-Grained Access Control DEMO"))
    print(accent("  Cognito JWT  ->  CloudFront + WAF  ->  AgentCore Gateway  ->  Interceptor FGAC"))
    print(accent("=" * 78))


def step(number: str, title: str):
    print()
    print(C.paint(f"┌{'─' * 76}┐", C.BLUE))
    print(C.paint(f"│ STEP {number}: {title:<{68 - len(str(number))}}│", C.BLUE, C.BOLD))
    print(C.paint(f"└{'─' * 76}┘", C.BLUE))


def explain(*lines: str):
    """Narrative for the customer: WHAT is happening and WHY."""
    for line in lines:
        print(f"  {info('ℹ')}  {line}")


def pause(message: str = "Presiona ENTER para continuar..."):
    if not PAUSE_ENABLED:
        return
    try:
        input(dim(f"\n  ⏎  {message}"))
    except EOFError:
        pass


def show_json(label: str, obj, max_chars: int = 3000):
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=str) if not isinstance(obj, str) else obj
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n... [truncado, {len(text) - max_chars} chars mas]"
    print(f"\n  {bold(label)}")
    for line in text.splitlines():
        print(f"    {dim('│')} {line}")


def show_command(args: list):
    """Print the equivalent AWS CLI command so the audience can replicate it."""
    print(f"\n  {bold('$')} {dim(' '.join(args))}")


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"  {warn('?')}  {prompt}{suffix}: ").strip()
    except EOFError:
        value = ""
    return value or default


# ------------------------------------------------------------------------
# AWS HELPERS (same approach as validate_fgac.py)
# ------------------------------------------------------------------------
def _aws(args: list) -> str:
    result = subprocess.run(["aws"] + args + ["--region", REGION], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def get_stack_outputs() -> dict:
    cmd = ["aws", "cloudformation", "describe-stacks", "--stack-name", STACK_NAME,
           "--region", REGION, "--query", "Stacks[0].Outputs", "--output", "json"]
    show_command(cmd)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(bad(f"\n  ✗ No fue posible leer el stack '{STACK_NAME}': {e.stderr.strip()}"))
        print(bad("    Verifica credenciales AWS (aws sts get-caller-identity) y que el stack este desplegado."))
        sys.exit(1)

    raw_outputs = json.loads(result.stdout) or []
    outputs = {o["OutputKey"]: o["OutputValue"] for o in raw_outputs}

    if not outputs:
        print(warn("  ! Stack outputs no listos, descubriendo recursos directamente..."))
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
            "GatewayId": gateway_id,
            "CognitoUserPoolId": pool_id,
            "CognitoAppClientId": client_id,
            "CustomDomainMcpUrl": "https://santi-bank-fine-access.cb.events.genai.aws.dev/mcp",
        }
    return outputs


def get_token(client_id: str, username: str, password: str) -> str:
    cmd = ["aws", "cognito-idp", "initiate-auth", "--region", REGION,
           "--auth-flow", "USER_PASSWORD_AUTH", "--client-id", client_id,
           "--auth-parameters", f"USERNAME={username},PASSWORD=********",
           "--query", "AuthenticationResult.AccessToken", "--output", "text"]
    show_command(cmd)
    real_cmd = [a.replace("PASSWORD=********", f"PASSWORD={password}") for a in cmd]
    result = subprocess.run(real_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "initiate-auth failed")
    return result.stdout.strip()


def decode_jwt(token: str) -> tuple:
    """Decode header + payload of a JWT (NO signature validation, that is the Gateway's job)."""
    def _b64(segment: str):
        segment += "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment))

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"JWT invalido: se esperaban 3 partes, llegaron {len(parts)}")
    return _b64(parts[0]), _b64(parts[1])


def mcp_request(url: str, token, payload: dict, timeout: int = 60):
    """POST an MCP JSON-RPC request. Returns (status_code, parsed_body_or_text, elapsed_ms)."""
    global LAST_RAW_RESPONSE
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
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode()
            status = response.status
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        status = e.code
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    # Handle SSE-formatted responses (text/event-stream)
    if body.startswith("event:") or "\ndata:" in body or body.startswith("data:"):
        for line in body.splitlines():
            if line.startswith("data:"):
                body = line[len("data:"):].strip()
                break
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = body
    LAST_RAW_RESPONSE = {"http_status": status, "body": parsed}
    return status, parsed, elapsed_ms


def base_tool_name(gateway_tool_name: str) -> str:
    return gateway_tool_name.split("___")[1] if "___" in gateway_tool_name else gateway_tool_name


def gateway_tool_name(tool: str) -> str:
    """Gateway exposes tools as '<target-name>___<tool_name>' (target = tool with dashes)."""
    return f"{tool.replace('_', '-')}___{tool}"


# ------------------------------------------------------------------------
# STEP 0: DISCOVER DEPLOYMENT
# ------------------------------------------------------------------------
def step_discover(url_mode: str) -> tuple:
    step(0, "Descubrir el despliegue (CloudFormation outputs)")
    explain(
        "Leemos los outputs del stack CDK para NO hardcodear nada: URL del Gateway,",
        "dominio custom (CloudFront + WAF), User Pool y App Client de Cognito, tablas DynamoDB.",
    )
    outputs = get_stack_outputs()
    print()
    for key in ("GatewayUrl", "CustomDomainMcpUrl", "CloudFrontDomain", "CognitoUserPoolId",
                "CognitoAppClientId", "CognitoDiscoveryUrl", "FineGrainedAccessTableName", "WafWebAclArn"):
        if key in outputs:
            print(f"    {bold(f'{key:<28}')} {outputs[key]}")

    mcp_url = outputs["GatewayUrl"] if url_mode == "gateway" else outputs["CustomDomainMcpUrl"]
    print()
    if url_mode == "gateway":
        print(warn("  ! Modo 'gateway': se invocara la URL DIRECTA del Gateway. El WAF la BLOQUEA a proposito"))
        print(warn("    (origin cloaking): solo CloudFront inyecta el header secreto X-Origin-Verify."))
    else:
        explain(f"Endpoint MCP que usaremos (via CloudFront + WAF): {bold(mcp_url)}")
    pause()
    return outputs, mcp_url


# ------------------------------------------------------------------------
# STEP 1: SELECT USER
# ------------------------------------------------------------------------
def step_select_user(preselected: str = "") -> str:
    step(1, "Seleccionar el usuario de la DEMO")
    explain(
        "Cada usuario tiene una fila por tool en la tabla DynamoDB 'santi-bank-fine-grained-access-mapping'",
        "(PK=USER#<user>, SK=TOOL#<tool>, Allowed=true|false). Esa tabla es la UNICA fuente de verdad del FGAC.",
    )
    print()
    header = f"    {'#':<3} {'Usuario':<10} " + " ".join(f"{t:<22}" for t in ALL_TOOLS)
    print(bold(header))
    users = list(EXPECTED_PERMISSIONS)
    for idx, user in enumerate(users, start=1):
        cells = []
        for tool in ALL_TOOLS:
            cells.append(ok(f"{'✅ permitida':<22}") if tool in EXPECTED_PERMISSIONS[user] else bad(f"{'🚫 denegada':<22}"))
        print(f"    {idx:<3} {user:<10} " + " ".join(cells))
    print(f"    {'4':<3} {'<otro>':<10} {dim('cualquier username de Cognito (util para mostrar fail-closed)')}")

    if preselected:
        print(f"\n  {ok('✓')} Usuario pre-seleccionado por argumento: {bold(preselected)}")
        return preselected

    while True:
        choice = ask("Elige el usuario (1-3, o escribe el username)", "1")
        if choice in ("1", "2", "3"):
            return users[int(choice) - 1]
        if choice == "4":
            custom = ask("Username de Cognito")
            if custom:
                return custom
        elif choice:
            return choice


# ------------------------------------------------------------------------
# STEP 2: AUTHENTICATION (Cognito JWT)
# ------------------------------------------------------------------------
def step_authenticate(outputs: dict, username: str, password: str) -> str:
    step(2, f"Autenticacion: obtener el JWT de Cognito para '{username}'")
    explain(
        "El cliente (agente / MCP Inspector / Postman) NO habla con el Gateway sin identidad.",
        "Primero se autentica contra Cognito (flujo USER_PASSWORD_AUTH) y recibe un ACCESS TOKEN (JWT).",
        "El Gateway tiene configurado un inbound authorizer CUSTOM_JWT apuntando al discovery URL de Cognito:",
        f"  {dim(outputs.get('CognitoDiscoveryUrl', 'N/A'))}",
    )
    try:
        token = get_token(outputs["CognitoAppClientId"], username, password)
    except RuntimeError as e:
        print(bad(f"\n  ✗ Autenticacion FALLIDA para '{username}': {e}"))
        return ""

    print(f"\n  {ok('✓')} Access Token recibido ({len(token)} chars)")
    print(f"    {dim(token[:40] + ' ... ' + token[-20:])}")

    header, payload = decode_jwt(token)
    show_json("JWT header (algoritmo + key id usada para validar la firma):", header)
    show_json("JWT payload (claims):", payload)

    exp = payload.get("exp")
    remaining = ""
    if exp:
        remaining_s = int(exp - time.time())
        remaining = f"expira en ~{remaining_s // 60} min ({datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()})"
    print()
    explain(
        f"Claim {bold('username')} = '{payload.get('username') or payload.get('cognito:username')}'  "
        f"<- ESTE es el claim que el interceptor FGAC usa para buscar permisos en DynamoDB.",
        f"Claim {bold('client_id')} = '{payload.get('client_id')}'  <- debe estar en la lista allowedClients del Gateway.",
        f"Claim {bold('token_use')} = '{payload.get('token_use')}'  |  {remaining}",
        "La FIRMA la valida el Gateway (JWKS de Cognito) ANTES de invocar el interceptor.",
        "El interceptor NUNCA confia en headers custom (X-Client-ID, etc.): solo en el JWT ya validado.",
    )
    pause()
    return token


# ------------------------------------------------------------------------
# STEP 3: MCP HANDSHAKE (initialize)
# ------------------------------------------------------------------------
def step_mcp_initialize(url: str, token: str):
    step(3, "MCP handshake: 'initialize' contra el AgentCore Gateway")
    explain(
        "Un cliente MCP (Strands, Claude, Kiro, MCP Inspector...) inicia la sesion con 'initialize':",
        "negocia la version del protocolo y descubre las capacidades del servidor (aqui: tools).",
        "El interceptor deja pasar este metodo sin tocarlo (solo actua en tools/list y tools/call).",
    )
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "santi-bank-demo-client", "version": "1.0.0"},
        },
    }
    show_json(f"REQUEST  -> POST {url}", payload)
    status, body, ms = mcp_request(url, token, payload)
    show_json(f"RESPONSE <- HTTP {status} ({ms} ms)", body)
    if status == 200 and isinstance(body, dict) and "result" in body:
        server = body["result"].get("serverInfo", {})
        print(f"\n  {ok('✓')} Sesion MCP inicializada con {bold(server.get('name', 'AgentCore Gateway'))} "
              f"{server.get('version', '')} | protocolo {body['result'].get('protocolVersion', '?')}")
    else:
        print(warn("\n  ! El handshake no devolvio 'result'. Si el HTTP es 403 y estas en modo 'gateway',"))
        print(warn("    es el WAF (origin cloaking) haciendo su trabajo. Continuamos con tools/list."))
    pause()


# ------------------------------------------------------------------------
# STEP 4: MCP tools/list (RESPONSE interceptor filtering)
# ------------------------------------------------------------------------
def step_list_tools(url: str, token: str, username: str, verbose: bool = True) -> list:
    """Returns the list of tool dicts visible to the user."""
    if verbose:
        step(4, f"MCP 'tools/list': que tools VE el usuario '{username}'")
        explain(
            "El Gateway agrega las tools de sus 4 Lambda targets y responde tools/list.",
            "ANTES de llegar al cliente, el RESPONSE interceptor lee el JWT, consulta DynamoDB y",
            "ELIMINA de la lista las tools NO permitidas. El usuario nunca las ve.",
        )
    payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    show_json(f"REQUEST  -> POST {url}", payload)
    status, body, ms = mcp_request(url, token, payload)

    tools = (body.get("result") or {}).get("tools", []) if isinstance(body, dict) else []
    if status != 200 or (isinstance(body, dict) and "error" in body):
        show_json(f"RESPONSE <- HTTP {status} ({ms} ms)", body)
        print(bad(f"\n  ✗ tools/list fallo (HTTP {status})."))
        return []

    print(f"\n  {bold(f'RESPONSE <- HTTP {status} ({ms} ms) | {len(tools)} tools visibles')}")
    visible = sorted(base_tool_name(t["name"]) for t in tools)
    hidden = [t for t in ALL_TOOLS if t not in visible]
    for tool in tools:
        props = (tool.get("inputSchema") or {}).get("properties", {}) or {}
        required = (tool.get("inputSchema") or {}).get("required", []) or []
        params = ", ".join(f"{p}{'*' if p in required else ''}" for p in props) or "(sin parametros)"
        print(f"\n    {ok('✅')} {bold(tool['name'])}")
        print(f"       {dim((tool.get('description') or '').strip()[:110])}")
        print(f"       params: {params}")
    for tool in hidden:
        print(f"\n    {bad('🚫')} {bold(gateway_tool_name(tool))}  {bad('<- OCULTA por el RESPONSE interceptor')}")
        print(f"       {dim(ALL_TOOLS[tool])}")

    expected = sorted(EXPECTED_PERMISSIONS.get(username, []))
    print()
    if username in EXPECTED_PERMISSIONS:
        matches = visible == expected
        print((ok("  ✓ ") if matches else warn("  ! ")) +
              f"Visibles {visible} | Esperadas (seed) {expected}" +
              ("" if matches else "  <- difiere del seed: alguien cambio DynamoDB (DEMO permisos dinamicos)"))
    else:
        print(warn(f"  ! Usuario '{username}' no esta en la matriz seed -> fail-closed: {len(visible)} tools visibles."))
    if verbose:
        pause()
    return tools


# ------------------------------------------------------------------------
# STEP 5: USE THE TOOLS (tools/call) + forged calls
# ------------------------------------------------------------------------
def prompt_arguments(tool: dict, username: str) -> dict:
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties", {}) or {}
    required = set(schema.get("required", []) or [])
    if not props:
        print(dim("    (la tool no recibe parametros)"))
        return {}
    arguments = {}
    for name, spec in props.items():
        default = username if name == "username" else str(spec.get("default", ""))
        label = f"{name} ({spec.get('type', 'string')}){' *' if name in required else ''}"
        if spec.get("description"):
            label += f" - {spec['description'][:60]}"
        raw = ask(label, default)
        if raw == "" and name not in required:
            continue
        kind = spec.get("type")
        try:
            if kind == "integer":
                arguments[name] = int(raw)
            elif kind == "number":
                arguments[name] = float(raw)
            elif kind == "boolean":
                arguments[name] = raw.lower() in ("1", "true", "yes", "si", "y")
            else:
                arguments[name] = raw
        except ValueError:
            arguments[name] = raw
    return arguments


def render_tool_result(status: int, body, ms: int):
    show_json(f"RESPONSE <- HTTP {status} ({ms} ms)", body, max_chars=2500)
    if not isinstance(body, dict):
        return
    if "error" in body:
        print(bad(f"\n  🚫 JSON-RPC error {body['error'].get('code')}: {body['error'].get('message')}"))
        return
    result = body.get("result", {}) or {}
    is_error = result.get("isError", False)
    print()
    for item in result.get("content", []) or []:
        if item.get("type") != "text":
            continue
        text = item.get("text", "")
        try:
            parsed = json.loads(text)
            show_json("Resultado de la tool (parseado):" if not is_error else "Mensaje de DENY:", parsed)
        except (json.JSONDecodeError, TypeError):
            for line in text.splitlines():
                print(f"    {(bad if is_error else ok)('│')} {line}")
    if is_error:
        print(bad("\n  🚫 DENEGADO por el REQUEST interceptor: short-circuit, el Lambda target NUNCA se invoco."))
        explain(
            "HTTP 200 + isError=true (no un 4xx): asi el agente/LLM LEE la razon y puede reaccionar.",
            "Un 403 haria que muchos clientes MCP muestren un error generico y se pierda el mensaje.",
        )
    else:
        print(ok("\n  ✅ PERMITIDO: el REQUEST interceptor valido el permiso y el Lambda target respondio."))


def invoke_tool(url: str, token: str, name: str, arguments: dict, request_id: int):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    show_json(f"REQUEST  -> POST {url}", payload)
    status, body, ms = mcp_request(url, token, payload)
    render_tool_result(status, body, ms)


def demo_errors(url: str):
    print()
    print(bold("  DEMO manejo de errores (Hipotesis 2): sin token / token invalido"))
    explain("El inbound authorizer del Gateway rechaza la peticion ANTES de cualquier interceptor.")
    payload = {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}
    for label, token in (("SIN token", None), ("token INVALIDO", "invalid.jwt.token")):
        status, body, ms = mcp_request(url, token, payload)
        verdict = ok("✓ rechazado") if status in (401, 403) else bad("✗ NO rechazado")
        print(f"\n    {bold(label):<28} -> HTTP {status} ({ms} ms) {verdict}")
        print(f"      {dim(json.dumps(body, ensure_ascii=False)[:200])}")


def demo_origin_cloaking(outputs: dict, token: str):
    print()
    print(bold("  DEMO origin cloaking: solo CloudFront puede llegar al Gateway (WAF + Secrets Manager)"))
    explain(
        "CloudFront inyecta el header secreto X-Origin-Verify. El WAF asociado al Gateway BLOQUEA",
        "todo lo que no lo traiga, AUNQUE el JWT sea valido. Asi nadie se salta el WAF/CloudFront.",
    )
    payload = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
    status, body, ms = mcp_request(outputs["GatewayUrl"], token, payload)
    blocked = status == 403 or (isinstance(body, dict) and (body.get("error") or {}).get("code") == -32002)
    print(f"\n    {bold('Gateway DIRECTO'):<28} -> HTTP {status} ({ms} ms) "
          f"{ok('✓ BLOQUEADO por WAF') if blocked else bad('✗ NO bloqueado')}")
    print(f"      {dim(json.dumps(body, ensure_ascii=False)[:200] if isinstance(body, dict) else str(body)[:200])}")
    status, body, ms = mcp_request(outputs["CustomDomainMcpUrl"], token, payload)
    n = len(((body.get("result") or {}).get("tools", [])) if isinstance(body, dict) else [])
    print(f"    {bold('Via CloudFront'):<28} -> HTTP {status} ({ms} ms) "
          f"{ok(f'✓ PERMITIDO ({n} tools)') if status == 200 and n else bad('✗ fallo')}")


def show_dynamic_permissions_hint(outputs: dict, username: str, visible: list):
    """Print grant/revoke commands based on what the user CURRENTLY sees (live state, not the seed)."""
    table = outputs.get("FineGrainedAccessTableName", "santi-bank-fine-grained-access-mapping")
    print()
    print(bold("  DEMO permisos dinamicos (sin redeploy): cambia DynamoDB y vuelve a listar con [L]"))
    explain("El interceptor consulta DynamoDB en CADA peticion: el cambio aplica de inmediato, sin redeploy ni cache.")
    for tool in ALL_TOOLS:
        allowed = "true" if tool not in visible else "false"
        action = "OTORGAR" if allowed == "true" else "REVOCAR"
        print(f"\n    {dim('# ' + action + ' ' + tool + ' a ' + username)}")
        print(f"    {dim('$')} aws dynamodb update-item --region {REGION} --table-name {table} \\")
        print(f"        --key '{{\"PK\":{{\"S\":\"USER#{username}\"}},\"SK\":{{\"S\":\"TOOL#{tool}\"}}}}' \\")
        print(f"        --update-expression 'SET Allowed = :a' --expression-attribute-values '{{\":a\":{{\"BOOL\":{allowed}}}}}'")


def step_interactive_menu(outputs: dict, url: str, token: str, username: str, tools: list, password: str):
    """Main interactive loop. Returns (username, token, tools) so the caller can re-run if user switches."""
    step(5, f"USAR las tools como '{username}' (tools/call) - menu interactivo")
    explain(
        "Cada tools/call pasa PRIMERO por el REQUEST interceptor: si el usuario NO tiene permiso,",
        "el Gateway responde de inmediato (short-circuit) y el Lambda target nunca corre.",
        "Tambien puedes 'armar' una peticion a una tool OCULTA para demostrar que verla != ejecutarla.",
    )
    request_id = 10
    while True:
        visible = sorted(base_tool_name(t["name"]) for t in tools)
        hidden = [t for t in ALL_TOOLS if t not in visible]
        print()
        print(bold(f"  ── Menu ({username}) ────────────────────────────────────────────────"))
        for idx, tool in enumerate(tools, start=1):
            print(f"    [{idx}] {ok('▶')} {tool['name']:<45} {dim((tool.get('description') or '')[:45])}")
        if hidden:
            print(f"    [F] {bad('🚫')} Forzar tools/call a una tool OCULTA (peticion armada): {', '.join(hidden)}")
        print(f"    [L] 🔄 Volver a listar tools (tools/list) - util tras cambiar permisos en DynamoDB")
        print(f"    [D] 🔥 Ver comandos para OTORGAR/REVOCAR permisos dinamicamente (DynamoDB)")
        print(f"    [U] 👤 Cambiar de usuario (nueva autenticacion)")
        print(f"    [E] ⚠️  Demo manejo de errores (sin token / token invalido)")
        print(f"    [W] 🧱 Demo origin cloaking (Gateway directo vs CloudFront)")
        print(f"    [R] 🧾 Ver la ultima respuesta RAW completa")
        print(f"    [Q] Salir")
        choice = ask("Opcion", "1" if tools else "Q").upper()

        if choice == "Q":
            return None
        if choice == "U":
            return "SWITCH_USER"
        if choice == "L":
            tools = step_list_tools(url, token, username, verbose=False)
            continue
        if choice == "D":
            show_dynamic_permissions_hint(outputs, username, visible)
            continue
        if choice == "E":
            demo_errors(url)
            continue
        if choice == "W":
            demo_origin_cloaking(outputs, token)
            continue
        if choice == "R":
            show_json("Ultima respuesta RAW:", LAST_RAW_RESPONSE, max_chars=20000)
            continue
        if choice == "F" and hidden:
            print()
            for idx, tool in enumerate(hidden, start=1):
                print(f"    [{idx}] {bad('🚫')} {gateway_tool_name(tool)}  {dim(ALL_TOOLS[tool])}")
            pick = ask("Tool oculta a forzar", "1")
            if not pick.isdigit() or not (1 <= int(pick) <= len(hidden)):
                continue
            tool = hidden[int(pick) - 1]
            arguments = {} if tool == "consulta_canales" else {"username": username}
            print(warn(f"\n  ⚔️  Peticion ARMADA: '{username}' intenta ejecutar '{tool}' aunque NO la ve en tools/list"))
            request_id += 1
            invoke_tool(url, token, gateway_tool_name(tool), arguments, request_id)
            pause()
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(tools):
            tool = tools[int(choice) - 1]
            print(f"\n  {bold('Tool:')} {tool['name']}")
            arguments = prompt_arguments(tool, username)
            request_id += 1
            invoke_tool(url, token, tool["name"], arguments, request_id)
            pause()
            continue
        print(warn("  ! Opcion no valida."))


# ------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------
def main():
    global PAUSE_ENABLED, REGION, STACK_NAME

    parser = argparse.ArgumentParser(description="santi-bank FGAC interactive step-by-step DEMO")
    parser.add_argument("--user", default="", help="Pre-select the demo user (santi|jimmy|joacho|<other>)")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Cognito password (or env SANTI_BANK_PASSWORD)")
    parser.add_argument("--url-mode", choices=["gateway", "domain"], default="domain",
                        help="domain = CloudFront custom domain (default) | gateway = direct Gateway URL (WAF blocks)")
    parser.add_argument("--stack-name", default=STACK_NAME)
    parser.add_argument("--region", default=REGION)
    parser.add_argument("--no-pause", action="store_true", help="Do not wait for ENTER between steps")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    PAUSE_ENABLED = not args.no_pause
    REGION, STACK_NAME = args.region, args.stack_name
    C.enabled = not (args.no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty())

    banner()
    try:
        outputs, mcp_url = step_discover(args.url_mode)
        username = args.user
        while True:
            username = step_select_user(username)
            token = step_authenticate(outputs, username, args.password)
            if not token:
                username = ""
                pause("ENTER para elegir otro usuario...")
                continue
            step_mcp_initialize(mcp_url, token)
            tools = step_list_tools(mcp_url, token, username)
            outcome = step_interactive_menu(outputs, mcp_url, token, username, tools, args.password)
            if outcome != "SWITCH_USER":
                break
            username = ""
    except KeyboardInterrupt:
        print("\n")
    except subprocess.CalledProcessError as e:
        print(bad(f"\n  ✗ Error ejecutando AWS CLI: {e.stderr.strip() if e.stderr else e}"))
        sys.exit(1)

    print(accent("\n  Gracias por ver la demo de santi-bank FGAC 🏦🛡️  Nunca pares de aprender AWS!"))


if __name__ == "__main__":
    main()
