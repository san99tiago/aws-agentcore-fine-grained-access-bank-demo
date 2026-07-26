"""
santi-bank :: Tool Lambda :: CONSULTA PREFERENCIAS

AgentCore Gateway Lambda Target that returns the app preferences of a given
user (nickname, color-app, tope-cajero, tope-transaccion, contacto-emergencia,
etc.) by querying the "santi-bank-users-data" DynamoDB table.

Input (MCP tool arguments): {"username": "<username>"}
"""

# Built-in imports
import json
import os

# External imports
import boto3

USERS_TABLE_NAME = os.environ.get("USERS_TABLE_NAME", "santi-bank-users-data")

dynamodb = boto3.resource("dynamodb")
users_table = dynamodb.Table(USERS_TABLE_NAME)


def lambda_handler(event, context):
    """Main handler for the consulta_preferencias tool."""
    print("=" * 80)
    print("[CONSULTA-PREFERENCIAS] Received event:")
    print(json.dumps(event, default=str))

    tool_name = "unknown"
    if context.client_context and getattr(context.client_context, "custom", None):
        print(f"[CONSULTA-PREFERENCIAS] Client context custom: {context.client_context.custom}")
        tool_name = context.client_context.custom.get("bedrockAgentCoreToolName", "unknown")
    print(f"[CONSULTA-PREFERENCIAS] Resolved tool name: {tool_name}")

    username = str(event.get("username", "")).strip().lower()
    print(f"[CONSULTA-PREFERENCIAS] Requested username: '{username}'")

    if not username:
        error_msg = "ERROR: El parametro 'username' es requerido para consultar las preferencias."
        print(f"[CONSULTA-PREFERENCIAS] {error_msg}")
        return {"error": error_msg}

    try:
        print(f"[CONSULTA-PREFERENCIAS] Querying '{USERS_TABLE_NAME}' PK=USER#{username} SK=PREFERENCES")
        response = users_table.get_item(Key={"PK": f"USER#{username}", "SK": "PREFERENCES"})
        item = response.get("Item")
        print(f"[CONSULTA-PREFERENCIAS] Preferences item found: {json.dumps(item, default=str)}")

        if not item:
            not_found_msg = f"No se encontraron preferencias para el usuario '{username}' en santi-bank."
            print(f"[CONSULTA-PREFERENCIAS] {not_found_msg}")
            return {"error": not_found_msg}

        result = {
            "banco": "santi-bank",
            "tool": "consulta_preferencias",
            "username": username,
            "preferencias": {
                "nickname": item.get("nickname", "N/A"),
                "color_app": item.get("color_app", "N/A"),
                "tope_cajero": str(item.get("tope_cajero", "N/A")),
                "tope_transaccion": str(item.get("tope_transaccion", "N/A")),
                "contacto_emergencia": item.get("contacto_emergencia", "N/A"),
                "idioma": item.get("idioma", "es-CO"),
                "notificaciones_push": bool(item.get("notificaciones_push", True)),
            },
        }
        print(f"[CONSULTA-PREFERENCIAS] SUCCESS - Returning result: {json.dumps(result, default=str)}")
        return result

    except Exception as e:
        print(f"[CONSULTA-PREFERENCIAS] EXCEPTION: {type(e).__name__}: {e}")
        return {"error": f"Error interno consultando las preferencias: {str(e)}"}
