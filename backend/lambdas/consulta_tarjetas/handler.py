"""
santi-bank :: Tool Lambda :: CONSULTA TARJETAS

AgentCore Gateway Lambda Target that returns the credit/debit cards of a given
user by querying the "santi-bank-users-data" DynamoDB table.

Input (MCP tool arguments): {"username": "<username>"}
"""

# Built-in imports
import json
import os

# External imports
import boto3
from boto3.dynamodb.conditions import Key

USERS_TABLE_NAME = os.environ.get("USERS_TABLE_NAME", "santi-bank-users-data")

dynamodb = boto3.resource("dynamodb")
users_table = dynamodb.Table(USERS_TABLE_NAME)


def lambda_handler(event, context):
    """Main handler for the consulta_tarjetas tool."""
    print("=" * 80)
    print("[CONSULTA-TARJETAS] Received event:")
    print(json.dumps(event, default=str))

    tool_name = "unknown"
    if context.client_context and getattr(context.client_context, "custom", None):
        print(f"[CONSULTA-TARJETAS] Client context custom: {context.client_context.custom}")
        tool_name = context.client_context.custom.get("bedrockAgentCoreToolName", "unknown")
    print(f"[CONSULTA-TARJETAS] Resolved tool name: {tool_name}")

    username = str(event.get("username", "")).strip().lower()
    print(f"[CONSULTA-TARJETAS] Requested username: '{username}'")

    if not username:
        error_msg = "ERROR: El parametro 'username' es requerido para consultar las tarjetas."
        print(f"[CONSULTA-TARJETAS] {error_msg}")
        return {"error": error_msg}

    try:
        print(f"[CONSULTA-TARJETAS] Querying '{USERS_TABLE_NAME}' PK=USER#{username} SK begins_with CARD#")
        response = users_table.query(
            KeyConditionExpression=Key("PK").eq(f"USER#{username}") & Key("SK").begins_with("CARD#")
        )
        items = response.get("Items", [])
        print(f"[CONSULTA-TARJETAS] Found {len(items)} card items: {json.dumps(items, default=str)}")

        if not items:
            not_found_msg = f"No se encontraron tarjetas para el usuario '{username}' en santi-bank."
            print(f"[CONSULTA-TARJETAS] {not_found_msg}")
            return {"error": not_found_msg}

        cards = []
        for item in items:
            cards.append(
                {
                    "tipo": item.get("card_type", "N/A"),
                    "franquicia": item.get("brand", "N/A"),
                    "numero_enmascarado": item.get("masked_number", "N/A"),
                    "estado": item.get("status", "N/A"),
                    "cupo_total": str(item.get("credit_limit", "N/A")),
                    "cupo_disponible": str(item.get("available_credit", "N/A")),
                    "fecha_expiracion": item.get("expiration_date", "N/A"),
                }
            )

        result = {
            "banco": "santi-bank",
            "tool": "consulta_tarjetas",
            "username": username,
            "total_tarjetas": len(cards),
            "tarjetas": cards,
        }
        print(f"[CONSULTA-TARJETAS] SUCCESS - Returning result: {json.dumps(result, default=str)}")
        return result

    except Exception as e:
        print(f"[CONSULTA-TARJETAS] EXCEPTION: {type(e).__name__}: {e}")
        return {"error": f"Error interno consultando las tarjetas: {str(e)}"}
