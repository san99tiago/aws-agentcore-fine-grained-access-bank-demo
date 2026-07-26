"""
santi-bank :: Tool Lambda :: CONSULTA SALDO

AgentCore Gateway Lambda Target that returns the balance (saldo) of a given
user by querying the "santi-bank-users-data" DynamoDB table.

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
    """Main handler for the consulta_saldo tool."""
    print("=" * 80)
    print("[CONSULTA-SALDO] Received event:")
    print(json.dumps(event, default=str))

    # AgentCore Gateway passes tool metadata via the Lambda client context
    tool_name = "unknown"
    if context.client_context and getattr(context.client_context, "custom", None):
        print(f"[CONSULTA-SALDO] Client context custom: {context.client_context.custom}")
        tool_name = context.client_context.custom.get("bedrockAgentCoreToolName", "unknown")
    print(f"[CONSULTA-SALDO] Resolved tool name: {tool_name}")

    username = str(event.get("username", "")).strip().lower()
    print(f"[CONSULTA-SALDO] Requested username: '{username}'")

    if not username:
        error_msg = "ERROR: El parametro 'username' es requerido para consultar el saldo."
        print(f"[CONSULTA-SALDO] {error_msg}")
        return {"error": error_msg}

    try:
        print(f"[CONSULTA-SALDO] Querying DynamoDB table '{USERS_TABLE_NAME}' PK=USER#{username} SK=BALANCE")
        balance_response = users_table.get_item(Key={"PK": f"USER#{username}", "SK": "BALANCE"})
        profile_response = users_table.get_item(Key={"PK": f"USER#{username}", "SK": "PROFILE"})

        balance_item = balance_response.get("Item")
        profile_item = profile_response.get("Item")
        print(f"[CONSULTA-SALDO] Balance item found: {json.dumps(balance_item, default=str)}")
        print(f"[CONSULTA-SALDO] Profile item found: {json.dumps(profile_item, default=str)}")

        if not balance_item:
            not_found_msg = f"No se encontro informacion de saldo para el usuario '{username}' en santi-bank."
            print(f"[CONSULTA-SALDO] {not_found_msg}")
            return {"error": not_found_msg}

        result = {
            "banco": "santi-bank",
            "tool": "consulta_saldo",
            "username": username,
            "nombre_completo": (profile_item or {}).get("full_name", "N/A"),
            "cuenta": balance_item.get("account_number", "N/A"),
            "tipo_cuenta": balance_item.get("account_type", "N/A"),
            "saldo_disponible": str(balance_item.get("available_balance", "0")),
            "saldo_total": str(balance_item.get("total_balance", "0")),
            "moneda": balance_item.get("currency", "COP"),
            "ultima_actualizacion": balance_item.get("last_updated", "N/A"),
        }
        print(f"[CONSULTA-SALDO] SUCCESS - Returning result: {json.dumps(result, default=str)}")
        return result

    except Exception as e:
        print(f"[CONSULTA-SALDO] EXCEPTION: {type(e).__name__}: {e}")
        return {"error": f"Error interno consultando el saldo: {str(e)}"}
