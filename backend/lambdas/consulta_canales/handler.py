"""
santi-bank :: Tool Lambda :: CONSULTA CANALES

AgentCore Gateway Lambda Target that returns the CURRENT STATUS of ALL the
santi-bank channels by scanning the "santi-bank-channels-data" DynamoDB table.

Channels include: Sucursal Virtual Personas (SVP), Sucursal Virtual Negocios
(SVN), MiBancoApp (App), Valores santi-bank, SantiBot (WhatsApp), etc.

Input (MCP tool arguments): {} (no parameters required)
"""

# Built-in imports
import json
import os

# External imports
import boto3

CHANNELS_TABLE_NAME = os.environ.get("CHANNELS_TABLE_NAME", "santi-bank-channels-data")

dynamodb = boto3.resource("dynamodb")
channels_table = dynamodb.Table(CHANNELS_TABLE_NAME)


def lambda_handler(event, context):
    """Main handler for the consulta_canales tool."""
    print("=" * 80)
    print("[CONSULTA-CANALES] Received event:")
    print(json.dumps(event, default=str))

    tool_name = "unknown"
    if context.client_context and getattr(context.client_context, "custom", None):
        print(f"[CONSULTA-CANALES] Client context custom: {context.client_context.custom}")
        tool_name = context.client_context.custom.get("bedrockAgentCoreToolName", "unknown")
    print(f"[CONSULTA-CANALES] Resolved tool name: {tool_name}")

    try:
        print(f"[CONSULTA-CANALES] Scanning ALL items from table '{CHANNELS_TABLE_NAME}'")
        items = []
        response = channels_table.scan()
        items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            print("[CONSULTA-CANALES] Paginating scan...")
            response = channels_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        print(f"[CONSULTA-CANALES] Found {len(items)} channel items: {json.dumps(items, default=str)}")

        channels = []
        for item in items:
            channels.append(
                {
                    "canal_id": item.get("PK", "").replace("CHANNEL#", ""),
                    "nombre": item.get("channel_name", "N/A"),
                    "estado": item.get("status", "N/A"),
                    "disponibilidad_pct": str(item.get("availability_pct", "N/A")),
                    "ultimo_incidente": item.get("last_incident", "N/A"),
                    "mensaje": item.get("message", ""),
                }
            )

        result = {
            "banco": "santi-bank",
            "tool": "consulta_canales",
            "total_canales": len(channels),
            "canales": channels,
        }
        print(f"[CONSULTA-CANALES] SUCCESS - Returning result: {json.dumps(result, default=str)}")
        return result

    except Exception as e:
        print(f"[CONSULTA-CANALES] EXCEPTION: {type(e).__name__}: {e}")
        return {"error": f"Error interno consultando los canales: {str(e)}"}
