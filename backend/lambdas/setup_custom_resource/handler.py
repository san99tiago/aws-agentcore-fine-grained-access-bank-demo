"""
santi-bank :: CloudFormation CUSTOM RESOURCE :: Setup Users & Seed Data

Custom Resource Lambda (invoked via CDK Provider Framework) that on CREATE and
UPDATE events:

1. Creates the 3 Cognito users: "santi", "jimmy", "joacho" (password
   "Testing123." set as PERMANENT, no email verification needed).
2. Seeds the "santi-bank-users-data" table (profiles, balances, cards,
   preferences per user).
3. Seeds the "santi-bank-channels-data" table (SVP, SVN, MiBancoApp,
   Valores santi-bank, SantiBot WhatsApp).
4. Seeds the "santi-bank-fine-grained-access-mapping" table with the
   user -> tool permissions matrix:
       - santi:  ALL tools
       - jimmy:  consulta_saldo, consulta_preferencias, consulta_tarjetas (NO consulta_canales)
       - joacho: consulta_saldo, consulta_canales (NO consulta_tarjetas, NO consulta_preferencias)

All operations are IDEMPOTENT so CREATE/UPDATE both work safely.
"""

# Built-in imports
import json
import os
from decimal import Decimal

# External imports
import boto3
from botocore.exceptions import ClientError

USER_POOL_ID = os.environ["USER_POOL_ID"]
USERS_TABLE_NAME = os.environ["USERS_TABLE_NAME"]
CHANNELS_TABLE_NAME = os.environ["CHANNELS_TABLE_NAME"]
FGAC_TABLE_NAME = os.environ["FGAC_TABLE_NAME"]
USERS_PASSWORD = os.environ.get("USERS_PASSWORD", "Testing123.")

cognito_client = boto3.client("cognito-idp")
dynamodb = boto3.resource("dynamodb")
users_table = dynamodb.Table(USERS_TABLE_NAME)
channels_table = dynamodb.Table(CHANNELS_TABLE_NAME)
fgac_table = dynamodb.Table(FGAC_TABLE_NAME)

COGNITO_USERS = ["santi", "jimmy", "joacho"]

# ---------------------------------------------------------------------------
# FGAC PERMISSIONS MATRIX (user -> {tool: allowed})
# Explicit Allowed=false items make the demo table easy to read and allow
# flipping a single boolean in DynamoDB to grant/revoke access DYNAMICALLY.
# ---------------------------------------------------------------------------
PERMISSIONS_MATRIX = {
    "santi": {
        "consulta_saldo": True,
        "consulta_tarjetas": True,
        "consulta_canales": True,
        "consulta_preferencias": True,
    },
    "jimmy": {
        "consulta_saldo": True,
        "consulta_tarjetas": True,
        "consulta_canales": False,  # <- jimmy can NOT see/execute canales
        "consulta_preferencias": True,
    },
    "joacho": {
        "consulta_saldo": True,
        "consulta_tarjetas": False,  # <- joacho can NOT see/execute tarjetas
        "consulta_canales": True,
        "consulta_preferencias": False,  # <- joacho can NOT see/execute preferencias
    },
}

USERS_DATA = [
    # ------------------------- SANTI -------------------------
    {"PK": "USER#santi", "SK": "PROFILE", "full_name": "Santiago Garcia Arango",
     "document": "CC-1036800001", "segment": "Preferencial", "email": "santi@santi-bank.com"},
    {"PK": "USER#santi", "SK": "BALANCE", "account_number": "***1234", "account_type": "Ahorros",
     "available_balance": Decimal("15750000.50"), "total_balance": Decimal("16250000.50"),
     "currency": "COP", "last_updated": "2026-07-26T10:00:00Z"},
    {"PK": "USER#santi", "SK": "CARD#CREDIT-VISA-4321", "card_type": "CREDITO", "brand": "VISA",
     "masked_number": "****-****-****-4321", "status": "ACTIVA",
     "credit_limit": Decimal("20000000"), "available_credit": Decimal("18500000"),
     "expiration_date": "2029-05"},
    {"PK": "USER#santi", "SK": "CARD#DEBIT-MASTER-9876", "card_type": "DEBITO", "brand": "MASTERCARD",
     "masked_number": "****-****-****-9876", "status": "ACTIVA",
     "credit_limit": Decimal("0"), "available_credit": Decimal("0"),
     "expiration_date": "2028-11"},
    {"PK": "USER#santi", "SK": "PREFERENCES", "nickname": "Santi Crack", "color_app": "Negro",
     "tope_cajero": Decimal("2000000"), "tope_transaccion": Decimal("10000000"),
     "contacto_emergencia": "+57 300 111 2233", "idioma": "es-CO", "notificaciones_push": True},
    # ------------------------- JIMMY -------------------------
    {"PK": "USER#jimmy", "SK": "PROFILE", "full_name": "Jimmy santi-bank Dev",
     "document": "CC-1036800002", "segment": "Personal", "email": "jimmy@santi-bank.com"},
    {"PK": "USER#jimmy", "SK": "BALANCE", "account_number": "***5678", "account_type": "Corriente",
     "available_balance": Decimal("3250000.00"), "total_balance": Decimal("3250000.00"),
     "currency": "COP", "last_updated": "2026-07-26T10:00:00Z"},
    {"PK": "USER#jimmy", "SK": "CARD#CREDIT-AMEX-1111", "card_type": "CREDITO", "brand": "AMEX",
     "masked_number": "****-****-****-1111", "status": "ACTIVA",
     "credit_limit": Decimal("8000000"), "available_credit": Decimal("4200000"),
     "expiration_date": "2027-09"},
    {"PK": "USER#jimmy", "SK": "PREFERENCES", "nickname": "JimmyDev", "color_app": "Blanco",
     "tope_cajero": Decimal("800000"), "tope_transaccion": Decimal("3000000"),
     "contacto_emergencia": "+57 301 444 5566", "idioma": "es-CO", "notificaciones_push": True},
    # ------------------------- JOACHO -------------------------
    {"PK": "USER#joacho", "SK": "PROFILE", "full_name": "Joacho Platform Engineer",
     "document": "CC-1036800003", "segment": "Personal", "email": "joacho@santi-bank.com"},
    {"PK": "USER#joacho", "SK": "BALANCE", "account_number": "***9012", "account_type": "Ahorros",
     "available_balance": Decimal("890000.75"), "total_balance": Decimal("890000.75"),
     "currency": "COP", "last_updated": "2026-07-26T10:00:00Z"},
    {"PK": "USER#joacho", "SK": "CARD#DEBIT-VISA-2222", "card_type": "DEBITO", "brand": "VISA",
     "masked_number": "****-****-****-2222", "status": "BLOQUEADA",
     "credit_limit": Decimal("0"), "available_credit": Decimal("0"),
     "expiration_date": "2027-03"},
    {"PK": "USER#joacho", "SK": "PREFERENCES", "nickname": "Joachito", "color_app": "Blanco",
     "tope_cajero": Decimal("500000"), "tope_transaccion": Decimal("1500000"),
     "contacto_emergencia": "+57 302 777 8899", "idioma": "es-CO", "notificaciones_push": False},
]

CHANNELS_DATA = [
    {"PK": "CHANNEL#SVP", "SK": "STATUS", "channel_name": "Sucursal Virtual Personas (SVP)",
     "status": "OPERATIVO", "availability_pct": Decimal("99.95"),
     "last_incident": "2026-07-10T03:20:00Z", "message": "Operacion normal"},
    {"PK": "CHANNEL#SVN", "SK": "STATUS", "channel_name": "Sucursal Virtual Negocios (SVN)",
     "status": "OPERATIVO", "availability_pct": Decimal("99.90"),
     "last_incident": "2026-06-28T14:05:00Z", "message": "Operacion normal"},
    {"PK": "CHANNEL#APP-MIBANCOAPP", "SK": "STATUS", "channel_name": "MiBancoApp (App)",
     "status": "DEGRADADO", "availability_pct": Decimal("97.30"),
     "last_incident": "2026-07-26T08:45:00Z",
     "message": "Intermitencia en biometria facial - equipo trabajando en la solucion"},
    {"PK": "CHANNEL#VALORES", "SK": "STATUS", "channel_name": "Valores santi-bank",
     "status": "OPERATIVO", "availability_pct": Decimal("99.99"),
     "last_incident": "2026-05-15T11:00:00Z", "message": "Operacion normal"},
    {"PK": "CHANNEL#SANTIBOT", "SK": "STATUS", "channel_name": "SantiBot (WhatsApp)",
     "status": "MANTENIMIENTO", "availability_pct": Decimal("95.00"),
     "last_incident": "2026-07-25T22:00:00Z",
     "message": "Ventana de mantenimiento programado hasta 2026-07-27 02:00 UTC"},
]


def create_cognito_users():
    """Create the demo Cognito users with permanent password (idempotent)."""
    for username in COGNITO_USERS:
        print(f"[SETUP][COGNITO] Creating user '{username}' in pool '{USER_POOL_ID}'...")
        try:
            cognito_client.admin_create_user(
                UserPoolId=USER_POOL_ID,
                Username=username,
                UserAttributes=[
                    {"Name": "email", "Value": f"{username}@santi-bank.com"},
                    {"Name": "email_verified", "Value": "true"},
                ],
                MessageAction="SUPPRESS",
            )
            print(f"[SETUP][COGNITO] User '{username}' created")
        except ClientError as e:
            if e.response["Error"]["Code"] == "UsernameExistsException":
                print(f"[SETUP][COGNITO] User '{username}' already exists (idempotent, OK)")
            else:
                raise

        # Always (re)set the permanent password so UPDATE events also work
        cognito_client.admin_set_user_password(
            UserPoolId=USER_POOL_ID,
            Username=username,
            Password=USERS_PASSWORD,
            Permanent=True,
        )
        print(f"[SETUP][COGNITO] Permanent password set for '{username}'")


def seed_users_data():
    """Seed the santi-bank-users-data table (idempotent put_item overwrite)."""
    print(f"[SETUP][DDB] Seeding {len(USERS_DATA)} items into '{USERS_TABLE_NAME}'...")
    with users_table.batch_writer() as batch:
        for item in USERS_DATA:
            batch.put_item(Item=item)
    print("[SETUP][DDB] users-data seeded OK")


# Legacy keys removed on UPDATE (renamed channels from older seed versions)
LEGACY_CHANNEL_KEYS = [
    {"PK": "CHANNEL#APP-MIBANCOLOMBIA", "SK": "STATUS"},
    {"PK": "CHANNEL#TABOT", "SK": "STATUS"},
]


def seed_channels_data():
    """Seed the santi-bank-channels-data table (idempotent put_item overwrite)."""
    for legacy_key in LEGACY_CHANNEL_KEYS:
        print(f"[SETUP][DDB] Removing legacy channel item (if exists): {legacy_key}")
        channels_table.delete_item(Key=legacy_key)
    print(f"[SETUP][DDB] Seeding {len(CHANNELS_DATA)} items into '{CHANNELS_TABLE_NAME}'...")
    with channels_table.batch_writer() as batch:
        for item in CHANNELS_DATA:
            batch.put_item(Item=item)
    print("[SETUP][DDB] channels-data seeded OK")


def seed_fgac_mapping():
    """Seed the santi-bank-fine-grained-access-mapping table (permissions matrix)."""
    items = []
    for username, tools in PERMISSIONS_MATRIX.items():
        for tool_name, allowed in tools.items():
            items.append(
                {
                    "PK": f"USER#{username}",
                    "SK": f"TOOL#{tool_name}",
                    "Allowed": allowed,
                    "GrantedBy": "santi-bank-custom-resource",
                }
            )
    print(f"[SETUP][DDB] Seeding {len(items)} permission items into '{FGAC_TABLE_NAME}'...")
    print(f"[SETUP][DDB] Permissions matrix: {json.dumps(PERMISSIONS_MATRIX)}")
    with fgac_table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)
    print("[SETUP][DDB] fine-grained-access-mapping seeded OK")


def lambda_handler(event, context):
    """CloudFormation Custom Resource entrypoint (CDK Provider Framework)."""
    print("=" * 80)
    print(f"[SETUP] Received CloudFormation event: {json.dumps(event, default=str)}")

    request_type = event.get("RequestType", "Create")
    physical_id = f"santi-bank-setup-users-and-seed-data-{USER_POOL_ID}"

    if request_type in ("Create", "Update"):
        print(f"[SETUP] Handling '{request_type}' -> creating users + seeding all tables")
        create_cognito_users()
        seed_users_data()
        seed_channels_data()
        seed_fgac_mapping()
        print("[SETUP] ALL DONE - users created and tables populated")
    elif request_type == "Delete":
        # Users are deleted together with the User Pool, tables with the stack.
        print("[SETUP] Handling 'Delete' -> no-op (resources removed with the stack)")

    return {"PhysicalResourceId": physical_id}
