#!/usr/bin/env python3

# Built-in imports
import os
import sys

# External imports
import aws_cdk as cdk

# Own imports (allow running "python3 infrastructure/cdk/app.py" from repo root)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from helpers.add_tags import add_tags_to_app
from stacks.cdk_santi_bank_stack import SantiBankFineAccessStack

print("--> Deployment AWS configuration (safety first):")
print("CDK_DEFAULT_ACCOUNT", os.environ.get("CDK_DEFAULT_ACCOUNT"))
print("CDK_DEFAULT_REGION", os.environ.get("CDK_DEFAULT_REGION"))

app: cdk.App = cdk.App()

# Configurations for the deployment (obtained from env vars and CDK context)
DEPLOYMENT_ENVIRONMENT = os.environ.get("DEPLOYMENT_ENVIRONMENT", "dev")
MAIN_RESOURCES_NAME = app.node.try_get_context("app_config")[DEPLOYMENT_ENVIRONMENT]["main_resources_name"]
APP_CONFIG = app.node.try_get_context("app_config")[DEPLOYMENT_ENVIRONMENT]

# STACK 1: santi-bank Fine-Grained Access Control demo (AgentCore Gateway)
SantiBankFineAccessStack(
    app,
    f"{MAIN_RESOURCES_NAME}-fine-access-{DEPLOYMENT_ENVIRONMENT}",
    MAIN_RESOURCES_NAME,
    APP_CONFIG,
    env={
        "account": os.environ.get("CDK_DEFAULT_ACCOUNT"),
        "region": os.environ.get("CDK_DEFAULT_REGION"),
    },
    description=f"Stack for {MAIN_RESOURCES_NAME} AgentCore Gateway Fine-Grained Access Control demo in {DEPLOYMENT_ENVIRONMENT} environment",
)

# Apply global tags
add_tags_to_app(app, MAIN_RESOURCES_NAME, DEPLOYMENT_ENVIRONMENT)

app.synth()
