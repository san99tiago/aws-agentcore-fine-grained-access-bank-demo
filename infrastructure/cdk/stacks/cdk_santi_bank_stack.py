# Built-in imports
import os

# External imports
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    CustomResource,
    Fn,
    aws_bedrockagentcore as agentcore,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_cognito as cognito,
    aws_dynamodb as dynamodb,
    aws_lambda,
    aws_logs as logs,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    custom_resources as cr,
)
from constructs import Construct

# Path to the Lambda source code (repo_root/backend/lambdas)
LAMBDAS_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "backend", "lambdas")
)


class SantiBankFineAccessStack(Stack):
    """
    Class to create the santi-bank Fine-Grained Access Control demo resources:
    DynamoDB tables (data + FGAC mapping), Cognito User Pool (inbound auth),
    AgentCore Gateway with Lambda Interceptors (REQUEST + RESPONSE), 4 tool
    Lambda targets, a Custom Resource to create users/seed data, and a custom
    domain (Route53 + ACM + CloudFront) pointing to the Gateway MCP endpoint.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        main_resources_name: str,
        app_config: dict,
        **kwargs,
    ) -> None:
        """
        :param scope (Construct): Parent of this stack, usually an 'App' or a 'Stage'.
        :param construct_id (str): The construct ID of this stack.
        :param main_resources_name (str): The main unique identifier of this stack.
        :param app_config (dict): Dictionary with relevant configuration values for the stack.
        """
        super().__init__(scope, construct_id, **kwargs)

        # Input parameters
        self.construct_id = construct_id
        self.main_resources_name = main_resources_name
        self.app_config = app_config
        self.deployment_environment = self.app_config["deployment_environment"]

        # Main methods for the deployment
        self.create_dynamodb_tables()
        self.create_cognito_user_pool()
        self.create_tool_lambda_functions()
        self.create_fgac_interceptor_lambda()
        self.create_agentcore_gateway()
        self.create_gateway_lambda_targets()
        self.create_setup_custom_resource()
        self.create_custom_domain_with_cloudfront()
        self.create_outputs()

    def create_dynamodb_tables(self):
        """
        Method to create the 3 DynamoDB tables (on-demand, PK/SK single-table
        design): users data, channels data and fine-grained access mapping.
        Note: table names are explicitly defined by the customer scenario
        (santi-bank-users-data, santi-bank-channels-data,
        santi-bank-fine-grained-access-mapping).
        """
        removal_policy = (
            RemovalPolicy.RETAIN
            if self.deployment_environment == "prod"
            else RemovalPolicy.DESTROY
        )

        self.users_table = dynamodb.Table(
            self,
            "DynamoDB-UsersData",
            table_name=self.app_config["users_table_name"],
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=removal_policy,
        )

        self.channels_table = dynamodb.Table(
            self,
            "DynamoDB-ChannelsData",
            table_name=self.app_config["channels_table_name"],
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=removal_policy,
        )

        self.fgac_table = dynamodb.Table(
            self,
            "DynamoDB-FineGrainedAccessMapping",
            table_name=self.app_config["fine_grained_access_table_name"],
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=removal_policy,
        )

    def create_cognito_user_pool(self):
        """
        Method to create the Cognito User Pool (INBOUND AUTH for the AgentCore
        Gateway) WITHOUT self-registration, and an App Client that supports
        USER_PASSWORD_AUTH so the demo users can obtain JWT Access Tokens.
        """
        self.user_pool = cognito.UserPool(
            self,
            "Cognito-UserPool",
            user_pool_name=f"{self.main_resources_name}-user-pool-{self.deployment_environment}",
            self_sign_up_enabled=False,  # NO user registration allowed
            sign_in_aliases=cognito.SignInAliases(username=True),
            account_recovery=cognito.AccountRecovery.NONE,
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.user_pool_client = self.user_pool.add_client(
            "Cognito-UserPoolClient",
            user_pool_client_name=f"{self.main_resources_name}-mcp-client-{self.deployment_environment}",
            auth_flows=cognito.AuthFlow(user_password=True, user_srp=True),
            generate_secret=False,
            access_token_validity=Duration.hours(8),
            id_token_validity=Duration.hours(8),
        )

        self.cognito_discovery_url = (
            f"https://cognito-idp.{self.region}.amazonaws.com/"
            f"{self.user_pool.user_pool_id}/.well-known/openid-configuration"
        )

    def create_tool_lambda_functions(self):
        """
        Method to create the 4 tool Lambda Functions (AgentCore Gateway Lambda
        Targets): consulta-saldo, consulta-tarjetas, consulta-canales and
        consulta-preferencias.
        """

        def _tool_lambda(purpose: str, source_folder: str, env: dict) -> aws_lambda.Function:
            function = aws_lambda.Function(
                self,
                f"Lambda-{purpose}",
                function_name=f"{self.main_resources_name}-{purpose}-{self.deployment_environment}",
                runtime=aws_lambda.Runtime.PYTHON_3_13,
                architecture=aws_lambda.Architecture.ARM_64,
                handler="handler.lambda_handler",
                code=aws_lambda.Code.from_asset(os.path.join(LAMBDAS_PATH, source_folder)),
                timeout=Duration.seconds(30),
                memory_size=256,
                environment=env,
                log_retention=logs.RetentionDays.ONE_WEEK,
            )
            return function

        self.lambda_consulta_saldo = _tool_lambda(
            "consulta-saldo",
            "consulta_saldo",
            {"USERS_TABLE_NAME": self.users_table.table_name},
        )
        self.lambda_consulta_tarjetas = _tool_lambda(
            "consulta-tarjetas",
            "consulta_tarjetas",
            {"USERS_TABLE_NAME": self.users_table.table_name},
        )
        self.lambda_consulta_canales = _tool_lambda(
            "consulta-canales",
            "consulta_canales",
            {"CHANNELS_TABLE_NAME": self.channels_table.table_name},
        )
        self.lambda_consulta_preferencias = _tool_lambda(
            "consulta-preferencias",
            "consulta_preferencias",
            {"USERS_TABLE_NAME": self.users_table.table_name},
        )

        # Least-privilege reads for each tool Lambda
        self.users_table.grant_read_data(self.lambda_consulta_saldo)
        self.users_table.grant_read_data(self.lambda_consulta_tarjetas)
        self.users_table.grant_read_data(self.lambda_consulta_preferencias)
        self.channels_table.grant_read_data(self.lambda_consulta_canales)

    def create_fgac_interceptor_lambda(self):
        """
        Method to create the Fine-Grained Access Control Lambda Interceptor
        (single Lambda attached to BOTH the REQUEST and RESPONSE interception
        points of the AgentCore Gateway).
        """
        self.lambda_fgac_interceptor = aws_lambda.Function(
            self,
            "Lambda-FGACInterceptor",
            function_name=f"{self.main_resources_name}-fgac-interceptor-{self.deployment_environment}",
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            architecture=aws_lambda.Architecture.ARM_64,
            handler="handler.lambda_handler",
            code=aws_lambda.Code.from_asset(os.path.join(LAMBDAS_PATH, "fgac_interceptor")),
            timeout=Duration.seconds(15),
            memory_size=256,
            environment={
                "FGAC_TABLE_NAME": self.fgac_table.table_name,
                "DENY_MODE": self.app_config.get("interceptor_deny_mode", "mcp_error"),
            },
            log_retention=logs.RetentionDays.ONE_WEEK,
        )
        self.fgac_table.grant_read_data(self.lambda_fgac_interceptor)

    def create_agentcore_gateway(self):
        """
        Method to create the AgentCore Gateway (MCP) with INBOUND AUTH via
        Cognito (CUSTOM_JWT) and the FGAC Lambda Interceptor configured at
        BOTH interception points:
        - REQUEST  -> InvokeTool validation (block unauthorized tools/call)
        - RESPONSE -> ListTools validation (filter unauthorized tools/list)
        ExceptionLevel=DEBUG enables detailed Gateway error messages (instead
        of the generic 'same message for every non-200').
        """
        self.gateway = agentcore.Gateway(
            self,
            "AgentCore-Gateway",
            gateway_name=f"{self.main_resources_name}-gateway-{self.deployment_environment}",
            description="santi-bank MCP Gateway with Fine-Grained Access Control via DynamoDB + Cognito JWT",
            protocol_configuration=agentcore.McpProtocolConfiguration(
                supported_versions=[
                    agentcore.MCPProtocolVersion.MCP_2025_03_26,
                    agentcore.MCPProtocolVersion.MCP_2025_06_18,
                ],
            ),
            authorizer_configuration=agentcore.CustomJwtAuthorizer(
                discovery_url=self.cognito_discovery_url,
                allowed_clients=[self.user_pool_client.user_pool_client_id],
            ),
            exception_level=agentcore.GatewayExceptionLevel.DEBUG,
            interceptor_configurations=[
                # REQUEST interceptor: InvokeTool enforcement (needs headers for JWT)
                agentcore.LambdaInterceptor.for_request(
                    self.lambda_fgac_interceptor,
                    pass_request_headers=True,
                ),
                # RESPONSE interceptor: ListTools filtering (needs headers for JWT)
                agentcore.LambdaInterceptor.for_response(
                    self.lambda_fgac_interceptor,
                    pass_request_headers=True,
                ),
            ],
        )

    def create_gateway_lambda_targets(self):
        """
        Method to register the 4 tool Lambda Functions as MCP Lambda Targets
        of the AgentCore Gateway (with inline MCP tool schemas).
        """
        username_input_schema = agentcore.SchemaDefinition(
            type=agentcore.SchemaDefinitionType.OBJECT,
            properties={
                "username": agentcore.SchemaDefinition(
                    type=agentcore.SchemaDefinitionType.STRING,
                    description="Username del cliente de santi-bank (ejemplo: santi, jimmy, joacho)",
                )
            },
            required=["username"],
        )
        empty_input_schema = agentcore.SchemaDefinition(
            type=agentcore.SchemaDefinitionType.OBJECT,
            properties={},
        )

        targets_config = [
            {
                "id": "Target-ConsultaSaldo",
                "target_name": "consulta-saldo",
                "lambda_function": self.lambda_consulta_saldo,
                "tool": agentcore.ToolDefinition(
                    name="consulta_saldo",
                    description=(
                        "Consulta el saldo disponible y total de un usuario de santi-bank. "
                        "Requiere el username del cliente."
                    ),
                    input_schema=username_input_schema,
                ),
            },
            {
                "id": "Target-ConsultaTarjetas",
                "target_name": "consulta-tarjetas",
                "lambda_function": self.lambda_consulta_tarjetas,
                "tool": agentcore.ToolDefinition(
                    name="consulta_tarjetas",
                    description=(
                        "Consulta las tarjetas de credito y debito de un usuario de santi-bank "
                        "(franquicia, estado, cupos). Requiere el username del cliente."
                    ),
                    input_schema=username_input_schema,
                ),
            },
            {
                "id": "Target-ConsultaCanales",
                "target_name": "consulta-canales",
                "lambda_function": self.lambda_consulta_canales,
                "tool": agentcore.ToolDefinition(
                    name="consulta_canales",
                    description=(
                        "Consulta el estado actual de TODOS los canales de santi-bank: "
                        "Sucursal Virtual Personas (SVP), Sucursal Virtual Negocios (SVN), "
                        "MiBancoApp (App), Valores santi-bank, SantiBot (WhatsApp). "
                        "No requiere parametros."
                    ),
                    input_schema=empty_input_schema,
                ),
            },
            {
                "id": "Target-ConsultaPreferencias",
                "target_name": "consulta-preferencias",
                "lambda_function": self.lambda_consulta_preferencias,
                "tool": agentcore.ToolDefinition(
                    name="consulta_preferencias",
                    description=(
                        "Consulta las preferencias de la app de un usuario de santi-bank "
                        "(nickname, color-app, tope-cajero, tope-transaccion, "
                        "contacto-emergencia). Requiere el username del cliente."
                    ),
                    input_schema=username_input_schema,
                ),
            },
        ]

        self.gateway_targets = []
        for config in targets_config:
            target = self.gateway.add_lambda_target(
                config["id"],
                gateway_target_name=config["target_name"],
                lambda_function=config["lambda_function"],
                tool_schema=agentcore.ToolSchema.from_inline([config["tool"]]),
                credential_provider_configurations=[
                    agentcore.GatewayCredentialProvider.from_iam_role()
                ],
            )
            self.gateway_targets.append(target)

    def create_setup_custom_resource(self):
        """
        Method to create the CloudFormation Custom Resource (Lambda + Provider
        Framework) that creates the Cognito users (santi, jimmy, joacho) and
        seeds the 3 DynamoDB tables on CREATE and UPDATE events.
        """
        self.lambda_setup = aws_lambda.Function(
            self,
            "Lambda-SetupUsersAndData",
            function_name=f"{self.main_resources_name}-setup-users-{self.deployment_environment}",
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            architecture=aws_lambda.Architecture.ARM_64,
            handler="handler.lambda_handler",
            code=aws_lambda.Code.from_asset(os.path.join(LAMBDAS_PATH, "setup_custom_resource")),
            timeout=Duration.minutes(5),
            memory_size=256,
            environment={
                "USER_POOL_ID": self.user_pool.user_pool_id,
                "USERS_TABLE_NAME": self.users_table.table_name,
                "CHANNELS_TABLE_NAME": self.channels_table.table_name,
                "FGAC_TABLE_NAME": self.fgac_table.table_name,
                "USERS_PASSWORD": "Testing123.",  # Demo-only password (explicit requirement)
            },
            log_retention=logs.RetentionDays.ONE_WEEK,
        )

        # Permissions: manage Cognito users + write seed data to the 3 tables
        self.user_pool.grant(
            self.lambda_setup,
            "cognito-idp:AdminCreateUser",
            "cognito-idp:AdminSetUserPassword",
            "cognito-idp:AdminGetUser",
        )
        self.users_table.grant_write_data(self.lambda_setup)
        self.channels_table.grant_write_data(self.lambda_setup)
        self.fgac_table.grant_write_data(self.lambda_setup)

        provider = cr.Provider(
            self,
            "CustomResource-Provider",
            on_event_handler=self.lambda_setup,
            log_retention=logs.RetentionDays.ONE_WEEK,
        )

        self.setup_custom_resource = CustomResource(
            self,
            "CustomResource-SetupUsersAndData",
            service_token=provider.service_token,
            properties={
                # Bump this version to force a re-seed on the next deployment
                "SeedVersion": "v1.2.0",
            },
        )

        # Explicit dependencies: run AFTER tables and user pool exist
        self.setup_custom_resource.node.add_dependency(self.users_table)
        self.setup_custom_resource.node.add_dependency(self.channels_table)
        self.setup_custom_resource.node.add_dependency(self.fgac_table)
        self.setup_custom_resource.node.add_dependency(self.user_pool)

    def create_custom_domain_with_cloudfront(self):
        """
        Method to create the custom domain for the MCP endpoint:
        Route53 record (santi-bank-fine-access.cb.events.genai.aws.dev) ->
        CloudFront distribution -> AgentCore Gateway endpoint (HTTPS origin).
        """
        hosted_zone_name = self.app_config["hosted_zone_name"]
        subdomain = self.app_config["custom_domain_subdomain"]
        self.full_domain_name = f"{subdomain}.{hosted_zone_name}"

        self.hosted_zone = route53.HostedZone.from_hosted_zone_attributes(
            self,
            "Route53-HostedZone",
            hosted_zone_id=self.app_config["hosted_zone_id"],
            zone_name=hosted_zone_name,
        )

        # ACM certificate (deployed in us-east-1, required by CloudFront)
        self.certificate = acm.Certificate(
            self,
            "ACM-Certificate",
            domain_name=self.full_domain_name,
            validation=acm.CertificateValidation.from_dns(self.hosted_zone),
        )

        # Extract the Gateway domain from its URL (https://<domain>/mcp)
        gateway_domain = Fn.select(2, Fn.split("/", self.gateway.gateway_url))

        self.distribution = cloudfront.Distribution(
            self,
            "CloudFront-Distribution",
            comment=f"{self.main_resources_name} MCP Gateway custom domain ({self.deployment_environment})",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin(
                    gateway_domain,
                    protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
                ),
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
            ),
            domain_names=[self.full_domain_name],
            certificate=self.certificate,
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            http_version=cloudfront.HttpVersion.HTTP2,
        )

        route53.ARecord(
            self,
            "Route53-ARecord",
            zone=self.hosted_zone,
            record_name=subdomain,
            target=route53.RecordTarget.from_alias(
                route53_targets.CloudFrontTarget(self.distribution)
            ),
        )
        route53.AaaaRecord(
            self,
            "Route53-AaaaRecord",
            zone=self.hosted_zone,
            record_name=subdomain,
            target=route53.RecordTarget.from_alias(
                route53_targets.CloudFrontTarget(self.distribution)
            ),
        )

    def create_outputs(self):
        """Method to export the key resource identifiers of the deployment."""
        CfnOutput(self, "GatewayUrl", value=self.gateway.gateway_url)
        CfnOutput(self, "GatewayId", value=self.gateway.gateway_id)
        CfnOutput(self, "CustomDomainMcpUrl", value=f"https://{self.full_domain_name}/mcp")
        CfnOutput(self, "CloudFrontDomain", value=self.distribution.distribution_domain_name)
        CfnOutput(self, "CognitoUserPoolId", value=self.user_pool.user_pool_id)
        CfnOutput(self, "CognitoAppClientId", value=self.user_pool_client.user_pool_client_id)
        CfnOutput(self, "CognitoDiscoveryUrl", value=self.cognito_discovery_url)
        CfnOutput(self, "UsersTableName", value=self.users_table.table_name)
        CfnOutput(self, "ChannelsTableName", value=self.channels_table.table_name)
        CfnOutput(self, "FineGrainedAccessTableName", value=self.fgac_table.table_name)
