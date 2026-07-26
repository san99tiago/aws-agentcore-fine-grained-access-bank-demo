Actua como experto en AgentCore Gateway (y vas a guiarte SIEMPRE de la documentación que encuentres aquí: https://github.com/awslabs/agentcore-samples).

- Para el FINE-GRAINED-ACCESS (control de AgentCore Gateway Tools desde Cognito JWT, hacia DynamoDB), TIENES que leer esta documentación y seguirla: https://github.com/awslabs/agentcore-samples/blob/main/06-workshops/02-AgentCore-gateway/09-fine-grained-access-control/02-fine-grained-access-control-using-data-store/02-fine-grained-access-control-using-data-store.ipynb

---

Tu misión es REPLICAR UN ESCENARIO DE UN CLIENTE, para el cual lo vas a dejar como "santi-bank" (TODO con este resource name). Utiliza el SKILL de cdk-infrastructure. El cliente es "santi-bank".

---

CONTEXTO: El objetivo es con base en esta información:
(((
Dudas desde equipo santi-bank para Santi:

- 1. AGCW authN/authZ...
  - El equipo originalmente tenía el proceso de AuthN/AuthZ para LISTAR las tools desde la Lambda Interceptor de Response... Sin embargo, cuando esta se ejecutaba ya estaba "muy tarde", y lo que querían es que al llamar una tool no se bloqueara solamente en el "List Tools", sino también en el "Invoke Tool". Por ende, el mejor setup es:
    - A) Validación en el ListTools (via Interceptor Response)...
    - B) Validación en InvokeTool (via Interceptor Request)...
  - Se recomienda hacer alguna validación de headers o algún otro mecanismo?
- 2. Errores de ACGW: - Manejo de ERRORES... - Petición enviada.. Y luego cuando se tiene la respuesta es como si "no se tuviera clara la respuesta". Doble click? - Filtrado OK... Sin problemas. - Petición ARMADA de tool que ya NO tiene permiso... - Si es petición de listar tool, ok... Nuevo filtrado. - Nos soñamos ver: "Sí puedes ver tool, pero NO ejectuarla".. - StatusCode diferente a 200, da SIEMPRE el mismo mensaje... - No solo con invoke de lambdas... también con tokens vacíos.. - (La DEMO fue desde un lab llamado SQL Injection, del repo de AgentCore Samples...)
     ))), puedas proceder a realizar un despliegue similar y ayudar a validar estas dos hipótessis. Haz los cambios via CDK y luego despliega.

TAREA: proceder a crear un despliegue con CDK, donde puedas desplegar via infraestructura como código...

- Route53 (Custom Domain in the Hosted Zone: "cb.events.genai.aws.dev" with subdomain "santi-bank-fine-access")
- CloudFront pointing towards the AgentCore Gateway Endpoint.
- AgentCore Gateway, with INBOUND AUTH, with Cognito.
- Crearás 4 funciones Lambda, con nombres descriptivos. Estas serás: 1) Consulta Saldo (consultar el saldo de un usuario. Se pasa username, y se consulta la tabla de "santi-bank-users-data"). 2) Consulta Tarjetas (la cual retornará las tarjetas de crédito/débito de un usuario. Se pasa el nombre canales, que consulte el estado actual de los canales consultando la DynamoDB (TODOS LOSergencia",etc....
- Cognito User Pool. WITHOUT the possibility to register users.
- 3 DynamoDB Tables (with on-demand), and they will have PK/SK (single-table-design, easty to read)... Una de las DynamoDB ("santi-bank-fine-grained-access-mapping") para los fine-grained-access controls y la otra ("santi-bank-users-data") para la DATA (saldos de los usuarios, nombres, perfiles, tarjetas de crédito, preferencias app MiBancoApp). Y la de los canales "santi-bank-channels-data" (donde se guarde la información actual del status de los canales: Sucursal Virtual Personas (SVP), Sucursal Virtual Negocios (SVN), MiBancoApp (App), Valores santi-bank, SantiBot (WhatsApp), etc..)
- A CloudFormation CUSTOM-RESOURCE (via LambdaFunction/Python), that is able to create 3 cognito-users: "santi", "jimmy", "joacho"... TODOS deben tener la contraseña "Testing123." Adicionalmente, en el CustomResource vas a crear estos usuarios en la DYNAMODB, para hacer el "mapeo" entre usuarios/permisos... santi debe tener acceso a TODAS las tools, jimmy debe tener acceso a tool consulta saldo, consulta preferencias y consulta tarjetas pero NO debe tener acceso a consulta canales. joacho debe tener acceso a consulta saldo, consulta canale, pero NO a tarjetas, ni a preferencias.... El custom resource debe funciona para estados tanto de CREATE/UPDATE resources... Es decir, al desplegar, deben quedar POPULADAS estas tablas. (y lógicamente, deberá ser posterior a depslegar la DYnamodb table con los recursos de CDK oficiales).
- Las LambdaFunctions será de tipo "Lambda Interceptor", para que puedan servir en el AgentCore Gateway, y VALIDAR que los usarios (tokens de cognito), tengan acceso y se mapeen al fine-grained access control a través de la tabla de DynamoDB "santi-bank-fine-grained-access-mapping", con base en el input JWT del usuario. Agregar LOGGING SIGNITFICATIVO (Extra logs/prints/console-log) a las lambdas en Python, para poder ver lo que está llegando/saliendo.
- Agregar cualquier recurso adicional necesario con base en la documentación pasada, para ahcer el proceso funcional E2E.

IMPORNTATE:

- Debes crear el código en CDK Python, y Lambdas en Python. Todo siguiendo loss skills de re
- Seguir convernciónes de "santi-bank".
- Para las Lambdas, hacerlas en Python, y que hayan abundantes LOGGING/Prints.
- Hacer cdk synth, luego DESPLEGAR, y luego proceder a hacer validaciones de un CLIENTE MCP (mcp-inspector), con ayuda de COGNITO y los usuarios con los respectivos permisos, para validar que el endpoint MCP esté funcional con el DNS, con los tokens según el Cognito/JWT, y los permisos respectivos dB.
- Valida que todo funcione bien, y haz ajustes en caso de ser necesario.
