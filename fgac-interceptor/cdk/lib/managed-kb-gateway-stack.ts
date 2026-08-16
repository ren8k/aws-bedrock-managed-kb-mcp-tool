import * as path from "node:path";
import * as cdk from "aws-cdk-lib";
import * as bedrock from "aws-cdk-lib/aws-bedrock";
import * as agentcore from "aws-cdk-lib/aws-bedrockagentcore";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as cr from "aws-cdk-lib/custom-resources";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";

/**
 * Managed KB as MCP tools via AgentCore Gateway, with userContext
 * injected by a REQUEST interceptor. Self-contained:
 *
 * - S3 bucket + dataset deployment (documents with per-document ACL)
 * - Managed Knowledge Base (type MANAGED) + ACL-enabled S3 data source
 * - Cognito user pool + domain (userInfo endpoint) + app client
 * - REQUEST interceptor Lambda (resolves email from the access token
 *   via OIDC userInfo or Cognito GetUser, injects it into userContext)
 * - Gateway (CUSTOM_JWT, access-token auth) + Managed KB connector target
 *
 * Token handling follows OAuth semantics: the client sends only the
 * access token in Authorization, which the gateway authorizer verifies
 * via allowedClients. The interceptor resolves the user's email through
 * the userInfo endpoint with that same verified token, so the
 * authenticated principal and the userContext principal cannot diverge.
 * Clients need no userContext logic, and spoofed userContext values are
 * overwritten inside the gateway.
 */
export class ManagedKbGatewayStack extends cdk.Stack {
	constructor(scope: Construct, id: string, props?: cdk.StackProps) {
		super(scope, id, props);

		const account = cdk.Stack.of(this).account;
		const region = cdk.Stack.of(this).region;

		// ---- S3 bucket + dataset (documents + ACL sidecars) ----
		const bucket = new s3.Bucket(this, "KbBucket", {
			bucketName: `managed-kb-gateway-${account}`,
			blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
			encryption: s3.BucketEncryption.S3_MANAGED,
			enforceSSL: true,
			removalPolicy: cdk.RemovalPolicy.RETAIN,
		});
		const dataset = new s3deploy.BucketDeployment(this, "DatasetDeployment", {
			sources: [s3deploy.Source.asset(path.join(__dirname, "..", "dataset"))],
			destinationBucket: bucket,
			prune: false,
		});

		// The global ACL file addresses documents by absolute S3 URI, so it
		// cannot be a static asset; render it with the bucket name.
		const globalAclKey = "acl-config/global-acl.json";
		const globalAcl = new s3deploy.BucketDeployment(
			this,
			"GlobalAclDeployment",
			{
				sources: [
					s3deploy.Source.jsonData(globalAclKey, [
						{
							keyPrefix: `s3://${bucket.bucketName}/global-docs/finance/`,
							aclEntries: [
								{ Name: "user-a@example.com", Type: "USER", Access: "ALLOW" },
							],
						},
						{
							keyPrefix: `s3://${bucket.bucketName}/global-docs/hr/`,
							aclEntries: [
								{ Name: "user-b@example.com", Type: "USER", Access: "ALLOW" },
							],
						},
					]),
				],
				destinationBucket: bucket,
				prune: false,
			},
		);

		// ---- Managed Knowledge Base ----
		const kbRole = new iam.Role(this, "KbServiceRole", {
			roleName: "managed-kb-service-role",
			assumedBy: new iam.ServicePrincipal("bedrock.amazonaws.com", {
				conditions: {
					StringEquals: { "aws:SourceAccount": account },
					ArnLike: {
						"aws:SourceArn": `arn:aws:bedrock:${region}:${account}:knowledge-base/*`,
					},
				},
			}),
		});
		kbRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "S3Read",
				actions: ["s3:GetObject", "s3:ListBucket"],
				resources: [bucket.bucketArn, `${bucket.bucketArn}/*`],
			}),
		);
		kbRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "BedrockModelInvocation",
				actions: [
					"bedrock:InvokeModel",
					"bedrock:InvokeModelWithResponseStream",
				],
				resources: ["*"],
			}),
		);

		// The generated L1 validator requires embeddingModelArn inside
		// ManagedKnowledgeBaseConfiguration, but the live CFN schema has no
		// required fields and the service rejects embeddingModelArn when
		// embeddingModelType is MANAGED. Raw property overrides bypass the
		// stale validator.
		const kb = new bedrock.CfnKnowledgeBase(this, "Kb", {
			name: "managed-kb",
			description: "Managed KB exposed as MCP tools with ACL-aware retrieval",
			roleArn: kbRole.roleArn,
			knowledgeBaseConfiguration: { type: "MANAGED" },
		});
		kb.addPropertyOverride(
			"KnowledgeBaseConfiguration.ManagedKnowledgeBaseConfiguration",
			{ EmbeddingModelType: "MANAGED" },
		);
		kb.node.addDependency(kbRole);

		// ACL-enabled S3 data source (per-document metadata.json sidecars)
		const dataSource = new bedrock.CfnDataSource(this, "DocsDataSource", {
			name: "docs",
			description: "Department documents with per-document ACL",
			knowledgeBaseId: kb.attrKnowledgeBaseId,
			dataDeletionPolicy: "DELETE",
			dataSourceConfiguration: {
				type: "MANAGED_KNOWLEDGE_BASE_CONNECTOR",
				managedKnowledgeBaseConnectorConfiguration: {
					deletionProtectionConfiguration: {
						deletionProtectionStatus: "DISABLED",
					},
					connectorParameters: {
						type: "S3",
						version: "1",
						aclEnabled: true,
						connectionConfiguration: {
							bucketName: bucket.bucketName,
							bucketOwnerAccountId: account,
						},
						filterConfiguration: { inclusionPrefixes: ["docs/"] },
					},
				},
			},
		});
		dataSource.node.addDependency(dataset);

		// ACL-enabled S3 data source (global ACL file, prefix-level control).
		// Documents under global-docs/no-acl/ match no keyPrefix and have no
		// sidecar, so they are not ingested (fail-closed).
		const globalDataSource = new bedrock.CfnDataSource(
			this,
			"GlobalDocsDataSource",
			{
				name: "global-docs",
				description: "Department documents with a global ACL file",
				knowledgeBaseId: kb.attrKnowledgeBaseId,
				dataDeletionPolicy: "DELETE",
				dataSourceConfiguration: {
					type: "MANAGED_KNOWLEDGE_BASE_CONNECTOR",
					managedKnowledgeBaseConnectorConfiguration: {
						deletionProtectionConfiguration: {
							deletionProtectionStatus: "DISABLED",
						},
						connectorParameters: {
							type: "S3",
							version: "1",
							aclEnabled: true,
							connectionConfiguration: {
								bucketName: bucket.bucketName,
								bucketOwnerAccountId: account,
							},
							aclConfiguration: {
								globalAccessControlListS3Uri: `s3://${bucket.bucketName}/${globalAclKey}`,
							},
							filterConfiguration: { inclusionPrefixes: ["global-docs/"] },
						},
					},
				},
			},
		);
		globalDataSource.node.addDependency(globalAcl);
		// Managed KB data source creation is async; create sequentially to
		// avoid concurrent-modification conflicts on the same KB.
		globalDataSource.node.addDependency(dataSource);

		// ---- Cognito (JWT issuer; stand-in for a corporate IdP) ----
		const userPool = new cognito.UserPool(this, "UserPool", {
			userPoolName: "managed-kb-users",
			selfSignUpEnabled: false,
			signInAliases: { email: true },
			standardAttributes: { email: { required: true, mutable: true } },
			removalPolicy: cdk.RemovalPolicy.DESTROY,
		});
		const userPoolClient = userPool.addClient("Client", {
			userPoolClientName: "managed-kb-client",
			authFlows: { userPassword: true },
			generateSecret: false,
			idTokenValidity: cdk.Duration.hours(12),
		});
		// The Cognito domain hosts the OIDC userInfo endpoint the
		// interceptor calls to resolve email from the access token.
		const userPoolDomain = userPool.addDomain("Domain", {
			cognitoDomain: { domainPrefix: `managed-kb-${account}` },
		});
		const userInfoUrl = `${userPoolDomain.baseUrl()}/oauth2/userInfo`;
		const discoveryUrl = `https://cognito-idp.${region}.amazonaws.com/${userPool.userPoolId}/.well-known/openid-configuration`;

		// ---- Test users (verification only) ----
		// The password is generated once when the secret is created and
		// stored in Secrets Manager; it never appears in the template or
		// the repository.
		const testPasswordSecret = new secretsmanager.Secret(
			this,
			"TestUserPassword",
			{
				secretName: "managed-kb-test-user-password",
				description: "Shared password for the demo test users",
				generateSecretString: {
					passwordLength: 24,
					requireEachIncludedType: true,
					excludeCharacters: "\"'\\`",
				},
			},
		);
		// Secure dynamic references ({{resolve:secretsmanager:...}}) are not
		// resolved inside custom resource properties, so the secret value
		// cannot be passed to adminSetUserPassword directly. Read it with a
		// getSecretValue custom resource and reference the response field
		// (Fn::GetAtt), which CloudFormation does resolve.
		// logApiResponseData keeps the secret value out of the provider's
		// CloudWatch logs.
		const readSecretCall = {
			service: "SecretsManager",
			action: "getSecretValue",
			parameters: { SecretId: testPasswordSecret.secretArn },
			physicalResourceId: cr.PhysicalResourceId.of("read-test-user-password"),
			logApiResponseData: false,
		};
		const readTestPassword = new cr.AwsCustomResource(
			this,
			"ReadTestUserPassword",
			{
				onCreate: readSecretCall,
				onUpdate: readSecretCall,
				policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
					resources: [testPasswordSecret.secretArn],
				}),
			},
		);
		const testPassword = readTestPassword.getResponseField("SecretString");
		for (const [idSuffix, email] of [
			["A", "user-a@example.com"],
			["B", "user-b@example.com"],
		] as const) {
			const user = new cognito.CfnUserPoolUser(this, `User${idSuffix}`, {
				userPoolId: userPool.userPoolId,
				username: email,
				userAttributes: [
					{ name: "email", value: email },
					{ name: "email_verified", value: "true" },
				],
				messageAction: "SUPPRESS",
			});
			// CloudFormation cannot set a permanent password natively; use an
			// SDK call so USER_PASSWORD_AUTH works right after deploy.
			// onUpdate mirrors onCreate so a rotated secret value is applied
			// to existing users too.
			const setPasswordCall = {
				service: "CognitoIdentityServiceProvider",
				action: "adminSetUserPassword",
				parameters: {
					UserPoolId: userPool.userPoolId,
					Username: email,
					Password: testPassword,
					Permanent: true,
				},
				physicalResourceId: cr.PhysicalResourceId.of(`set-password-${email}`),
			};
			const setPassword = new cr.AwsCustomResource(
				this,
				`User${idSuffix}Password`,
				{
					onCreate: setPasswordCall,
					onUpdate: setPasswordCall,
					policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
						resources: [userPool.userPoolArn],
					}),
				},
			);
			setPassword.node.addDependency(user);
		}

		// ---- REQUEST interceptor Lambda ----
		// Email is resolved with the authorizer-verified access token via
		// OIDC userInfo (openid scope) or Cognito GetUser, so no JWT
		// verification (and no dependency layer) is needed here.
		const interceptorFn = new lambda.Function(this, "InterceptorFn", {
			functionName: "managed-kb-usercontext-interceptor",
			runtime: lambda.Runtime.PYTHON_3_12,
			architecture: lambda.Architecture.ARM_64,
			handler: "handler.handler",
			code: lambda.Code.fromAsset(
				path.join(__dirname, "..", "lambda", "interceptor"),
			),
			environment: {
				USERINFO_URL: userInfoUrl,
			},
			timeout: cdk.Duration.seconds(30),
		});

		// ---- Gateway execution role ----
		// No confused-deputy conditions: GatewayTarget validation assumes
		// this role without source context and fails with them.
		const gwRole = new iam.Role(this, "GatewayRole", {
			roleName: "managed-kb-gateway-role",
			assumedBy: new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
		});
		gwRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "KbAccess",
				actions: ["bedrock:GetKnowledgeBase", "bedrock:Retrieve"],
				resources: [
					`arn:aws:bedrock:${region}:${account}:knowledge-base/${kb.attrKnowledgeBaseId}`,
				],
			}),
		);
		gwRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "AgenticRetrieve",
				// bedrock:AgenticRetrieveStream cannot be resource-scoped.
				actions: ["bedrock:AgenticRetrieveStream"],
				resources: ["*"],
			}),
		);
		interceptorFn.grantInvoke(gwRole);

		// ---- Gateway (CUSTOM_JWT + REQUEST interceptor) ----
		const gateway = new agentcore.CfnGateway(this, "Gateway", {
			name: "managed-kb-gateway",
			description:
				"JWT-auth gateway that injects userContext via REQUEST interceptor",
			roleArn: gwRole.roleArn,
			protocolType: "MCP",
			authorizerType: "CUSTOM_JWT",
			authorizerConfiguration: {
				customJwtAuthorizer: {
					discoveryUrl,
					// Client-only: inbound auth uses the Cognito access token
					// (client_id claim; no aud). allowedAudience and
					// allowedClients are ANDed, so setting both rejects every
					// Cognito token. The email is resolved by the interceptor
					// from this same verified token (userInfo / GetUser).
					allowedClients: [userPoolClient.userPoolClientId],
				},
			},
			exceptionLevel: "DEBUG",
			interceptorConfigurations: [
				{
					interceptionPoints: ["REQUEST"],
					interceptor: { lambda: { arn: interceptorFn.functionArn } },
					inputConfiguration: { passRequestHeaders: true },
				},
			],
		});

		// ---- Managed KB connector target ----
		const target = new agentcore.CfnGatewayTarget(this, "KbTarget", {
			gatewayIdentifier: gateway.attrGatewayIdentifier,
			name: "kb",
			description:
				"Managed KB tools with userContext injected by the interceptor",
			credentialProviderConfigurations: [
				{ credentialProviderType: "GATEWAY_IAM_ROLE" },
			],
			targetConfiguration: {
				mcp: {
					connector: {
						source: { connectorId: "bedrock-knowledge-bases" },
						configurations: [
							{
								name: "Retrieve",
								parameterValues: {
									knowledgeBaseId: kb.attrKnowledgeBaseId,
								},
								// The interceptor can only set parameters that are
								// visible; hidden parameters are rejected with
								// "cannot set parameter(s)".
								parameterOverrides: [
									{
										path: "$.userContext",
										description:
											"End-user identity for ACL-aware retrieval (set by the gateway interceptor)",
										visible: true,
									},
								],
							},
							{
								name: "AgenticRetrieveStream",
								parameterValues: {
									retrievers: [
										{
											description:
												"Department documents (business plans, notices)",
											configuration: {
												knowledgeBase: {
													knowledgeBaseId: kb.attrKnowledgeBaseId,
												},
											},
										},
									],
									// An empty object passes target validation but
									// fails at call time with "Missing required
									// field(s)"; bind explicit values.
									agenticRetrieveConfiguration: {
										foundationModelType: "MANAGED",
										rerankingModelType: "MANAGED",
									},
								},
								parameterOverrides: [
									{
										path: "$.userContext",
										description:
											"End-user identity for ACL-aware retrieval (set by the gateway interceptor)",
										visible: true,
									},
								],
							},
						],
					},
				},
			},
		});
		target.node.addDependency(gwRole);

		new cdk.CfnOutput(this, "KbId", { value: kb.attrKnowledgeBaseId });
		new cdk.CfnOutput(this, "DataSourceId", {
			value: dataSource.attrDataSourceId,
		});
		new cdk.CfnOutput(this, "GlobalDataSourceId", {
			value: globalDataSource.attrDataSourceId,
		});
		new cdk.CfnOutput(this, "BucketName", { value: bucket.bucketName });
		new cdk.CfnOutput(this, "UserPoolId", { value: userPool.userPoolId });
		new cdk.CfnOutput(this, "UserPoolClientId", {
			value: userPoolClient.userPoolClientId,
		});
		new cdk.CfnOutput(this, "GatewayUrl", { value: gateway.attrGatewayUrl });
		new cdk.CfnOutput(this, "UserInfoUrl", { value: userInfoUrl });
		new cdk.CfnOutput(this, "TestUserPasswordSecretName", {
			value: testPasswordSecret.secretName,
		});
		new cdk.CfnOutput(this, "GatewayId", {
			value: gateway.attrGatewayIdentifier,
		});
		new cdk.CfnOutput(this, "TargetId", { value: target.attrTargetId });
		new cdk.CfnOutput(this, "InterceptorFnName", {
			value: interceptorFn.functionName,
		});
	}
}
