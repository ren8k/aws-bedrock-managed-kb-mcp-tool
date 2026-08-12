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
 * Defense-in-depth variant of ManagedKbGatewayStack. Two independent
 * layers bind the caller's verified identity to userContext:
 *
 * - Injection: a REQUEST interceptor decodes the authorizer-verified
 *   access token and force-sets arguments.userContext from its email
 *   claim (added by a Cognito pre token generation trigger).
 * - Verification: an AgentCore Policy engine (Cedar, ENFORCE) evaluates
 *   the transformed request AFTER the interceptor and denies any
 *   tools/call whose userContext.userId differs from the JWT email
 *   claim. A single misconfiguration (for example, the interceptor
 *   detached from the gateway) no longer breaks tenant isolation.
 *
 * A second gateway without the interceptor shares the same policy
 * engine. It exists to demonstrate the policy-only behavior: requests
 * must carry a userContext that matches the caller's own email, and
 * spoofed or missing values are denied by policy. Production use should
 * prefer the main gateway (injection + verification).
 */
export class ManagedKbPolicyStack extends cdk.Stack {
	constructor(scope: Construct, id: string, props?: cdk.StackProps) {
		super(scope, id, props);

		const account = cdk.Stack.of(this).account;
		const region = cdk.Stack.of(this).region;

		// ---- S3 bucket + dataset (documents + ACL sidecars) ----
		const bucket = new s3.Bucket(this, "KbBucket", {
			bucketName: `managed-kb-policy-${account}`,
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

		// ---- Managed Knowledge Base ----
		const kbRole = new iam.Role(this, "KbServiceRole", {
			roleName: "managed-kb-policy-service-role",
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
			name: "managed-kb-policy",
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

		// ---- Cognito (JWT issuer; stand-in for a corporate IdP) ----
		// Access token customization (pre token generation V2_0) requires
		// the ESSENTIALS feature plan; declare it explicitly rather than
		// relying on the default.
		const userPool = new cognito.UserPool(this, "UserPool", {
			userPoolName: "managed-kb-policy-users",
			featurePlan: cognito.FeaturePlan.ESSENTIALS,
			selfSignUpEnabled: false,
			signInAliases: { email: true },
			standardAttributes: { email: { required: true, mutable: true } },
			removalPolicy: cdk.RemovalPolicy.DESTROY,
		});
		const userPoolClient = userPool.addClient("Client", {
			userPoolClientName: "managed-kb-policy-client",
			authFlows: { userPassword: true },
			generateSecret: false,
			idTokenValidity: cdk.Duration.hours(12),
		});
		const discoveryUrl = `https://cognito-idp.${region}.amazonaws.com/${userPool.userPoolId}/.well-known/openid-configuration`;

		// Pre token generation trigger (V2_0): copies the user's email
		// attribute into the ACCESS token claims. Both the interceptor and
		// the Cedar policies read the email from this claim, so the two
		// layers derive identity from the same verified source.
		const preTokenFn = new lambda.Function(this, "PreTokenGenFn", {
			functionName: "managed-kb-policy-pre-token",
			runtime: lambda.Runtime.PYTHON_3_12,
			architecture: lambda.Architecture.ARM_64,
			handler: "handler.handler",
			code: lambda.Code.fromAsset(
				path.join(__dirname, "..", "lambda", "pre-token-gen"),
			),
			timeout: cdk.Duration.seconds(10),
		});
		userPool.addTrigger(
			cognito.UserPoolOperation.PRE_TOKEN_GENERATION_CONFIG,
			preTokenFn,
			cognito.LambdaVersion.V2_0,
		);

		// ---- Test users (verification only) ----
		// The password is generated per deployment and stored in Secrets
		// Manager; it never appears in the template or the repository.
		const testPasswordSecret = new secretsmanager.Secret(
			this,
			"TestUserPassword",
			{
				secretName: "managed-kb-policy-test-user-password",
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
		// Standard library only: the email comes from the access token's
		// email claim (added by the pre token generation trigger), so no
		// external call is needed here.
		const interceptorFn = new lambda.Function(this, "InterceptorFn", {
			functionName: "managed-kb-policy-usercontext-interceptor",
			runtime: lambda.Runtime.PYTHON_3_12,
			architecture: lambda.Architecture.ARM_64,
			handler: "handler.handler",
			code: lambda.Code.fromAsset(
				path.join(__dirname, "..", "lambda", "interceptor"),
			),
			timeout: cdk.Duration.seconds(30),
		});

		// ---- Gateway execution role ----
		// No confused-deputy conditions: GatewayTarget validation assumes
		// this role without source context and fails with them.
		const gwRole = new iam.Role(this, "GatewayRole", {
			roleName: "managed-kb-policy-gateway-role",
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

		// ---- AgentCore Policy engine ----
		// Hyphens are not allowed in policy engine and policy names.
		const policyEngine = new agentcore.CfnPolicyEngine(this, "PolicyEngine", {
			name: "managed_kb_policy_engine",
			description:
				"Verifies that userContext matches the JWT email claim after interception",
		});

		// ---- Gateway (CUSTOM_JWT + REQUEST interceptor + policy engine) ----
		const gateway = new agentcore.CfnGateway(this, "Gateway", {
			name: "managed-kb-policy-gateway",
			description:
				"Gateway with interceptor injection verified by AgentCore Policy",
			roleArn: gwRole.roleArn,
			protocolType: "MCP",
			authorizerType: "CUSTOM_JWT",
			authorizerConfiguration: {
				customJwtAuthorizer: {
					discoveryUrl,
					// Client-only: inbound auth uses the Cognito access token
					// (client_id claim; no aud). allowedAudience and
					// allowedClients are ANDed, so setting both rejects every
					// Cognito token.
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
			// The policy engine evaluates tools/call AFTER the REQUEST
			// interceptor, so the Cedar policies verify the interceptor's
			// output, not the raw client input.
			policyEngineConfiguration: {
				arn: policyEngine.attrPolicyEngineArn,
				mode: "ENFORCE",
			},
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

		// ---- Verification gateway (no interceptor, same policy engine) ----
		// Demonstrates the policy-only behavior: callers must supply a
		// userContext that matches their own email claim; spoofed or
		// missing values are denied by the Cedar policies.
		const nointGateway = new agentcore.CfnGateway(
			this,
			"NoInterceptorGateway",
			{
				name: "managed-kb-policy-noint",
				description:
					"Verification gateway without interceptor to observe policy denies",
				roleArn: gwRole.roleArn,
				protocolType: "MCP",
				authorizerType: "CUSTOM_JWT",
				authorizerConfiguration: {
					customJwtAuthorizer: {
						discoveryUrl,
						allowedClients: [userPoolClient.userPoolClientId],
					},
				},
				exceptionLevel: "DEBUG",
				policyEngineConfiguration: {
					arn: policyEngine.attrPolicyEngineArn,
					mode: "ENFORCE",
				},
			},
		);
		const nointTarget = new agentcore.CfnGatewayTarget(this, "NoIntKbTarget", {
			gatewayIdentifier: nointGateway.attrGatewayIdentifier,
			name: "kb",
			description: "Managed KB Retrieve with policy-only access control",
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
								parameterOverrides: [
									{
										path: "$.userContext",
										description:
											"End-user identity for ACL-aware retrieval (must match your own email)",
										visible: true,
									},
								],
							},
						],
					},
				},
			},
		});
		nointTarget.node.addDependency(gwRole);

		// ---- Cedar policies ----
		// The when clause requires the (post-interception) userContext to
		// match the caller's email claim. Policies must be created after
		// their gateway target: CreateGatewayTarget implicitly synchronizes
		// the tool schema into the policy engine, and FAIL_ON_ANY_FINDINGS
		// rejects actions the engine does not know yet.
		const cedarUserContextMatch = (
			action: string,
			gatewayArn: string,
		): string => `permit(
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"${action}",
  resource == AgentCore::Gateway::"${gatewayArn}"
) when {
  principal.hasTag("email") &&
  context has input && context.input has userContext &&
  context.input.userContext has userId &&
  context.input.userContext.userId == principal.getTag("email")
};`;

		const policies: Array<{
			id: string;
			name: string;
			action: string;
			gatewayArn: string;
			dependsOn: cdk.CfnResource;
		}> = [
			{
				id: "MainRetrievePolicy",
				name: "managed_kb_policy_main_retrieve",
				action: "kb___Retrieve",
				gatewayArn: gateway.attrGatewayArn,
				dependsOn: target,
			},
			{
				id: "MainAgenticPolicy",
				name: "managed_kb_policy_main_agentic",
				action: "kb___AgenticRetrieveStream",
				gatewayArn: gateway.attrGatewayArn,
				dependsOn: target,
			},
			{
				id: "NoIntRetrievePolicy",
				name: "managed_kb_policy_noint_retrieve",
				action: "kb___Retrieve",
				gatewayArn: nointGateway.attrGatewayArn,
				dependsOn: nointTarget,
			},
		];
		for (const def of policies) {
			const policy = new agentcore.CfnPolicy(this, def.id, {
				name: def.name,
				policyEngineId: policyEngine.attrPolicyEngineId,
				definition: {
					cedar: {
						statement: cedarUserContextMatch(def.action, def.gatewayArn),
					},
				},
				validationMode: "FAIL_ON_ANY_FINDINGS",
			});
			policy.node.addDependency(def.dependsOn);
		}

		new cdk.CfnOutput(this, "KbId", { value: kb.attrKnowledgeBaseId });
		new cdk.CfnOutput(this, "DataSourceId", {
			value: dataSource.attrDataSourceId,
		});
		new cdk.CfnOutput(this, "BucketName", { value: bucket.bucketName });
		new cdk.CfnOutput(this, "UserPoolId", { value: userPool.userPoolId });
		new cdk.CfnOutput(this, "UserPoolClientId", {
			value: userPoolClient.userPoolClientId,
		});
		new cdk.CfnOutput(this, "GatewayUrl", { value: gateway.attrGatewayUrl });
		new cdk.CfnOutput(this, "NoInterceptorGatewayUrl", {
			value: nointGateway.attrGatewayUrl,
		});
		new cdk.CfnOutput(this, "TestUserPasswordSecretName", {
			value: testPasswordSecret.secretName,
		});
		new cdk.CfnOutput(this, "GatewayId", {
			value: gateway.attrGatewayIdentifier,
		});
		new cdk.CfnOutput(this, "NoInterceptorGatewayId", {
			value: nointGateway.attrGatewayIdentifier,
		});
		new cdk.CfnOutput(this, "TargetId", { value: target.attrTargetId });
		new cdk.CfnOutput(this, "PolicyEngineId", {
			value: policyEngine.attrPolicyEngineId,
		});
		new cdk.CfnOutput(this, "InterceptorFnName", {
			value: interceptorFn.functionName,
		});
		new cdk.CfnOutput(this, "PreTokenFnName", {
			value: preTokenFn.functionName,
		});
	}
}
