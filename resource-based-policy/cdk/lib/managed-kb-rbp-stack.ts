import * as path from "node:path";
import * as cdk from "aws-cdk-lib";
import * as bedrock from "aws-cdk-lib/aws-bedrock";
import * as agentcore from "aws-cdk-lib/aws-bedrockagentcore";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as cr from "aws-cdk-lib/custom-resources";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";

/**
 * Resource-based-policy variant of ManagedKbPolicyStack. On top of the
 * gateway-side layers (REQUEST interceptor injection + AgentCore Policy
 * verification), this stack adds an asset-side layer that gateway-scoped
 * controls cannot provide: a resource-based policy attached to the
 * managed KB itself that denies bedrock:Retrieve and
 * bedrock:GetDocumentContent to every principal except the legitimate
 * gateway execution role.
 *
 * Gateway-side controls only cover requests that pass through the
 * gateway they are attached to. The threat they cannot address is a KB
 * access path that never touches that gateway: a direct Retrieve call
 * with other credentials, or a second gateway (without the interceptor)
 * added for the same KB. To make that threat observable the stack also
 * provisions a "rogue" role whose identity-based policy allows every KB
 * action, and a rogue gateway (no interceptor, no policy engine) that
 * executes as that role. The resource policy is what must stop both.
 *
 * The resource policy supports only bedrock:Retrieve and
 * bedrock:GetDocumentContent; bedrock:AgenticRetrieveStream and
 * control-plane actions cannot appear in it. Whether the deny still
 * reaches AgenticRetrieveStream through its internal retrieval is one of
 * the questions the verification script answers empirically.
 */
export class ManagedKbRbpStack extends cdk.Stack {
	constructor(scope: Construct, id: string, props?: cdk.StackProps) {
		super(scope, id, props);

		const account = cdk.Stack.of(this).account;
		const region = cdk.Stack.of(this).region;

		// ---- S3 bucket + dataset (documents + ACL sidecars) ----
		// Like advanced-policy, this verification variant destroys the
		// bucket with the stack.
		const bucket = new s3.Bucket(this, "KbBucket", {
			bucketName: `managed-kb-rbp-${account}`,
			blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
			encryption: s3.BucketEncryption.S3_MANAGED,
			enforceSSL: true,
			removalPolicy: cdk.RemovalPolicy.DESTROY,
			autoDeleteObjects: true,
		});
		const dataset = new s3deploy.BucketDeployment(this, "DatasetDeployment", {
			sources: [s3deploy.Source.asset(path.join(__dirname, "..", "dataset"))],
			destinationBucket: bucket,
			prune: false,
		});

		// ---- Managed Knowledge Base ----
		const kbRole = new iam.Role(this, "KbServiceRole", {
			roleName: "managed-kb-rbp-service-role",
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
			name: "managed-kb-rbp",
			description: "Managed KB guarded by a resource-based policy",
			roleArn: kbRole.roleArn,
			knowledgeBaseConfiguration: { type: "MANAGED" },
		});
		kb.addPropertyOverride(
			"KnowledgeBaseConfiguration.ManagedKnowledgeBaseConfiguration",
			{ EmbeddingModelType: "MANAGED" },
		);
		kb.node.addDependency(kbRole);
		const kbArn = `arn:aws:bedrock:${region}:${account}:knowledge-base/${kb.attrKnowledgeBaseId}`;

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
			userPoolName: "managed-kb-rbp-users",
			featurePlan: cognito.FeaturePlan.ESSENTIALS,
			selfSignUpEnabled: false,
			signInAliases: { email: true },
			standardAttributes: { email: { required: true, mutable: true } },
			removalPolicy: cdk.RemovalPolicy.DESTROY,
		});
		const userPoolClient = userPool.addClient("Client", {
			userPoolClientName: "managed-kb-rbp-client",
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
			functionName: "managed-kb-rbp-pre-token",
			runtime: lambda.Runtime.PYTHON_3_12,
			architecture: lambda.Architecture.ARM_64,
			handler: "handler.handler",
			code: lambda.Code.fromAsset(
				path.join(__dirname, "..", "lambda", "pre-token-gen"),
			),
			timeout: cdk.Duration.seconds(10),
			logGroup: new logs.LogGroup(this, "PreTokenGenLogs", {
				logGroupName: "/aws/lambda/managed-kb-rbp-pre-token",
				retention: logs.RetentionDays.ONE_WEEK,
				removalPolicy: cdk.RemovalPolicy.DESTROY,
			}),
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
				secretName: "managed-kb-rbp-test-user-password",
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
			functionName: "managed-kb-rbp-usercontext-interceptor",
			runtime: lambda.Runtime.PYTHON_3_12,
			architecture: lambda.Architecture.ARM_64,
			handler: "handler.handler",
			code: lambda.Code.fromAsset(
				path.join(__dirname, "..", "lambda", "interceptor"),
			),
			timeout: cdk.Duration.seconds(30),
			logGroup: new logs.LogGroup(this, "InterceptorLogs", {
				logGroupName: "/aws/lambda/managed-kb-rbp-usercontext-interceptor",
				retention: logs.RetentionDays.ONE_WEEK,
				removalPolicy: cdk.RemovalPolicy.DESTROY,
			}),
		});

		// ---- Gateway execution role (the ONLY principal the KB resource
		// policy exempts from its deny) ----
		// No confused-deputy conditions: GatewayTarget validation assumes
		// this role without source context and fails with them.
		const gwRole = new iam.Role(this, "GatewayRole", {
			roleName: "managed-kb-rbp-gateway-role",
			assumedBy: new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
		});
		gwRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "KbAccess",
				actions: ["bedrock:GetKnowledgeBase", "bedrock:Retrieve"],
				resources: [kbArn],
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

		// ---- Rogue role (bypass-path simulator) ----
		// Represents the threat the gateway-side layers cannot reach: a
		// principal other than the legitimate gateway role whose
		// identity-based policy fully allows the KB data actions. Without
		// the KB resource policy every call below would succeed. The role
		// trusts both bedrock-agentcore (to execute the rogue gateway) and
		// the account (so the verification script can assume it directly).
		const rogueRole = new iam.Role(this, "RogueRole", {
			roleName: "managed-kb-rbp-rogue-role",
			assumedBy: new iam.CompositePrincipal(
				new iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
				new iam.AccountRootPrincipal(),
			),
		});
		rogueRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "KbAccess",
				actions: [
					"bedrock:GetKnowledgeBase",
					"bedrock:Retrieve",
					"bedrock:GetDocumentContent",
				],
				resources: [kbArn],
			}),
		);
		rogueRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "AgenticRetrieve",
				actions: ["bedrock:AgenticRetrieveStream"],
				resources: ["*"],
			}),
		);

		// ---- AgentCore Policy engine (gateway-side verification layer,
		// carried over from advanced-policy) ----
		// Hyphens are not allowed in policy engine and policy names.
		const policyEngine = new agentcore.CfnPolicyEngine(this, "PolicyEngine", {
			name: "managed_kb_rbp_engine",
			description:
				"Verifies that userContext matches the JWT email claim after interception",
		});
		// The gateway evaluates Cedar policies with its execution role:
		// CreateGateway validates GetPolicyEngine on the policy engine and
		// AuthorizeAction (the runtime evaluation API) on both the policy
		// engine and the gateway itself. The gateway ARN contains a
		// generated suffix that does not exist before creation, so
		// AuthorizeAction is scoped by name pattern instead.
		gwRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "PolicyEngineRead",
				actions: ["bedrock-agentcore:GetPolicyEngine"],
				resources: [policyEngine.attrPolicyEngineArn],
			}),
		);
		gwRole.addToPolicy(
			new iam.PolicyStatement({
				sid: "PolicyEvaluate",
				// AuthorizeAction evaluates tools/call; PartiallyAuthorizeActions
				// filters tools/list. Both are checked against the policy engine
				// and the gateway resource.
				actions: [
					"bedrock-agentcore:AuthorizeAction",
					"bedrock-agentcore:PartiallyAuthorizeActions",
				],
				resources: [
					policyEngine.attrPolicyEngineArn,
					`arn:aws:bedrock-agentcore:${region}:${account}:gateway/managed-kb-rbp-*`,
				],
			}),
		);

		// ---- Main gateway (CUSTOM_JWT + REQUEST interceptor + policy engine) ----
		const gateway = new agentcore.CfnGateway(this, "Gateway", {
			name: "managed-kb-rbp-gateway",
			description:
				"Legitimate gateway whose execution role the KB resource policy exempts",
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
		// The gateway only references gwRole.roleArn, which orders it after
		// the Role resource but NOT after the role's default policy.
		// CreateGateway validates GetPolicyEngine with the role, so it must
		// wait for the policy attachment (the Role construct includes it).
		gateway.node.addDependency(gwRole);

		// ---- Managed KB connector target (main gateway) ----
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

		// ---- Rogue gateway (no interceptor, no policy engine) ----
		// The exact scenario the article's gateway-side layers cannot
		// prevent: another gateway added for the same KB, executing as a
		// role other than the exempted one. Inbound auth still uses the
		// same Cognito issuer; the point is that nothing gateway-side
		// constrains userContext here, so only the KB resource policy
		// stands between this path and the documents.
		const rogueGateway = new agentcore.CfnGateway(this, "RogueGateway", {
			name: "managed-kb-rbp-rogue",
			description:
				"Interceptor-less gateway on a non-exempted role to observe the resource policy deny",
			roleArn: rogueRole.roleArn,
			protocolType: "MCP",
			authorizerType: "CUSTOM_JWT",
			authorizerConfiguration: {
				customJwtAuthorizer: {
					discoveryUrl,
					allowedClients: [userPoolClient.userPoolClientId],
				},
			},
			exceptionLevel: "DEBUG",
		});
		rogueGateway.node.addDependency(rogueRole);
		const rogueTarget = new agentcore.CfnGatewayTarget(this, "RogueKbTarget", {
			gatewayIdentifier: rogueGateway.attrGatewayIdentifier,
			name: "kb",
			description:
				"Managed KB Retrieve reached without any gateway-side control",
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
											"End-user identity for ACL-aware retrieval (caller-supplied)",
										visible: true,
									},
								],
							},
						],
					},
				},
			},
		});
		rogueTarget.node.addDependency(rogueRole);

		// ---- Cedar policies (main gateway only) ----
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

		for (const def of [
			{
				id: "MainRetrievePolicy",
				name: "managed_kb_rbp_main_retrieve",
				action: "kb___Retrieve",
			},
			{
				id: "MainAgenticPolicy",
				name: "managed_kb_rbp_main_agentic",
				action: "kb___AgenticRetrieveStream",
			},
		]) {
			const policy = new agentcore.CfnPolicy(this, def.id, {
				name: def.name,
				policyEngineId: policyEngine.attrPolicyEngineId,
				definition: {
					cedar: {
						statement: cedarUserContextMatch(
							def.action,
							gateway.attrGatewayArn,
						),
					},
				},
				validationMode: "FAIL_ON_ANY_FINDINGS",
			});
			policy.node.addDependency(target);
		}

		// ---- KB resource-based policy (asset-side layer) ----
		// Only bedrock:Retrieve and bedrock:GetDocumentContent are valid in
		// KB resource policies (control-plane actions and
		// bedrock:AgenticRetrieveStream are rejected), and wildcards are
		// not allowed in Action or Resource. The explicit deny overrides
		// any identity-based allow in this account, so every principal
		// except the legitimate gateway execution role loses Retrieve,
		// regardless of which path (direct API or another gateway) it uses.
		const kbResourcePolicy = {
			Version: "2012-10-17",
			Statement: [
				{
					Sid: "DenyRetrieveExceptGatewayRole",
					Effect: "Deny",
					Principal: "*",
					Action: ["bedrock:Retrieve", "bedrock:GetDocumentContent"],
					Resource: kbArn,
					Condition: {
						// aws:PrincipalArn resolves to the ROLE ARN (not the
						// assumed-role session ARN) for role sessions, so a
						// single ARN exempts every session of the gateway role.
						ArnNotEquals: { "aws:PrincipalArn": gwRole.roleArn },
					},
				},
			],
		};
		// No CloudFormation resource type exists for KB resource policies;
		// call the bedrock-agent API from a custom resource. The Lambda
		// runtime's bundled SDK may predate PutResourcePolicy, so install
		// the latest SDK at runtime.
		const putPolicyCall = {
			service: "bedrock-agent",
			action: "PutResourcePolicy",
			parameters: {
				resourceArn: kbArn,
				policy: JSON.stringify(kbResourcePolicy),
			},
			physicalResourceId: cr.PhysicalResourceId.of("kb-resource-policy"),
		};
		const kbPolicyResource = new cr.AwsCustomResource(
			this,
			"KbResourcePolicy",
			{
				onCreate: putPolicyCall,
				onUpdate: putPolicyCall,
				onDelete: {
					service: "bedrock-agent",
					action: "DeleteResourcePolicy",
					parameters: { resourceArn: kbArn },
					ignoreErrorCodesMatching: "ResourceNotFoundException",
				},
				installLatestAwsSdk: true,
				// fromSdkCalls would derive the IAM prefix from the SDK client
				// name (bedrock-agent), but the real prefix is bedrock.
				policy: cr.AwsCustomResourcePolicy.fromStatements([
					new iam.PolicyStatement({
						actions: [
							"bedrock:PutResourcePolicy",
							"bedrock:DeleteResourcePolicy",
						],
						resources: [kbArn],
					}),
				]),
			},
		);
		// Attach the deny only after both gateway targets exist, so target
		// creation (which validates KB access with the execution role) is
		// not entangled with the policy under test. This also mirrors the
		// threat: the rogue path exists first, then the asset-side control
		// shuts it down.
		kbPolicyResource.node.addDependency(target);
		kbPolicyResource.node.addDependency(rogueTarget);

		new cdk.CfnOutput(this, "KbId", { value: kb.attrKnowledgeBaseId });
		new cdk.CfnOutput(this, "KbArn", { value: kbArn });
		new cdk.CfnOutput(this, "DataSourceId", {
			value: dataSource.attrDataSourceId,
		});
		new cdk.CfnOutput(this, "BucketName", { value: bucket.bucketName });
		new cdk.CfnOutput(this, "UserPoolId", { value: userPool.userPoolId });
		new cdk.CfnOutput(this, "UserPoolClientId", {
			value: userPoolClient.userPoolClientId,
		});
		new cdk.CfnOutput(this, "GatewayUrl", { value: gateway.attrGatewayUrl });
		new cdk.CfnOutput(this, "GatewayId", {
			value: gateway.attrGatewayIdentifier,
		});
		new cdk.CfnOutput(this, "GatewayRoleArn", { value: gwRole.roleArn });
		new cdk.CfnOutput(this, "RogueGatewayUrl", {
			value: rogueGateway.attrGatewayUrl,
		});
		new cdk.CfnOutput(this, "RogueGatewayId", {
			value: rogueGateway.attrGatewayIdentifier,
		});
		new cdk.CfnOutput(this, "RogueRoleArn", { value: rogueRole.roleArn });
		new cdk.CfnOutput(this, "TestUserPasswordSecretName", {
			value: testPasswordSecret.secretName,
		});
		new cdk.CfnOutput(this, "PolicyEngineId", {
			value: policyEngine.attrPolicyEngineId,
		});
		new cdk.CfnOutput(this, "TargetId", { value: target.attrTargetId });
		new cdk.CfnOutput(this, "InterceptorFnName", {
			value: interceptorFn.functionName,
		});
		new cdk.CfnOutput(this, "PreTokenFnName", {
			value: preTokenFn.functionName,
		});
	}
}
