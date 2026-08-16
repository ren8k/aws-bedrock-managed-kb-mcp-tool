#!/usr/bin/env node
import * as cdk from "aws-cdk-lib/core";
import { ManagedKbGatewayStack } from "../lib/managed-kb-gateway-stack";

const app = new cdk.App();
new ManagedKbGatewayStack(app, "ManagedKbGatewayStack", {
	env: {
		account: process.env.CDK_DEFAULT_ACCOUNT,
		region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
	},
});
