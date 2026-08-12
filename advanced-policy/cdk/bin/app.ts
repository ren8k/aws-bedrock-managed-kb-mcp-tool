#!/usr/bin/env node
import * as cdk from "aws-cdk-lib/core";
import { ManagedKbPolicyStack } from "../lib/managed-kb-policy-stack";

const app = new cdk.App();
new ManagedKbPolicyStack(app, "ManagedKbPolicyStack", {
	env: {
		account: process.env.CDK_DEFAULT_ACCOUNT,
		region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
	},
});
