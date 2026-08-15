#!/usr/bin/env node
import * as cdk from "aws-cdk-lib/core";
import { ManagedKbRbpStack } from "../lib/managed-kb-rbp-stack";

const app = new cdk.App();
new ManagedKbRbpStack(app, "ManagedKbRbpStack", {
	env: {
		account: process.env.CDK_DEFAULT_ACCOUNT,
		region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
	},
});
