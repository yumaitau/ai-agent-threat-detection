#!/usr/bin/env python3
"""Builds deploy/cfn/yuma-aia-core.yaml. EventBridge patterns are read from detections/*.eventbridge.json so the
template and the detection files can't drift. Long-form intrinsics (Fn::Sub, Ref, Fn::GetAtt) keep it plain YAML."""
import json
import pathlib

import sys
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
DET = ROOT / "detections"


def pattern(name):
    return json.loads((DET / name).read_text())


def sub(s):
    return {"Fn::Sub": s}


def ref(x):
    return {"Ref": x}


def att(x, a):
    return {"Fn::GetAtt": [x, a]}


def lambda_fn(logical, module, role, env, timeout=60, memory=256, desc=""):
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "FunctionName": sub("${AWS::StackName}-" + module.replace("_", "-")),
            "Description": desc,
            "Runtime": "python3.12",
            "Handler": f"{module}.handler",
            "Role": att(role, "Arn"),
            "Timeout": timeout,
            "MemorySize": memory,
            "Code": {"S3Bucket": ref("ArtifactBucket"), "S3Key": sub("${ArtifactPrefix}lambda/" + module + ".zip")},
            "Environment": {"Variables": env},
            "LoggingConfig": {"LogFormat": "JSON"},
        },
    }


def role(statements, service="lambda.amazonaws.com", managed=None):
    r = {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]},
            "Policies": [{"PolicyName": "inline", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}],
        },
    }
    if managed:
        r["Properties"]["ManagedPolicyArns"] = managed
    return r


BASIC = [sub("arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")]
TABLE_ARN = att("RegisterTable", "Arn")
TABLE_IDX = sub("${RegisterTable.Arn}/index/*")
ENV_TABLE = {"REGISTER_TABLE": ref("RegisterTable")}

t = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Yuma AI agent threat pack (AWS) core: register, evidence bucket, PB1 containment with human approval, "
                   "PB2 register writer, PB4 inventory, PB5 ISM evidence export, EventBridge detections A03/A04/A10/A12 "
                   "and GuardDuty AI Protection routing. DRAFT - lab use only until validated.",
    "Parameters": {
        "ArtifactBucket": {"Type": "String", "Description": "S3 bucket holding Lambda zips and the PB1 ASL (tools/package_lambdas.py output)"},
        "ArtifactPrefix": {"Type": "String", "Default": "yuma-aia/0.1.0/", "Description": "Key prefix ending in /"},
        "ApproverEmail": {"Type": "String", "Description": "Mailbox for containment approval requests (SNS email subscription)"},
        "RegisterEmail": {"Type": "String", "Description": "Mailbox for register decisions and review reminders"},
        "ChatWebhookSecretId": {"Type": "String", "Default": "", "Description": "Optional Secrets Manager secret ID holding a Slack or Teams incoming webhook URL"},
        "ContainmentMode": {"Type": "String", "Default": "deny-all", "AllowedValues": ["deny-all", "revoke-sessions"]},
        "EvidenceRetentionDays": {"Type": "Number", "Default": 2555, "MinValue": 1, "Description": "S3 Object Lock default retention (compliance mode). Default about 7 years; set to the customer's records policy"},
        "TrailName": {"Type": "String", "Default": "", "Description": "CloudTrail trail name PB5 inspects for Bedrock/AgentCore data event selectors"},
        "LookupTableArn": {"Type": "String", "Default": "", "Description": "Optional CloudWatch Logs lookup table ARN (yuma_aia_register) refreshed by PB4 for A02"},
    },
    "Conditions": {
        "IsUsEast1": {"Fn::Equals": [ref("AWS::Region"), "us-east-1"]},
        "HasWebhook": {"Fn::Not": [{"Fn::Equals": [ref("ChatWebhookSecretId"), ""]}]},
    },
    "Resources": {},
    "Outputs": {},
}
R = t["Resources"]

# ---------------- register and evidence ----------------
R["RegisterTable"] = {
    "Type": "AWS::DynamoDB::Table",
    "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
    "Properties": {
        "TableName": sub("YumaAIAgentRegister-${AWS::Region}"),
        "BillingMode": "PAY_PER_REQUEST",
        "AttributeDefinitions": [{"AttributeName": n, "AttributeType": "S"} for n in ("pk", "sk", "status", "next_review_due")],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        "GlobalSecondaryIndexes": [{"IndexName": "by-status-review",
                                    "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"}, {"AttributeName": "next_review_due", "KeyType": "RANGE"}],
                                    "Projection": {"ProjectionType": "ALL"}}],
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        "SSESpecification": {"SSEEnabled": True},
        "DeletionProtectionEnabled": True,
    },
}
R["EvidenceBucket"] = {
    "Type": "AWS::S3::Bucket",
    "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
    "Properties": {
        "ObjectLockEnabled": True,
        "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": ref("EvidenceRetentionDays")}}},
        "VersioningConfiguration": {"Status": "Enabled"},
        "BucketEncryption": {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]},
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
        "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
    },
}
R["EvidenceBucketPolicy"] = {
    "Type": "AWS::S3::BucketPolicy",
    "Properties": {"Bucket": ref("EvidenceBucket"), "PolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": [att("EvidenceBucket", "Arn"), sub("${EvidenceBucket.Arn}/*")],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}},
}

# ---------------- notifications ----------------
for name, subj_param in (("ApprovalTopic", "ApproverEmail"), ("NotifyTopic", "ApproverEmail"), ("RegisterTopic", "RegisterEmail")):
    R[name] = {"Type": "AWS::SNS::Topic", "Properties": {"KmsMasterKeyId": "alias/aws/sns",
               "Subscription": [{"Protocol": "email", "Endpoint": ref(subj_param)}]}}
R["NotifyTopicPolicy"] = {
    "Type": "AWS::SNS::TopicPolicy",
    "Properties": {"Topics": [ref("NotifyTopic")], "PolicyDocument": {"Version": "2012-10-17", "Statement": [
        {"Sid": "AllowEventBridge", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sns:Publish",
         "Resource": ref("NotifyTopic"), "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]}},
}

# ---------------- PB1 ----------------
R["PB1EnrichRole"] = role([
    {"Effect": "Allow", "Action": ["iam:GetRole"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": TABLE_ARN}], managed=BASIC)
R["PB1ApprovalRole"] = role([
    {"Effect": "Allow", "Action": ["sns:Publish"], "Resource": ref("ApprovalTopic")},
    {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
     "Resource": {"Fn::If": ["HasWebhook", sub("arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:${ChatWebhookSecretId}*"),
                             sub("arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:none-configured")]}}], managed=BASIC)
R["PB1ContainRole"] = role([
    {"Sid": "ContainAgentIdentities", "Effect": "Allow",
     "Action": ["iam:PutRolePolicy", "iam:TagRole", "iam:ListAccessKeys", "iam:UpdateAccessKey"],
     "Resource": [sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*"), sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:user/*")]},
    {"Sid": "NeverContainThePackOrBreakGlass", "Effect": "Deny",
     "Action": ["iam:PutRolePolicy", "iam:TagRole"],
     "Resource": [sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${AWS::StackName}-*"),
                  sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/aws-reserved/*"),
                  sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/OrganizationAccountAccessRole")]}], managed=BASIC)
R["PB1EnrichFunction"] = lambda_fn("PB1EnrichFunction", "pb1_enrich", "PB1EnrichRole", ENV_TABLE, desc="PB1 enrich")
R["PB1RequestApprovalFunction"] = lambda_fn("PB1RequestApprovalFunction", "pb1_request_approval", "PB1ApprovalRole", {
    "APPROVAL_TOPIC_ARN": ref("ApprovalTopic"), "CHAT_WEBHOOK_SECRET_ID": ref("ChatWebhookSecretId"),
    "APPROVAL_TIMEOUT_HOURS": "4"}, desc="PB1 approval request (task token)")
R["PB1ContainFunction"] = lambda_fn("PB1ContainFunction", "pb1_contain", "PB1ContainRole", {
    "CONTAINMENT_MODE": ref("ContainmentMode"), "CONTAINMENT_POLICY_NAME": "YumaAIAContainment"}, desc="PB1 containment")
R["PB1StateMachineRole"] = role([
    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": [att(f, "Arn") for f in ("PB1EnrichFunction", "PB1RequestApprovalFunction", "PB1ContainFunction")]},
    {"Effect": "Allow", "Action": "sns:Publish", "Resource": ref("NotifyTopic")},
    {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": TABLE_ARN}], service="states.amazonaws.com")
R["PB1StateMachine"] = {
    "Type": "AWS::StepFunctions::StateMachine",
    "Properties": {
        "StateMachineType": "STANDARD",
        "RoleArn": att("PB1StateMachineRole", "Arn"),
        "DefinitionS3Location": {"Bucket": ref("ArtifactBucket"), "Key": sub("${ArtifactPrefix}asl/PB1-agent-containment.asl.json")},
        "DefinitionSubstitutions": {
            "EnrichFunctionArn": att("PB1EnrichFunction", "Arn"),
            "RequestApprovalFunctionArn": att("PB1RequestApprovalFunction", "Arn"),
            "ContainFunctionArn": att("PB1ContainFunction", "Arn"),
            "NotifyTopicArn": ref("NotifyTopic"),
            "RegisterTableName": ref("RegisterTable"),
        },
        "TracingConfiguration": {"Enabled": True},
    },
}
R["EventsToStatesRole"] = role([{"Effect": "Allow", "Action": "states:StartExecution", "Resource": ref("PB1StateMachine")}],
                               service="events.amazonaws.com")

# ---------------- PB2 ----------------
R["PB2Role"] = role([
    {"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"], "Resource": [TABLE_ARN, TABLE_IDX]},
    {"Effect": "Allow", "Action": "sns:Publish", "Resource": ref("RegisterTopic")}], managed=BASIC)
R["PB2RegisterWriterFunction"] = lambda_fn("PB2RegisterWriterFunction", "pb2_register_writer", "PB2Role",
                                           dict(ENV_TABLE, REGISTER_TOPIC_ARN=ref("RegisterTopic")), desc="PB2 register writer")
R["PB2InvokePermission"] = {"Type": "AWS::Lambda::Permission", "Properties": {
    "FunctionName": ref("PB2RegisterWriterFunction"), "Action": "lambda:InvokeFunction", "Principal": "events.amazonaws.com",
    "SourceArn": att("RuleA03AgentOrToolChange", "Arn")}}

# ---------------- PB4 / PB5 ----------------
R["PB4Role"] = role([
    {"Sid": "Inventory", "Effect": "Allow", "Action": [
        "bedrock:ListAgents", "bedrock:GetAgent",
        "bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:GetAgentRuntime", "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:GetGateway", "bedrock-agentcore:ListWorkloadIdentities",
        "bedrock-agentcore:ListOauth2CredentialProviders", "bedrock-agentcore:ListApiKeyCredentialProviders",
        "agent-registry:ListRegistries", "agent-registry:ListRegistryRecords",
        "iam:ListRoles", "sts:GetCallerIdentity"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["dynamodb:Scan", "dynamodb:PutItem"], "Resource": TABLE_ARN},
    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": [sub("${EvidenceBucket.Arn}/inventory/*"), sub("${EvidenceBucket.Arn}/register/*")]},
    {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*", "Condition": {"StringEquals": {"cloudwatch:namespace": "Yuma/AIA"}}},
    {"Effect": "Allow", "Action": "logs:UpdateLookupTable", "Resource": "*"}], managed=BASIC)
R["PB4InventoryFunction"] = lambda_fn("PB4InventoryFunction", "pb4_inventory", "PB4Role", dict(
    ENV_TABLE, EVIDENCE_BUCKET=ref("EvidenceBucket"), LOOKUP_TABLE_ARN=ref("LookupTableArn")), timeout=300, desc="PB4 daily inventory")
R["PB5Role"] = role([
    {"Effect": "Allow", "Action": ["dynamodb:Scan"], "Resource": TABLE_ARN},
    {"Effect": "Allow", "Action": ["bedrock:GetModelInvocationLoggingConfiguration", "cloudtrail:GetEventSelectors",
                                   "guardduty:ListDetectors", "guardduty:GetDetector"], "Resource": "*"},
    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": sub("${EvidenceBucket.Arn}/evidence/*")}], managed=BASIC)
R["PB5EvidenceExportFunction"] = lambda_fn("PB5EvidenceExportFunction", "pb5_evidence_export", "PB5Role", dict(
    ENV_TABLE, EVIDENCE_BUCKET=ref("EvidenceBucket"), TRAIL_NAME=ref("TrailName")), timeout=300, desc="PB5 ISM evidence export")
R["SchedulerRole"] = role([{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": [
    att("PB2RegisterWriterFunction", "Arn"), att("PB4InventoryFunction", "Arn"), att("PB5EvidenceExportFunction", "Arn")]}],
    service="scheduler.amazonaws.com")
for name, fn, expr, payload in (
        ("SchedulePB2ReviewSweep", "PB2RegisterWriterFunction", "cron(0 8 ? * MON *)", '{"action": "review-sweep"}'),
        ("SchedulePB4Inventory", "PB4InventoryFunction", "cron(30 6 * * ? *)", "{}"),
        ("SchedulePB5EvidenceExport", "PB5EvidenceExportFunction", "cron(0 7 1 * ? *)", "{}")):
    R[name] = {"Type": "AWS::Scheduler::Schedule", "Properties": {
        "ScheduleExpression": expr, "ScheduleExpressionTimezone": "Australia/Sydney",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {"Arn": att(fn, "Arn"), "RoleArn": att("SchedulerRole", "Arn"), "Input": payload}}}

# ---------------- EventBridge detections ----------------
R["RuleA03AgentOrToolChange"] = {"Type": "AWS::Events::Rule", "Properties": {
    "Description": "Yuma AIA-A03: new or changed AI agent, tool, gateway target, workload identity or credential provider -> PB2",
    "EventPattern": pattern("A03-agent-or-tool-change.eventbridge.json"), "State": "ENABLED",
    "Targets": [{"Id": "pb2", "Arn": att("PB2RegisterWriterFunction", "Arn")}]}}
R["RuleA04AgentRolePrivilegeChange"] = {"Type": "AWS::Events::Rule", "Condition": "IsUsEast1", "Properties": {
    "Description": "Yuma AIA-A04: IAM role policy change (IAM events are recorded in us-east-1) -> PB1 decides if it is an agent role",
    "EventPattern": pattern("A04-agent-role-privilege-change.eventbridge.json"), "State": "ENABLED",
    "Targets": [{"Id": "pb1", "Arn": ref("PB1StateMachine"), "RoleArn": att("EventsToStatesRole", "Arn")}]}}
R["RuleGuardDutyAIProtection"] = {"Type": "AWS::Events::Rule", "Properties": {
    "Description": "GuardDuty AI Protection findings (prompt injection, anomalous model invocation, cost harvesting) -> PB1",
    "EventPattern": pattern("A10-guardduty-ai-findings.eventbridge.json"), "State": "ENABLED",
    "Targets": [{"Id": "pb1", "Arn": ref("PB1StateMachine"), "RoleArn": att("EventsToStatesRole", "Arn")}]}}
R["RuleA10PromptAttackSignal"] = {"Type": "AWS::Events::Rule", "Properties": {
    "Description": "Yuma AIA-A10 signal: Bedrock guardrail intervened on a prompt attack (needs AWS::Bedrock::Guardrail data events) -> notify",
    "EventPattern": pattern("A10-prompt-attack-signal.eventbridge.json"), "State": "ENABLED",
    "Targets": [{"Id": "notify", "Arn": ref("NotifyTopic")}]}}
R["RuleA12GuardrailOrLoggingTamper"] = {"Type": "AWS::Events::Rule", "Properties": {
    "Description": "Yuma AIA-A12: guardrail, enforced guardrail, invocation logging, trail selector or GuardDuty detector changed -> notify",
    "EventPattern": pattern("A12-guardrail-or-logging-tamper.eventbridge.json"), "State": "ENABLED",
    "Targets": [{"Id": "notify", "Arn": ref("NotifyTopic")}]}}

t["Outputs"] = {
    "RegisterTableName": {"Value": ref("RegisterTable")},
    "EvidenceBucketName": {"Value": ref("EvidenceBucket")},
    "PB1StateMachineArn": {"Value": ref("PB1StateMachine")},
    "ApprovalTopicArn": {"Value": ref("ApprovalTopic")},
}

out = ROOT / "deploy" / "cfn" / "yuma-aia-core.yaml"
out.parent.mkdir(parents=True, exist_ok=True)
header = "# GENERATED by tools/build_cfn.py - edit the generator, not this file.\n"
class NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


text = header + yaml.dump(t, Dumper=NoAlias, sort_keys=False, width=140)
if "--stdout" in sys.argv:
    sys.stdout.write(text)
else:
    out.write_text(text)
    print(f"wrote {out} ({len(R)} resources)")
