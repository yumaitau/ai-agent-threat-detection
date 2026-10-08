#!/usr/bin/env python3
"""Offline Lambda tests with botocore Stubber. Stubber rejects any request whose operation or parameters don't
match AWS's published service model, so these tests prove the API calls are well-formed (names, required
parameters, types). They don't prove IAM permissions or live behaviour."""
import datetime as dt
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.update({"AWS_DEFAULT_REGION": "ap-southeast-2", "AWS_REGION": "ap-southeast-2", "AWS_ACCESS_KEY_ID": "x",
                   "AWS_SECRET_ACCESS_KEY": "x", "REGISTER_TABLE": "YumaAIAgentRegister-ap-southeast-2",
                   "REGISTER_TOPIC_ARN": "arn:aws:sns:ap-southeast-2:000000000000:reg",
                   "APPROVAL_TOPIC_ARN": "arn:aws:sns:ap-southeast-2:000000000000:appr",
                   "EVIDENCE_BUCKET": "yuma-evidence", "TRAIL_NAME": "org-trail",
                   "WAF_LOG_GROUP": "aws-waf-logs-app", "IPSET_NAME": "yuma-aia-pb3-block", "IPSET_ID": "00000000-0000-0000-0000-000000000000",
                   "IPSET_SCOPE": "REGIONAL", "AUTO_BLOCK": "true", "LOOKUP_TABLE_ARN": "arn:aws:logs:ap-southeast-2:000000000000:lookup-table:yuma_aia_register"})
sys.path.insert(0, str(ROOT / "playbooks" / "lambda"))

from botocore.stub import ANY, Stubber  # noqa: E402

import pb1_contain  # noqa: E402
import pb1_enrich  # noqa: E402
import pb2_register_writer  # noqa: E402
import pb3_waf_block  # noqa: E402
import pb4_inventory  # noqa: E402
import pb5_evidence_export  # noqa: E402

SAMPLES = ROOT / "detections" / "samples"
T = os.environ["REGISTER_TABLE"]


class PB1(unittest.TestCase):
    def test_enrich_guardduty_finding(self):
        ev = json.loads((SAMPLES / "gd-prompt-injection.json").read_text())
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        with Stubber(pb1_enrich.iam) as iam_s, Stubber(pb1_enrich.ddb) as ddb_s:
            iam_s.add_response("get_role", {"Role": {"Path": "/", "RoleName": "AgentCoreRuntimeRole", "RoleId": "AROAEXAMPLEEXAMPLE1",
                               "Arn": "arn:aws:iam::000000000000:role/AgentCoreRuntimeRole", "CreateDate": dt.datetime(2026, 1, 1),
                               "AssumeRolePolicyDocument": json.dumps(trust)}}, {"RoleName": "AgentCoreRuntimeRole"})
            ddb_s.add_response("get_item", {}, {"TableName": T, "Key": {"pk": {"S": "IDENTITY#arn:aws:iam::000000000000:role/AgentCoreRuntimeRole"}, "sk": {"S": "MAP"}}})
            out = pb1_enrich.handler(ev, None)
        self.assertTrue(out["is_agent_identity"])
        self.assertEqual(out["role_arn"], "arn:aws:iam::000000000000:role/AgentCoreRuntimeRole")

    def test_contain_role_deny_all(self):
        ctx = {"role_arn": "arn:aws:iam::000000000000:role/AgentCoreRuntimeRole", "agent": {"agent_id": "arn:aws:bedrock-agentcore:ap-southeast-2:000000000000:runtime/rt-1"}}
        with Stubber(pb1_contain.iam) as s:
            s.add_response("put_role_policy", {}, {"RoleName": "AgentCoreRuntimeRole", "PolicyName": "YumaAIAContainment", "PolicyDocument": ANY})
            s.add_response("tag_role", {}, {"RoleName": "AgentCoreRuntimeRole", "Tags": ANY})
            out = pb1_contain.handler({"context": ctx, "decision": {"decision": "approve", "approver": "EXAMPLE_APPROVER"}}, None)
        self.assertEqual(out["agent_id"], ctx["agent"]["agent_id"])


class PB2(unittest.TestCase):
    def test_create_gateway_goes_to_register(self):
        ev = json.loads((SAMPLES / "ct-create-gateway.json").read_text())
        with Stubber(pb2_register_writer.ddb) as d, Stubber(pb2_register_writer.sns) as n:
            d.add_response("put_item", {}, {"TableName": T, "Item": ANY})
            d.add_response("update_item", {}, {"TableName": T, "Key": ANY, "UpdateExpression": ANY,
                                               "ExpressionAttributeNames": ANY, "ExpressionAttributeValues": ANY})
            d.add_response("put_item", {}, {"TableName": T, "Item": ANY})
            n.add_response("publish", {"MessageId": "m1"}, {"TopicArn": os.environ["REGISTER_TOPIC_ARN"], "Subject": ANY, "Message": ANY})
            out = pb2_register_writer.handler(ev, None)
        self.assertEqual(out["agent_id"], "arn:aws:bedrock-agentcore:ap-southeast-2:000000000000:gateway/gw-abc")

    def test_review_sweep(self):
        with Stubber(pb2_register_writer.ddb) as d, Stubber(pb2_register_writer.sns) as n:
            d.add_response("query", {"Items": [{"agent_id": {"S": "a1"}, "owner": {"S": "EXAMPLE_OWNER"}, "next_review_due": {"S": "2026-10-20"}}]},
                           {"TableName": T, "IndexName": "by-status-review", "KeyConditionExpression": ANY,
                            "ExpressionAttributeNames": ANY, "ExpressionAttributeValues": ANY})
            n.add_response("publish", {"MessageId": "m2"}, {"TopicArn": os.environ["REGISTER_TOPIC_ARN"], "Subject": ANY, "Message": ANY})
            self.assertEqual(pb2_register_writer.handler({"action": "review-sweep"}, None)["due"], 1)


class PB3(unittest.TestCase):
    def test_block_with_lock_token(self):
        rows = [{"ip": "203.0.113.10", "rulesHit": "7", "requests": "420"}]
        with mock.patch.object(pb3_waf_block, "enrich", return_value={"greynoise": {"classification": "malicious", "riot": False}}), \
             Stubber(pb3_waf_block.ddb) as d, Stubber(pb3_waf_block.waf) as w:
            d.add_response("put_item", {}, {"TableName": T, "Item": ANY})
            d.add_response("query", {"Items": []}, {"TableName": T, "KeyConditionExpression": ANY, "FilterExpression": ANY, "ExpressionAttributeValues": ANY})
            w.add_response("get_ip_set", {"IPSet": {"Name": "yuma-aia-pb3-block", "Id": os.environ["IPSET_ID"], "ARN": "arn:aws:wafv2:ap-southeast-2:000000000000:regional/ipset/yuma-aia-pb3-block/x",
                           "IPAddressVersion": "IPV4", "Addresses": ["198.51.100.1/32"]}, "LockToken": "tok-1"},
                           {"Name": "yuma-aia-pb3-block", "Scope": "REGIONAL", "Id": os.environ["IPSET_ID"]})
            w.add_response("update_ip_set", {"NextLockToken": "tok-2"}, {"Name": "yuma-aia-pb3-block", "Scope": "REGIONAL", "Id": os.environ["IPSET_ID"],
                           "Addresses": ["198.51.100.1/32", "203.0.113.10/32"], "LockToken": "tok-1"})
            out = pb3_waf_block.handler({"rows": rows}, None)
        self.assertEqual(out["proposed"], ["203.0.113.10/32"])

    def test_query_file_is_bundled_and_comment_free(self):
        q = pb3_waf_block._query_string() if (pathlib.Path(pb3_waf_block.QUERY_FILE)).exists() else None
        if q is None:
            q = "\n".join(l for l in (ROOT / "detections" / "A14-ai-speed-waf-burst.logsinsights").read_text().splitlines() if not l.startswith("#"))
        self.assertNotIn("#", q.split("\n")[0])
        self.assertIn("countDistinct", q)


class PB4(unittest.TestCase):
    def test_inventory_and_snapshot(self):
        import boto3
        made = {}
        real = boto3.client

        def fake_client(name, *a, **k):
            c = real(name, region_name="ap-southeast-2", aws_access_key_id="x", aws_secret_access_key="x")
            st = Stubber(c)
            made[name] = st
            if name == "bedrock-agent":
                st.add_response("list_agents", {"agentSummaries": [{"agentId": "AGENT1", "agentName": "hr-helper", "agentStatus": "PREPARED", "updatedAt": dt.datetime(2026, 10, 1)}]}, {})
                st.add_response("get_agent", {"agent": {"agentId": "AGENT1", "agentName": "hr-helper", "agentArn": "arn:aws:bedrock:ap-southeast-2:000000000000:agent/AGENT1",
                                "agentVersion": "DRAFT", "agentStatus": "PREPARED", "idleSessionTTLInSeconds": 600, "agentResourceRoleArn": "arn:aws:iam::000000000000:role/AmazonBedrockExecutionRoleForAgents_hr",
                                "createdAt": dt.datetime(2026, 1, 1), "updatedAt": dt.datetime(2026, 10, 1)}}, {"agentId": "AGENT1"})
            elif name == "bedrock-agentcore-control":
                st.add_response("list_agent_runtimes", {"agentRuntimes": []}, {})
                st.add_response("list_gateways", {"items": []}, {})
                st.add_response("list_workload_identities", {"workloadIdentities": []}, {})
                st.add_response("list_oauth2_credential_providers", {"credentialProviders": []}, {})
                st.add_response("list_api_key_credential_providers", {"credentialProviders": []}, {})
            elif name == "agent-registry-control":
                st.add_response("list_registries", {"registries": []}, {})
            elif name == "sts":
                st.add_response("get_caller_identity", {"Account": "000000000000", "Arn": "arn:aws:sts::000000000000:assumed-role/x/y", "UserId": "AROAX:y"}, {})
            st.activate()
            return c
        reg_empty = {"Items": []}
        with mock.patch.object(pb4_inventory.boto3, "client", side_effect=fake_client), \
             Stubber(pb4_inventory.iam) as i, Stubber(pb4_inventory.ddb) as d, Stubber(pb4_inventory.s3) as s, \
             Stubber(pb4_inventory.logs) as lg, Stubber(pb4_inventory.cw) as cw:
            i.add_response("list_roles", {"Roles": [], "IsTruncated": False}, {})
            d.add_response("scan", reg_empty, {"TableName": T, "FilterExpression": ANY, "ExpressionAttributeValues": ANY})
            d.add_response("put_item", {}, {"TableName": T, "Item": ANY})                       # history
            d.add_response("put_item", {}, {"TableName": T, "Item": ANY, "ConditionExpression": ANY})  # CURRENT
            d.add_response("put_item", {}, {"TableName": T, "Item": ANY})                       # identity map
            d.add_response("scan", {"Items": [{"pk": {"S": "AGENT#a"}, "sk": {"S": "CURRENT"}, "agent_id": {"S": "arn:aws:bedrock:ap-southeast-2:000000000000:agent/AGENT1"},
                           "status": {"S": "PendingReview"}, "identities": {"SS": ["arn:aws:iam::000000000000:role/AmazonBedrockExecutionRoleForAgents_hr"]}}]},
                           {"TableName": T, "FilterExpression": ANY, "ExpressionAttributeValues": ANY})
            s.add_response("put_object", {}, {"Bucket": "yuma-evidence", "Key": ANY, "Body": ANY})
            s.add_response("put_object", {}, {"Bucket": "yuma-evidence", "Key": ANY, "Body": ANY})
            lg.add_response("update_lookup_table", {"lookupTableArn": os.environ["LOOKUP_TABLE_ARN"]}, {"lookupTableArn": os.environ["LOOKUP_TABLE_ARN"], "tableBody": ANY})
            cw.add_response("put_metric_data", {}, {"Namespace": "Yuma/AIA", "MetricData": ANY})
            out = pb4_inventory.handler({}, None)
        self.assertEqual(out["new"], 1)
        self.assertEqual(out["pending"], 1)


class PB5(unittest.TestCase):
    def test_export(self):
        with Stubber(pb5_evidence_export.ddb) as d, Stubber(pb5_evidence_export.bedrock) as b, \
             Stubber(pb5_evidence_export.cloudtrail) as c, Stubber(pb5_evidence_export.guardduty) as g, Stubber(pb5_evidence_export.s3) as s:
            d.add_response("scan", {"Items": [{"agent_id": {"S": "a1"}, "agent_name": {"S": "hr-helper"}, "status": {"S": "Approved"},
                           "owner": {"S": "EXAMPLE_OWNER"}, "business_purpose": {"S": "HR FAQs"}, "identities": {"SS": ["arn:aws:iam::000000000000:role/r1"]},
                           "last_review": {"S": "2026-06-01"}, "next_review_due": {"S": "2026-11-30"}}]},
                           {"TableName": T, "FilterExpression": ANY, "ExpressionAttributeValues": ANY})
            b.add_response("get_model_invocation_logging_configuration", {"loggingConfig": {"cloudWatchConfig": {"logGroupName": "/bedrock/inv", "roleArn": "arn:aws:iam::000000000000:role/bedrock-logs"}}}, {})
            c.add_response("get_event_selectors", {"AdvancedEventSelectors": [{"Name": "agentcore", "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::BedrockAgentCore::Gateway", "AWS::Bedrock::AgentAlias", "AWS::Bedrock::Guardrail"]}]}]},
                {"TrailName": "org-trail"})
            g.add_response("list_detectors", {"DetectorIds": ["d1"]}, {})
            g.add_response("get_detector", {"ServiceRole": "arn:aws:iam::000000000000:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
                           "Status": "ENABLED", "Features": [{"Name": "AI_PROTECTION", "Status": "ENABLED"}]}, {"DetectorId": "d1"})
            for _ in range(4):
                s.add_response("put_object", {}, {"Bucket": "yuma-evidence", "Key": ANY, "Body": ANY, "ChecksumAlgorithm": "SHA256"})
            out = pb5_evidence_export.handler({}, None)
        self.assertIn("evidence/", out["prefix"])
        self.assertGreaterEqual(out["status_counts"].get("Evidence present", 0), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
