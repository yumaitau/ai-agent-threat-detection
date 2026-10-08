# PB1 Agent identity containment, with named human approval

**Trigger (EventBridge to Step Functions):**
- A04 IAM role policy change (rule in us-east-1, because IAM events are recorded there)
- GuardDuty AI Protection findings: `Impact:IAMUser/PromptInjection.Direct`, `Impact:IAMUser/AnomalousModelInvocation`,
  `Impact:IAMUser/CostHarvesting` (https://docs.aws.amazon.com/guardduty/latest/ug/findings-ai-protection.html)
- Scheduled detections (A07, A08, A10, A11) can start it with a `{"source": "yuma.aia", "detail": {...}}` input.

**Flow** (`asl/PB1-agent-containment.asl.json`, Standard workflow):
1. **Enrich** (`pb1_enrich.py`): resolve the principal; `iam:GetRole`; is it trusted by `bedrock.amazonaws.com` or
   `bedrock-agentcore.amazonaws.com`, or listed in the register? Who owns it?
2. Not an agent identity: notify only. Human identities are out of scope for automated containment.
3. **Request approval** (`lambda:invoke.waitForTaskToken`, timeout 4 hours): `pb1_request_approval.py` emails the
   approver topic and, optionally, posts to a Slack or Teams incoming webhook (URL kept in Secrets Manager).
   The message carries an AWS CLI command (`aws stepfunctions send-task-success --task-token ...`). The approver
   runs it with their own Identity Center session, so CloudTrail records who approved (ISM-2113 evidence).
   There is no public callback URL to protect. Callback pattern:
   https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html
4. **Contain** (`pb1_contain.py`): put inline policy `YumaAIAContainment` on the role. The mode is `deny-all` (default)
   or `revoke-sessions`, which denies sessions issued before now using `aws:TokenIssueTime`, as in AWS's documented
   pattern (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html). For an IAM user,
   its access keys are set Inactive. The role is tagged with the approver.
5. **Record**: an ApprovalDecision history item is written to the register (status Contained), then notify.
6. Rejection or timeout: notify, no change.

**Undo:** delete the inline policy (`aws iam delete-role-policy --role-name <r> --policy-name YumaAIAContainment`)
or reactivate the keys. Record a new register decision with `tools/register_decide.py`.

**Guardrails on PB1's own power:**
- The contain role may only touch roles and users in its own account.
- It has an explicit Deny on the pack's own roles, `aws-reserved/*` (Identity Center) and `OrganizationAccountAccessRole`.
- Add break-glass roles to that Deny before go-live. Consider a permissions boundary on the contain role too.

**ISM:** 2113, 2148, 2156. **Deployed by:** `deploy/cfn/yuma-aia-core.yaml`.
