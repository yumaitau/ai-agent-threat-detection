# AI and agent threat detection

An open-source collection of detections, response playbooks and agent registers for Microsoft, AWS and Google environments.

The project detects signs of shadow AI, rogue or over-permissioned agents, agent credential abuse, prompt injection followed by possible exfiltration, and AI-speed bot or exploit attacks on internet-facing apps. These signals need investigation. High request rates alone do not establish that an attacker used AI.

Each platform pack runs in your own environment. The registers record agent ownership, permissions and review decisions. Evidence exports support security assessments; they do not establish compliance.

## Platform coverage

| Platform | Detections | Response and evidence | Deployment |
|---|---|---|---|
| [Microsoft](microsoft/README.md) | 15 catalogue entries: 11 KQL files and 4 specifications; Defender XDR, Sentinel, Entra, Graph, Global Secure Access and App Gateway logs | Logic App templates and playbook designs, register functions, workbook, evidence exports | ARM and Bicep |
| [AWS](aws/README.md) | 15 catalogue entries: 12 SQL files, 5 Logs Insights files with 7 queries, 6 EventBridge patterns and 1 specification; CloudTrail, Security Lake, Bedrock and WAF logs | Step Functions, 7 Lambda handlers, DynamoDB register, Athena views, CloudWatch dashboard, evidence exports | CloudFormation and Terraform |
| [Google](google/README.md) | 15 catalogue entries: 14 YARA-L files and 14 BigQuery queries; Workspace, Cloud Audit, Model Armor, DNS and Cloud Armor logs | Workflows, Cloud Run functions, BigQuery register and evidence exports; SecOps SOAR designs | Terraform |

Some IDs have several query formats. Some entries are hunts or specifications, not deployable rules. The [combined mapping table](mappings/README.md) and [CSV](mappings/detections.csv) preserve all 45 IDs and their original ISM, Essential Eight, MITRE ATLAS, ATT&CK and OWASP mappings.

## Validation status

**All implemented files passed the supplied offline syntax, schema or structural checks applicable to their format. They have NOT been tested against live tenants, cloud accounts, organisations or SecOps instances. Thresholds need tuning.**

Offline checks do not prove that a detection finds attacks, that source logs contain the expected values, or that a playbook deploys and runs correctly. YARA-L and Logs Insights receive structural linting, not a vendor compiler check. Logic Apps workflow semantics and dashboard rendering remain untested. Bicep produces non-fatal warnings. Specifications have no executable implementation to validate.

Read the [validation report and limits](docs/validation.md) before deployment. CI uses no cloud credentials and performs no cloud deployments.

## Quick start

Clone the repository and run the [offline validation setup](docs/validation.md#run-locally). Choose one platform and work in a lab first. Review the required logs, permissions and placeholders in its README.

### Microsoft

1. Open [the Microsoft setup guide](microsoft/README.md). Enable the required Sentinel and Defender data sources.
2. From `microsoft/`, deploy `deploy/register-infra.json`, then `deploy/workbook.json` and the selected analytics rule templates. Replace the workspace, resource and rule ID placeholders.
3. Configure the playbook identities and connections. Rules and Logic Apps start disabled. Replay representative events, tune thresholds and test approval and recovery before enabling them.

### AWS

1. Open [the AWS setup guide](aws/README.md). Configure CloudTrail, Security Lake, model invocation and WAF logging for the detections you need.
2. From `aws/`, run `python3 tools/package_lambdas.py`. Upload the generated artefacts to your bucket, then deploy `deploy/cfn/yuma-aia-core.yaml` in a lab account.
3. Review `deploy/terraform/pb3-waf-block/` with `auto_block = false`. Populate the register and test the approval path. The scheduled SQL detection runner is not included yet.

### Google

1. Open [the Google setup guide](google/README.md). Configure a linked Log Analytics dataset, Workspace export and the required Data Access logs.
2. In `google/deploy/terraform/`, copy `terraform.tfvars.example` to `terraform.tfvars`, replace every placeholder, then run `terraform init` and `terraform plan`.
3. Review the plan before applying in a lab. Configure IAP approval and Workspace delegation, seed the register and test each playbook. SecOps users must also configure reference lists and compile the YARA-L rules in SecOps.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) for changes and validation. Use the issue templates for false positives, detection proposals and bugs. Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Participation follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Licence

MIT. Copyright 2026 Yuma IT Pty Ltd. See [LICENSE](LICENSE). The Contributor Covenant retains its attribution in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
