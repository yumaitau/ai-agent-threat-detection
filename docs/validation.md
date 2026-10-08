# Validation

Version 0.1.0 passes the applicable offline checks below. Nothing has been deployed to or tested against live tenants, accounts, organisations or SecOps instances. Thresholds need tuning against representative data.

## Checks

| Platform | Offline checks | Limits |
|---|---|---|
| Microsoft | 32 KQL items parsed and semantically bound against bundled table schemas; 4 negative controls; JSON and CSV parse; 3 Bicep builds; ARM decompile | Dynamic JSON keys, live values, permissions, Logic Apps workflow semantics and workbook rendering are not validated. Bicep reports non-fatal warnings about template style, resource types and hard-coded endpoints. |
| AWS | 13 SQL files parsed with sqlglot and field checks; 7 Logs Insights queries plus dashboard queries linted; 6 EventBridge patterns checked against 20 fixtures; 8 Lambda unit tests; botocore API checks; ASL validation; CloudFormation rebuild comparison and cfn-lint; Terraform validate and format | Logs Insights lint is not an AWS parser. EventBridge fixtures do not prove live array matching. API models do not establish permissions or runtime behaviour. |
| Google | 14 YARA-L rules structurally linted with UDM field and enum checks; 21 BigQuery SQL files parsed with source-field checks and detection wrappers; Workflows structure; Python compile; JSON parse; Terraform validate and format | YARA-L has not been compiled in SecOps. SQL has not had a BigQuery dry run. Cloud Run, IAP, Workspace delegation and Workflows execution remain untested. |
| Repository | All JSON parses; 45 mapping rows and generated Markdown agree; local Markdown links resolve; text hygiene checks | These checks do not determine detection effectiveness or framework compliance. |

The suite must reject its deliberately invalid fixtures. Messages containing `FAIL` for these fixtures are expected and followed by a negative-control success result. Any unexpected validator failure makes the overall run fail.

## Run locally

Use Python 3.12, Node.js 22, Terraform 1.15.8 and Bicep 0.48.1. Install Terraform and Bicep from their official distributions and put them on `PATH`. Provider versions and checksums for Linux amd64 and Mac arm64 are committed in the platform lock files.

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-validation.txt
npm ci --ignore-scripts
bash tools/validate_all.sh
```

The root runner calls each platform's existing `tools/validate_all.sh`. It writes logs under `artifacts/`, which is ignored by Git. It does not need cloud credentials. Dependency installation and `terraform init -backend=false` download packages but do not deploy resources. Optional documentation URL checks are excluded from CI; run with `CHECK_URLS=1` to include the AWS and Google link checkers.

CI uses the same root runner, pinned GitHub Actions and tool versions. Its validation logs are uploaded as an Actions artefact. The source archives' historical validation logs are excluded; use the logs for the current commit.

## Placeholders and release checks

The all-zero account number and UUID are synthetic placeholders. Replace them before deployment where the template requires an identifier. Angle-bracket email placeholders are instructions to supply your own values, not working addresses. Synthetic event fixtures use reserved documentation IP ranges. Workbook item UUIDs are generated layout identifiers, not tenant IDs.

Before a release, scan the staged tree with a secret scanner and an explicit list of excluded internal terms supplied through `GUARD_PATTERN`. Do not commit the private exclusion list or raw source planning material. Only the security contact belongs in repository prose. Provider source endpoints, public documentation links, AI service domains and parameterised cloud API URLs are expected.

## Live validation still required

Test log ingestion and field values, then replay both positive and benign examples. Measure query cost, volume and false positives before selecting thresholds. Test playbook permissions, approval identity, rejection, timeouts, containment and recovery in a lab. Confirm evidence exports and dashboards with real schemas.

Platform READMEs list remaining assumptions and design-only components. Preserve these limits when sharing results. Register status and framework mappings support an assessment; they are not an assessment outcome.
