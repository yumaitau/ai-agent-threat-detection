# Repository layout

Each platform keeps its original relative paths so its generators, templates and validators still work from that platform directory.

| Folder | Contents |
|---|---|
| `microsoft/detections` | KQL rules and hunts |
| `microsoft/functions` | Register, ISM status and evidence functions, plus the inventory sync query |
| `microsoft/playbooks` | Five Logic App playbook guides |
| `microsoft/deploy` | ARM, Bicep, register schemas, watchlists and workbook |
| `aws/detections` | SQL, Logs Insights, EventBridge patterns and synthetic fixtures |
| `aws/playbooks` | Five guides, Step Functions ASL and Lambda functions under `lambda/` |
| `aws/register` | DynamoDB schema, Athena views, control map and dashboard |
| `aws/deploy` | CloudFormation and Terraform |
| `google/detections` | YARA-L, BigQuery queries and specifications |
| `google/functions` | Cloud Run approval, OAuth revocation and IP response functions |
| `google/workflows` | Workflows definitions used by Terraform |
| `google/playbooks` | Five playbook guides |
| `google/register` | BigQuery schemas, views and control map |
| `google/dashboard` | Dashboard outlines |
| `google/deploy` | Terraform |
| `docs` | Shared setup, validation and layout notes |
| `mappings` | Combined source-preserving detection mapping |
| `tools` | Shared validation runner and mapping checks |

Each platform also has `tools/` with its original validators and negative fixtures. Generated build output and local configuration are ignored by Git. The source planning material and historical validation logs are excluded.

See [the complete tracked file tree](file-tree.txt).
