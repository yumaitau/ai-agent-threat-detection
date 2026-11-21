# PB5 ISM Evidence Export

**Runs:** monthly, on the 1st at 07:00 AEST, plus manual runs before an assessment.
**ARM skeleton:** `../deploy/playbook-PB5-ism-evidence-export.json`.
**Purpose:** give assessors a dated, self-contained evidence pack from the customer's own Sentinel workspace, with no other tool involved.

## Output

Each run writes one folder: `https://<account>.blob.core.windows.net/<container>/<yyyy-MM-dd>/`.

| File | Source function | Content |
|---|---|---|
| `agent-register.csv` | `YumaEvidenceRegisterCsv()` | Every active agent and AI app with ISM-2135 fields, decision, review dates and gap flags |
| `ism-controls.csv` | `YumaEvidenceControlsCsv()` | ISM-2133 to 2140 and ISM-2156 to 2159: control text, status, metric, 30-day alert count, evidence method |
| `summary.md` | `YumaEvidenceMarkdown()` | One-page summary for the assessor or the board |
| `manifest.json` | Logic App | Generation time, workspace ID, Logic App run ID, file list |

## Flow

1. **Set the run folder** to `yyyy-MM-dd`.
2. **Call the three evidence functions** in parallel through the Logs query API.
   - POST `https://api.loganalytics.azure.com/v1/workspaces/{WorkspaceId}/query`.
   - Authenticate with a managed identity token for `https://api.loganalytics.io`.
   - No timespan is sent, so the functions' own lookbacks apply.
   - Each function returns a single cell, which keeps the Logic App simple.
   - https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format
3. **PUT each file to Blob storage** with these headers: `x-ms-blob-type: BlockBlob`, `x-ms-version`, `x-ms-date`.
   - Authenticate with a managed identity token for `https://storage.azure.com/`.
   - https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob
4. **Write `manifest.json` last.**

## Setup

- **Logic App managed identity roles:**
  - Log Analytics Reader on the workspace
  - Storage Blob Data Contributor on the container
- **Evidence integrity:** turn on a time-based immutability policy, or at least versioning, on the container so exported evidence can't be altered. https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview
- **Assessor access:** give assessors read access to the container, or a time-limited SAS that the customer issues.

## SharePoint alternative

Use this when the customer's assessors work in Microsoft 365. Replace the three Blob PUTs with the SharePoint connector's "Create file" action, writing to a document library folder named for the run date (https://learn.microsoft.com/en-us/connectors/sharepointonline/). That connector needs a delegated connection, meaning a service account, rather than the managed identity.

## Unvalidated

- Nothing has been deployed.
- The response path `tables[0].rows[0][0]` follows the documented Logs query API response format but hasn't been run.
- Very large registers could exceed query result limits. If so, split the CSV by Source.
- Output order in `summary.md` relies on `serialize` plus `make_list`.
