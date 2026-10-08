# PB5: Monthly ISM evidence export to Cloud Storage

**Fires on:** Cloud Scheduler at 06:00 on the 1st of each month (Australia/Sydney).

**Controls:** evidence for ISM-2133 to 2140 and ISM-2156 to 2159

## Flow (`workflows/pb5-evidence-export.yaml`)

1. Work out the previous calendar month in Australia/Sydney.
2. Run BigQuery `EXPORT DATA` (CSV, header, `overwrite=false`) to `gs://<evidence bucket>/ism-evidence/YYYY-MM/`. Four exports:
   - `register_current-*.csv`: the register as it stands, with gap flags
   - `ism_control_status-*.csv`: one row per control, with status and an evidence note
   - `detection_hits-*.csv`: the month's hits
   - `decisions-*.csv`: consent, containment, review and retirement decisions, with who decided (ISM-2113)
3. Write `summary.md` from `v_evidence_summary_md`.
4. Write `manifest.json`, recording the period, generation time, workflow execution ID, files and controls.
5. The bucket has versioning, public access prevention and a 7-year retention policy. Lock the policy (Bucket Lock) once the customer agrees. Locking is irreversible.

**Status semantics:** Met / Gap / Partial / Attestation required. These are automated signals, not an assessor's opinion. ISM-2140 (device code flow) always needs the control owner's attestation, because no Google telemetry for it was found.

## A. SecOps

There's no native scheduled export of a case or rule set to GCS. Run the same workflow, or a SOAR job doing BigQuery *Run SQL Query* then Cloud Storage *Upload an Object To a Bucket*.

## Permissions

| Principal | Role | Risk |
|---|---|---|
| yuma-gai-pb5 | BigQuery dataViewer (register), jobUser | low |
| yuma-gai-pb5 | storage.objectCreator (evidence bucket only) | low. It can't overwrite or delete |

## Unvalidated

- Not executed.
- `EXPORT DATA` through the `jobs.insert` connector, and media upload through `googleapis.storage.v1.objects.insert`, follow the Google reference pages but are untested.
