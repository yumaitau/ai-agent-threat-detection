# PB2: Log new AI app consents and new agents to the register, then get a decision

**Fires on:**
- G01: AI OAuth app consent
- G09: Agent Runtime or Gemini Enterprise agent created or changed outside the register
- G02: domain-wide delegation granted
- Six-monthly: the review list

**Controls:** ISM-2134, ISM-2135, ISM-2137, ISM-2138, ISM-2113

## Flow

1. **Capture.**
   - The scheduled query `register/sql/pb2_pending_decisions.sql` runs hourly from Terraform.
   - It turns each new G01 or G09 entity with no decision yet into a `ConsentDecision` row with decision `Pending`.
   - The app or agent shows in `v_register_current` as `undecided = TRUE`.
2. **Ask.** The owner, or an administrator for user consents (ISM-2137), is asked to choose one of three:
   - **Approve**: a `ConsentDecision` with Approved, then add the client to `approved_apps` and the `%yuma_ai_approved_oauth_clients` list. Fill in owner, purpose and data sources (ISM-2135).
   - **Revoke**: hand off to PB1 with `action=revoke_oauth`.
   - **Investigate**: open a case.
3. **Review.**
   - Every month, run `register/sql/pb2_reviews_due.sql`. It lists apps and agents never reviewed or older than about six months, plus 30-day usage.
   - Apps unused for 30 days are flagged as revoke candidates.
   - Each completed review writes a `ReviewCompleted` row (ISM-2138).
4. **Prevent.** The real fix for ISM-2137 is in Workspace: Admin console > Security > API controls. Restrict unconfigured third-party apps so users can't consent. G01 then becomes a "should be zero" signal.

## A. SecOps SOAR

- **Case:** a G01 or G09 rule. **Enrich:** BigQuery *Run SQL Query* on the register.
- **Ask the owner:** Slack *Ask Question* or Email V2 *Send Email* / *Wait for Email from User*.
- **Write the decision:** BigQuery *Run SQL Query* with an INSERT.
- On revoke, call PB1. Use Siemplify *Add to Custom List* to keep the approved list in SOAR.

## B. No-SecOps

- The pending-decision scheduled query ships.
- The notifier reuses the PB1 approval service: run `pb1-containment` with `action=revoke_oauth`, and the approve or reject decision is recorded either way.
- Approval writes to `approved_apps` by hand or with a small INSERT. A dedicated PB2 approval workflow is a 4-week-plan item.

## Permissions

The detections service account has dataEditor on the register dataset. Owners need no Google Cloud access: they act through the approval link.

## Unvalidated

- The export literals `record_type='token'` and `event_name='authorize'`.
- The G09 method names.
- Gemini Enterprise agents have no verified audit method name, so they are matched loosely.
