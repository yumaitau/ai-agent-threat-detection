# PB3: Enrich attacking IPs (GreyNoise, AbuseIPDB, ThreatFox) and block with Cloud Armor

**Fires on:** G13 (AI-speed exploitation burst). G14 can be added as a source, but it is watch-only by default.

**Controls:** ISM-2116 (CTI supports detection and response); E8 patch applications (buys time to patch)

## Flow (`functions/ti_enrich_block`, run by Cloud Scheduler every 10 minutes; cleanup runs hourly)

1. Read the G13 hits from `detection_hits` for the last 15 minutes.
2. Look up each IP in three sources:
   - **GreyNoise Community**: `GET https://api.greynoise.io/v3/community/{ip}`, fields `noise`, `riot`, `classification`
   - **AbuseIPDB**: `GET /api/v2/check`, field `data.abuseConfidenceScore`
   - **ThreatFox**: `POST /api/v1/` with `{"query":"search_ioc","search_term":ip}`, header `Auth-Key`
3. Decide a verdict:
   - **Never block:** private IPs, allowlisted CIDRs, and GreyNoise `riot` or `benign`.
   - **Block:** AbuseIPDB score ≥ 75, or a ThreatFox hit, or GreyNoise `malicious`.
   - **Otherwise watch:** WAF behaviour alone doesn't trigger an automatic block.
4. **Block.**
   - Call Cloud Armor `securityPolicies.addRule` with `versionedExpr: SRC_IPS_V1`, up to **10 IPs per rule** (the Cloud Armor limit), and `action: deny(403)`.
   - Priority comes from a reserved band (1000–1999). The description is `yuma-gai-pb3 expires=<UTC time>`, 24 hours ahead.
5. **Cleanup.** `removeRule` deletes PB3 rules past their expiry.
6. Every decision is written as a structured log line, which is the evidence trail.

**Why there's no human click:** a WAF deny on an IP is low impact, time-limited and reversible. That makes it different from ISM-2113's "sensitive or high-impact" actions. If the customer wants approval anyway, route the block through the PB1 callback pattern.

## A. SecOps SOAR

- **Enrich:** use the marketplace integrations for GreyNoise, AbuseIPDB and abuse.ch ThreatFox if the tenant has them. Otherwise use HTTP v2.
- **Block:** Google Cloud Armor *Add a Rule to a Security Policy* (listed in Google's SOAR catalogue).
- **Track:** Siemplify *Add to Custom List* records the expiry. A scheduled job removes expired rules.

## Permissions

| Principal | Role | Risk |
|---|---|---|
| yuma-gai-fn-ti | roles/compute.securityAdmin (project) | HIGH: can change WAF policy. It is limited to tagged rules in a priority band by code, not by IAM |
| yuma-gai-fn-ti | BigQuery dataViewer (register) + jobUser; secretAccessor on 3 TI keys | low |

## Unvalidated

- Nothing has been executed against the live TI APIs.
- The free-tier quotas for AbuseIPDB (1,000 checks a day) and GreyNoise Community are tight for busy sites. Cache verdicts.
- The ThreatFox Auth-Key requirement and response shape are taken from its API page.
