# PB3 AI-speed exploitation: enrich, then block in a WAF IP set

**Trigger:** EventBridge Scheduler every 15 minutes. `pb3_waf_block.py` runs the A14 Logs Insights query over the
WAF log group (`StartQuery` / `GetQueryResults`).

**Enrichment** (free tiers, best effort, each call times out after 8 s):
- **GreyNoise Community** `GET https://api.greynoise.io/v3/community/{ip}`. Works without a key. RIOT (known business
  service) lowers the score; `classification: malicious` raises it.
- **AbuseIPDB** `GET https://api.abuseipdb.com/api/v2/check`. `Key` header; optional. Adds `abuseConfidenceScore`/4.
- **ThreatFox** `POST https://threatfox-api.abuse.ch/api/v1/`. `Auth-Key` header; optional. Any hit adds 30.
- Keys are held in one Secrets Manager secret.

**Decision:**
- Allow-listed CIDRs are skipped.
- Score at or above `BLOCK_SCORE` (60) proposes a block.
- With `AUTO_BLOCK=false` (the default) nothing is changed. Proposals are returned and logged.
- With `AUTO_BLOCK=true` (the customer pre-approves), the IP set is updated using WAF's optimistic locking: `GetIPSet` returns a
  `LockToken` and `UpdateIPSet` must send it back, with a retry on `WAFOptimisticLockException`
  (https://docs.aws.amazon.com/waf/latest/APIReference/API_UpdateIPSet.html).
- Each block is written to the register table (`pk = WAFBLOCK`) with `expires_at`. Expired entries are removed on the next run.

**Where the block applies:** the Terraform creates the IP set and a one-rule rule group. The customer adds that rule
group to their web ACL, ahead of other rules. Use CLOUDFRONT scope in us-east-1 for CloudFront distributions.

**Bot Control complement:** Bot Control's `CategoryAI` rule already blocks AI bots by default, and verified Web Bot Auth
bots are allowed (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html). PB3 is for
behaviour (many rules and paths per IP), which labels don't catch.

**ISM:** 2116. **Deployed by:** `deploy/terraform/pb3-waf-block/` (skeleton).
