# Yuma AIA-A15 (spec only, not rule-grade): Identity Center OIDC token issuance for CLI and agent clients

**Why:** ISM-2139 wants consent, token issuance and token use logged; ISM-2140 wants device code flow disabled.
AI coding agents and MCP clients often authenticate to AWS through `aws sso login`, which uses the IAM Identity
Center OIDC API (`RegisterClient`, `StartDeviceAuthorization`, `CreateToken`).

**What AWS logs (verified):** the Identity Center CloudTrail page lists `CreateToken` (event source `sso.amazonaws.com`)
and `CreateTokenWithIAM` (event source `sso-oauth.amazonaws.com`) as the public OIDC operations that emit events.
`RegisterClient` and `StartDeviceAuthorization` are not listed.
https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html

**Hunt (draft):** count `CreateToken` events per Identity Center user and client per day, and flag first-seen
client names. Field names inside `requestParameters` for the grant type and client are **not verified**: capture
a lab event first, then write the rule.

**ISM-2140 evidence:** AWS doesn't document a switch that turns device authorisation off for an Identity Center
instance, so this control is "Attestation required" in PB5 unless the customer shows an equivalent control
(for example, AWS CLI v2 configured for the PKCE authorization code flow). Not verified; treat as an open question.
