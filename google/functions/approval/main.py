"""PB1/PB2 human approval service (Cloud Run function, Python 3.12, functions-framework).

Status: SKELETON - compiles offline; not deployed.

Put this behind Identity-Aware Proxy and grant "IAP-secured Web App User" ONLY to the approver group.
IAP adds a signed header X-Goog-IAP-JWT-Assertion; we verify it and take the approver's email from it, so the
register records WHO approved (ISM-2113). https://docs.cloud.google.com/iap/docs/signed-headers-howto

The decision is POSTed to the Workflows callback URL with this service's own OAuth token (needs workflows.callbacks.send,
e.g. roles/workflows.invoker). https://docs.cloud.google.com/workflows/docs/creating-callback-endpoints
"""
import html
import os
import urllib.parse

import functions_framework
import google.auth
import google.auth.transport.requests
import requests
from google.auth.transport import requests as ga_requests
from google.oauth2 import id_token

IAP_AUDIENCE = os.environ.get("IAP_AUDIENCE", "")  # /projects/NUMBER/global/backendServices/ID or /projects/NUMBER/locations/REGION/services/NAME
CALLBACK_PREFIX = "https://workflowexecutions.googleapis.com/"
IAP_CERTS = "https://www.gstatic.com/iap/verify/public_key"


def _approver(request) -> str:
    assertion = request.headers.get("X-Goog-IAP-JWT-Assertion", "")
    if not assertion or not IAP_AUDIENCE:
        raise PermissionError("missing IAP assertion or IAP_AUDIENCE")
    claims = id_token.verify_token(assertion, ga_requests.Request(), audience=IAP_AUDIENCE, certs_url=IAP_CERTS)
    return claims["email"]


def _form(exec_id: str, cb: str, who: str) -> str:
    e = html.escape
    return f"""<!doctype html><title>AI containment approval</title>
<h2>Approval request</h2><p>Workflow execution: <code>{e(exec_id)}</code></p><p>You are signed in as {e(who)}.</p>
<form method="post"><input type="hidden" name="cb" value="{e(cb)}"><input type="hidden" name="exec" value="{e(exec_id)}">
<p><label>Reason <input name="reason" size="60" required></label></p>
<button name="decision" value="Approve">Approve action</button> <button name="decision" value="Reject">Reject</button></form>"""


@functions_framework.http
def approve(request):
    try:
        who = _approver(request)
    except Exception as exc:  # noqa: BLE001
        return (f"forbidden: {exc}", 403)

    if request.method == "GET":
        cb = request.args.get("cb", "")
        if not cb.startswith(CALLBACK_PREFIX):
            return ("bad callback", 400)
        return _form(request.args.get("exec", ""), cb, who)

    if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
        return ("cross-site post refused", 403)
    cb = request.form.get("cb", "")
    decision = request.form.get("decision", "")
    reason = request.form.get("reason", "")[:500]
    if not cb.startswith(CALLBACK_PREFIX) or decision not in ("Approve", "Reject"):
        return ("bad request", 400)

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(google.auth.transport.requests.Request())
    r = requests.post(cb, json={"decision": decision, "approver": who, "reason": reason},
                      headers={"Authorization": f"Bearer {creds.token}"}, timeout=20)
    if r.status_code >= 300:
        return (f"callback failed ({r.status_code}); the request may have timed out", 502)
    return f"Recorded: {html.escape(decision)} by {html.escape(who)}. You can close this tab."
