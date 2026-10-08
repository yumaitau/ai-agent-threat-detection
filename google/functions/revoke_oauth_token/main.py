"""PB1 action: revoke a third-party OAuth app's tokens for listed Workspace users (Directory API tokens.delete).

Status: SKELETON - compiles offline; not deployed. Called only by the PB1 workflow AFTER human approval.

API: DELETE https://admin.googleapis.com/admin/directory/v1/users/{userKey}/tokens/{clientId}
     scope https://www.googleapis.com/auth/admin.directory.user.security
     https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/delete

Auth (UNVALIDATED in a live tenant): keyless domain-wide delegation. The function's service account signs a JWT through the
IAM Credentials signJwt API (it needs roles/iam.serviceAccountTokenCreator on itself) with sub = a dedicated admin user that
holds only a custom admin role with "User security management". No key file exists.
This service account is itself a high-privilege agent: record it in the register; G02 will (correctly) flag its delegation.
"""
import os
import re

import functions_framework
import google.auth
from google.auth import iam
from google.auth.transport import requests as ga_requests
from google.oauth2 import service_account

SCOPE = "https://www.googleapis.com/auth/admin.directory.user.security"
TOKEN_URI = "https://oauth2.googleapis.com/token"
SA_EMAIL = os.environ["FUNCTION_SA_EMAIL"]
ADMIN_SUBJECT = os.environ["ADMIN_SUBJECT"]
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{5,200}$")
EMAIL_RE = re.compile(r"^[^@\s/]+@[^@\s/]+$")


def _session():
    source, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    signer = iam.Signer(ga_requests.Request(), source, SA_EMAIL)
    creds = service_account.Credentials(signer, SA_EMAIL, TOKEN_URI, scopes=[SCOPE], subject=ADMIN_SUBJECT)
    return ga_requests.AuthorizedSession(creds)


@functions_framework.http
def revoke(request):
    body = request.get_json(silent=True) or {}
    client_id = str(body.get("client_id", ""))
    users = [u for u in body.get("user_emails", []) if isinstance(u, str) and EMAIL_RE.match(u)]
    if not CLIENT_ID_RE.match(client_id) or not users or len(users) > 500:
        return ({"error": "need client_id and 1-500 user_emails"}, 400)
    s = _session()
    results = {}
    for u in users:
        r = s.delete(f"https://admin.googleapis.com/admin/directory/v1/users/{u}/tokens/{client_id}", timeout=20)
        results[u] = r.status_code  # 204 revoked, 404 no token for that user
    return {"client_id": client_id, "results": results}
