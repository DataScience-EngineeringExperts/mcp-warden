"""Check release.yml's production OIDC exchange without uploading or logging tokens."""

from __future__ import annotations

import base64
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPOSITORY = "DataScience-EngineeringExperts/mcp-warden"
OWNER_ID = "115239380"
WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"
MAX_RESPONSE = 65_536
ERROR_CODES = frozenset({
    "invalid-publisher", "invalid-pending-publisher", "invalid-token", "invalid-payload",
    "invalid-reuse-token", "rate-limit-exceeded",
})


class ProbeError(Exception):
    """Messages are fixed locally; never include credentials or server descriptions."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProbeError("Redirect refused; credentials were not forwarded.")


def _json_response(stream):
    raw = stream.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ProbeError("Response exceeded the verification size limit.")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ProbeError("Response was not valid JSON.") from None
    if not isinstance(result, dict):
        raise ProbeError("Response was not a JSON object.")
    return result


def fetch_json(request: Request, stage: str):
    try:
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            return _json_response(response)
    except HTTPError as exc:
        # PyPI can include arbitrary descriptions; only print known error codes.
        code = "unrecognized-error"
        try:
            body = _json_response(exc)
            errors = body.get("errors")
            if isinstance(errors, list):
                for item in errors:
                    if isinstance(item, dict) and item.get("code") in ERROR_CODES:
                        code = item["code"]
                        break
        except (ProbeError, TypeError):
            pass
        raise ProbeError(f"{stage}: HTTP {exc.code}, {code}.") from None
    except (URLError, TimeoutError):
        raise ProbeError(f"{stage}: HTTPS connection failed.") from None


def github_request_url(raw: str) -> str:
    parsed = urlsplit(raw)
    if (parsed.scheme != "https" or not parsed.hostname
            or not parsed.hostname.endswith(".actions.githubusercontent.com")
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.fragment):
        raise ProbeError("GitHub OIDC request endpoint was not an approved HTTPS host.")
    query = [(k, v) for k, v in parse_qsl(parsed.query) if k != "audience"]
    return urlunsplit(parsed._replace(query=urlencode([*query, ("audience", "pypi")])))


def check_claims(token: str, ref: str) -> None:
    # Decoding is a preflight check, NOT signature verification. PyPI verifies the JWT.
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError
        payload = parts[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if not isinstance(claims, dict):
            raise ValueError
    except (ValueError, UnicodeError):
        raise ProbeError("GitHub did not return a parseable OIDC identity.") from None
    expected = {
        "iss": "https://token.actions.githubusercontent.com", "aud": "pypi",
        "repository": REPOSITORY, "repository_owner": REPOSITORY.split("/")[0],
        "repository_owner_id": OWNER_ID, "workflow_ref": f"{WORKFLOW}@{ref}",
        "sub": f"repo:{REPOSITORY}:ref:{ref}",
    }
    if any(claims.get(key) != value for key, value in expected.items()):
        raise ProbeError("GitHub OIDC claims did not match this repository's release workflow.")
    if "environment" in claims or claims.get("job_workflow_ref", expected["workflow_ref"]) != expected["workflow_ref"]:
        raise ProbeError("Unexpected environment or reusable workflow identity.")


def verify() -> None:
    required = ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GITHUB_REF")
    if any(not os.environ.get(key) for key in required):
        raise ProbeError("Run the verify-pypi job in GitHub Actions with id-token: write.")
    ref = os.environ["GITHUB_REF"]
    if not ref.startswith(("refs/heads/", "refs/tags/")):
        raise ProbeError("Verification requires a branch or tag workflow ref.")
    url = github_request_url(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    github = fetch_json(Request(url, headers={
        "Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
    }), "GitHub identity request")
    token = github.get("value")
    if not isinstance(token, str) or not token:
        raise ProbeError("GitHub did not return an OIDC identity.")
    check_claims(token, ref)
    result = fetch_json(Request(
        "https://pypi.org/_/oidc/mint-token",
        data=json.dumps({"token": token}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    ), "PyPI exchange")
    credential, expiry = result.get("token"), result.get("expires")
    now = time.time()
    if (result.get("success") is not True or not isinstance(credential, str)
            or not credential.startswith("pypi-") or type(expiry) is not int
            or not now < expiry <= now + 930):
        raise ProbeError("PyPI did not return a successful short-lived credential exchange.")
    # The upload credential exists only in memory and is never used or stored.
    print("PyPI accepted this release workflow's OIDC identity.")
    print("No packages uploaded. Project upload authorization remains untested.")


def main() -> int:
    try:
        verify()
    except ProbeError as exc:
        print(f"::error::{exc}")
        return 1
    except Exception:
        # Do not render unexpected exceptions: they may include headers or tokens.
        print("::error::Unexpected verification failure; response details withheld.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
