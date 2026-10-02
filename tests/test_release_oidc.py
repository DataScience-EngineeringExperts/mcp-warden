"""Release authentication probe: fail closed without leaking or uploading credentials."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
import yaml

ROOT = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location("release_probe", ROOT / "scripts/verify_pypi_oidc.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
SENTINEL = "DO_NOT_LOG_TEST_CREDENTIAL"


def jwt(**changes):
    claims = {
        "iss": "https://token.actions.githubusercontent.com", "aud": "pypi",
        "repository": probe.REPOSITORY, "repository_owner": "DataScience-EngineeringExperts",
        "repository_owner_id": probe.OWNER_ID,
        "workflow_ref": f"{probe.WORKFLOW}@refs/heads/main",
        "sub": f"repo:{probe.REPOSITORY}:ref:refs/heads/main",
    } | changes
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{body}.{SENTINEL}"


@pytest.fixture
def environment(monkeypatch):
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/token?x=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", SENTINEL)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setattr(probe.time, "time", lambda: 1000)


def responses(monkeypatch, token=None, result=None):
    requests = []

    def fetch(request, stage):
        requests.append(request)
        if len(requests) == 1:
            return {"value": jwt() if token is None else token}
        return {"success": True, "token": "pypi-" + SENTINEL, "expires": 1900} if result is None else result

    monkeypatch.setattr(probe, "fetch_json", fetch)
    return requests


def test_success_exchanges_only_and_never_logs_credentials(environment, monkeypatch, capsys):
    requests = responses(monkeypatch)
    assert probe.main() == 0
    assert len(requests) == 2
    assert requests[0].get_header("Authorization") == "Bearer " + SENTINEL
    assert "audience=pypi" in requests[0].full_url
    assert requests[1].full_url == "https://pypi.org/_/oidc/mint-token"
    assert json.loads(requests[1].data) == {"token": jwt()}
    output = capsys.readouterr().out
    assert SENTINEL not in output
    assert "No packages uploaded" in output
    assert "authorization remains untested" in output


@pytest.mark.parametrize("claims", [
    {"iss": "https://attacker.invalid"}, {"aud": "sigstore"},
    {"repository": "attacker/mcp-warden"}, {"repository_owner": "attacker"},
    {"repository_owner_id": "different-owner"},
    {"workflow_ref": f"{probe.REPOSITORY}/.github/workflows/other.yml@refs/heads/main"},
    {"workflow_ref": f"{probe.WORKFLOW}@refs/heads/unreviewed"},
    {"sub": f"repo:{probe.REPOSITORY}:environment:pypi"},
    {"environment": "pypi"}, {"environment": ""},
    {"job_workflow_ref": "attacker/reusable@refs/heads/main"},
])
def test_mismatched_identity_never_reaches_pypi(environment, monkeypatch, capsys, claims):
    requests = responses(monkeypatch, token=jwt(**claims))
    assert probe.main() == 1
    assert len(requests) == 1
    assert SENTINEL not in capsys.readouterr().out


@pytest.mark.parametrize("url", [
    "http://vstoken.actions.githubusercontent.com/token",
    "https://actions.githubusercontent.com.attacker.invalid/token",
    "https://attacker.invalid/token", "https://user@vstoken.actions.githubusercontent.com/token",
    "https://vstoken.actions.githubusercontent.com:444/token",
    "https://vstoken.actions.githubusercontent.com/token#fragment",
])
def test_untrusted_endpoint_receives_no_request(environment, monkeypatch, url):
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", url)
    requests = responses(monkeypatch)
    assert probe.main() == 1
    assert not requests


def test_redirect_is_refused_before_forwarding():
    with pytest.raises(probe.ProbeError, match="Redirect refused"):
        probe.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://attacker.invalid")


@pytest.mark.parametrize("result", [
    {}, {"success": False, "token": "pypi-" + SENTINEL, "expires": 1900},
    {"success": True, "token": None, "expires": 1900},
    {"success": True, "token": SENTINEL, "expires": 1900},
    {"success": True, "token": "pypi-" + SENTINEL, "expires": True},
    {"success": True, "token": "pypi-" + SENTINEL, "expires": 999},
    {"success": True, "token": "pypi-" + SENTINEL, "expires": 99999},
])
def test_invalid_exchange_cannot_pass(environment, monkeypatch, capsys, result):
    responses(monkeypatch, result=result)
    assert probe.main() == 1
    assert SENTINEL not in capsys.readouterr().out


@pytest.mark.parametrize("token", [SENTINEL, "a.b.c", "a.bnVsbA.c", "a.W10.c"])
def test_malformed_jwt_fails_before_exchange(environment, monkeypatch, capsys, token):
    requests = responses(monkeypatch, token=token)
    assert probe.main() == 1
    assert len(requests) == 1
    assert SENTINEL not in capsys.readouterr().out


@pytest.mark.parametrize("body", [b"not json", b"[]", b"x" * (probe.MAX_RESPONSE + 1)])
def test_malformed_or_oversized_json_is_rejected(body):
    with pytest.raises(probe.ProbeError):
        probe._json_response(io.BytesIO(body))


@pytest.mark.parametrize("code", ["invalid-publisher", SENTINEL, [SENTINEL]])
def test_http_failures_do_not_reflect_server_secrets(environment, monkeypatch, capsys, code):
    body = json.dumps({"errors": [{"code": code, "description": SENTINEL}]}).encode()

    class Opener:
        def open(self, *args, **kwargs):
            raise HTTPError("https://pypi.org", 403, SENTINEL, {}, io.BytesIO(body))

    monkeypatch.setattr(probe, "build_opener", lambda *args: Opener())
    assert probe.main() == 1
    output = capsys.readouterr().out
    assert SENTINEL not in output
    assert "HTTP 403" in output


@pytest.mark.parametrize("error", [URLError(SENTINEL), TimeoutError(SENTINEL), ValueError(SENTINEL)])
def test_unexpected_network_exception_does_not_log_request(environment, monkeypatch, capsys, error):
    def fetch(*args):
        raise error

    monkeypatch.setattr(probe, "fetch_json", fetch)
    assert probe.main() == 1
    assert SENTINEL not in capsys.readouterr().out


def test_missing_actions_permission_is_a_failure(monkeypatch, capsys):
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    assert probe.main() == 1
    assert "id-token: write" in capsys.readouterr().out


def test_manual_verification_cannot_build_upload_sign_or_use_long_lived_credentials():
    workflow = yaml.load((ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader)
    jobs = workflow["jobs"]
    assert "verify-pypi" in workflow["on"]["workflow_dispatch"]["inputs"]["publish-target"]["options"]
    assert "publish-target != 'verify-pypi'" in jobs["build"]["if"]
    assert "publish-target == 'testpypi'" in jobs["pypi-publish"]["if"]
    assert jobs["sign"]["if"] == "github.event_name == 'release'"
    verify = jobs["pypi-verify"]
    assert "publish-target == 'verify-pypi'" in verify["if"]
    assert "needs" not in verify and "environment" not in verify
    assert verify["permissions"] == {"id-token": "write", "contents": "read"}
    assert [s["run"] for s in verify["steps"] if "run" in s] == ["python scripts/verify_pypi_oidc.py"]
    assert "secrets." not in json.dumps(verify)
    assert workflow["permissions"] == {"contents": "read"}
