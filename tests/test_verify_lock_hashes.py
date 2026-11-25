"""The lock check must cover distributions pip skips on the CI runner."""

import io
import json
from urllib.error import URLError

import pytest
from scripts import verify_lock_hashes as verifier

LINUX = "a" * 64
WINDOWS = "b" * 64
OTHER_RELEASE = "c" * 64


def lock_entry(name, version, hashes, marker=""):
    lines = [f"{name}=={version}{marker}", *(f"    --hash=sha256:{h}" for h in hashes)]
    return " \\\n".join(lines) + "\n"


def mock_pypi(monkeypatch, releases):
    requests = []

    class Response(io.BytesIO):
        def geturl(self):
            return requests[-1]

    def open_url(url, *, timeout):
        requests.append(url)
        assert timeout > 0
        return Response(json.dumps({"urls": releases[url]}).encode())

    monkeypatch.setattr(verifier, "urlopen", open_url)
    return requests


@pytest.mark.parametrize("tampered_lock", [None, "requirements-dev.lock", "action/requirements.lock"])
def test_all_release_digests_are_checked(tmp_path, monkeypatch, capsys, tampered_lock):
    dev = tmp_path / "requirements-dev.lock"
    action = tmp_path / "action" / "requirements.lock"
    action.parent.mkdir()
    for lock in [dev, action]:
        windows_hash = OTHER_RELEASE if lock.relative_to(tmp_path).as_posix() == tampered_lock else WINDOWS
        lock.write_text(
            "# uv lock fixture\n"
            + lock_entry("sample_pkg", "1.2", [LINUX, windows_hash])
            + "    # via a dependency\n"
            + lock_entry("sample_pkg", "1.3", [OTHER_RELEASE], " ; sys_platform == 'win32'"),
            encoding="utf-8",
        )

    release = "https://pypi.org/pypi/sample-pkg"
    requests = mock_pypi(
        monkeypatch,
        {
            f"{release}/1.2/json": [
                {"filename": "sample_pkg-1.2-cp311-manylinux_x86_64.whl", "digests": {"sha256": LINUX}},
                {"filename": "sample_pkg-1.2-cp311-win_amd64.whl", "digests": {"sha256": WINDOWS}},
            ],
            f"{release}/1.3/json": [
                {"filename": "sample_pkg-1.3-cp311-win_amd64.whl", "digests": {"sha256": OTHER_RELEASE}}
            ],
        },
    )

    result = verifier.main([str(dev), str(action)])
    output = capsys.readouterr()
    if tampered_lock is None:
        assert result == 0
        assert requests == [f"{release}/1.2/json", f"{release}/1.3/json"]
        assert output.out.count("verified 3 SHA-256 hashes across 2 pins") == 2
    else:
        assert result == 1
        assert f"{tampered_lock}:2: sample-pkg==1.2" in output.err
        assert OTHER_RELEASE in output.err


@pytest.mark.parametrize(
    "contents",
    [
        "# empty lock\n",
        "sample==1.2\n",
        "sample==1.2 \\\n    --hash=sha256:too-short\n",
        "sample==1.2 \\\n    --hash=sha256:" + LINUX + " \\\n",
        "sample==1.2 --hash=sha256:" + LINUX + " --index-url=https://example.test\n",
    ],
)
def test_malformed_lock_fails_closed(tmp_path, monkeypatch, contents):
    lock = tmp_path / "example.lock"
    lock.write_text(contents, encoding="utf-8")
    requests = mock_pypi(monkeypatch, {})

    assert verifier.main([str(lock)]) == 1
    assert requests == []


@pytest.mark.parametrize("files", [None, [], [{"digests": {}}], [{"digests": {"sha256": "bad"}}]])
def test_bad_metadata_fails_closed(tmp_path, monkeypatch, capsys, files):
    lock = tmp_path / "example.lock"
    lock.write_text(lock_entry("sample", "1.2", [LINUX]), encoding="utf-8")
    mock_pypi(monkeypatch, {"https://pypi.org/pypi/sample/1.2/json": files})

    assert verifier.main([str(lock)]) == 1
    assert "invalid PyPI release metadata" in capsys.readouterr().err


def test_network_error_fails_closed(tmp_path, monkeypatch, capsys):
    lock = tmp_path / "example.lock"
    lock.write_text(lock_entry("sample", "1.2", [LINUX]), encoding="utf-8")

    def unavailable(*args, **kwargs):
        raise URLError("unavailable")

    monkeypatch.setattr(verifier, "urlopen", unavailable)

    assert verifier.main([str(lock)]) == 1
    assert "could not fetch PyPI release metadata" in capsys.readouterr().err
