"""Generate ``tests/fixtures/corpus`` — a local corpus with FAKE sidecars.

Sidecars here are NOT sigstore bundles: they are ``{"over": <statement>}`` so the
unit tests can verify them through a monkeypatched boundary without network.
Real ``verify_statement`` rejects them (fail closed), which is the point.

Run from the repo root with the venv on PATH after pinning the mutated fixture:
``mcp-warden pin python tests/fixtures/mutated_server.py --lock /tmp/mutated.warden.lock``.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, "src")

from mcp_warden.lockfile import read_lock  # noqa: E402
from mcp_warden.signing import build_statement  # noqa: E402

ROOT = Path("tests/fixtures/corpus")
CLEAN = Path("tests/fixtures/clean.warden.lock")
MUTATED = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/mutated.warden.lock")
ISSUER = "https://token.actions.githubusercontent.com"


def attester(name: str) -> dict[str, str]:
    return {
        "id": name,
        "certificate_identity": f"https://github.com/example/attester-{name}/.github/workflows/attest.yml@refs/heads/main",
        "oidc_issuer": ISSUER,
    }


def entry(segment: str, who: str, lock_src: Path, sidecar: str = "ok") -> None:
    d = ROOT / "locks" / "npm" / segment / "1.0.0"
    d.mkdir(parents=True, exist_ok=True)
    lock_path = d / f"{who}.lock"
    shutil.copy(lock_src, lock_path)
    digest = read_lock(lock_path).overall_digest
    sc = d / f"{who}.lock.sigstore"
    if sidecar == "ok":
        doc = {"_fake": "mcp-warden TEST sidecar, not a sigstore bundle", "over": build_statement(digest).decode()}
        sc.write_text(json.dumps(doc) + "\n")
    elif sidecar == "corrupt":
        sc.write_text("this is not json {{{\n")
    elif sidecar == "wrong":
        doc = {"_fake": "signed over a DIFFERENT digest", "over": build_statement("sha256:" + "0" * 64).decode()}
        sc.write_text(json.dumps(doc) + "\n")
    # sidecar == "missing": write nothing


def main() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    assert read_lock(CLEAN).overall_digest != read_lock(MUTATED).overall_digest
    (ROOT / "attesters.json").write_text(json.dumps([attester("alice"), attester("bob")], indent=2) + "\n")

    entry("@example__clean", "alice", CLEAN)  # MATCH for the clean fixture
    entry("@example__clean", "bob", CLEAN)
    entry("@example__other", "alice", MUTATED)  # MISMATCH when the clean fixture is observed
    entry("@example__other", "bob", MUTATED)
    entry("@example__split", "alice", CLEAN)  # SPLIT: attesters disagree
    entry("@example__split", "bob", MUTATED)
    entry("@example__nosig", "alice", CLEAN, sidecar="missing")  # UNVERIFIABLE
    entry("@example__corrupt", "alice", CLEAN, sidecar="corrupt")  # UNVERIFIABLE
    entry("@example__wrongsig", "alice", CLEAN, sidecar="wrong")  # UNVERIFIABLE (verify fails)
    stranger = ROOT / "locks" / "npm" / "@example__stranger" / "1.0.0"  # undeclared attester
    stranger.mkdir(parents=True)
    shutil.copy(CLEAN, stranger / "mallory.lock")
    (stranger / "mallory.lock.sigstore").write_text("{}\n")
    (ROOT / "README.md").write_text(
        "# Fixture corpus\n\nSidecars are FAKE (`{\"over\": …}`), verified only through the "
        "monkeypatched boundary in `tests/test_corpus.py`. Real sigstore verification rejects "
        "them — by design. Regenerate with `tests/fixtures/gen_corpus.py`.\n"
    )
    for p in sorted(ROOT.rglob("*")):
        if p.is_file():
            print(p.relative_to(ROOT))


if __name__ == "__main__":
    main()
