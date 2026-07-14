"""Tests for the ``mcp-warden-precommit`` wrapper (issue #22).

Covers the design-v2 contract + the 5 adversarial-review binding fixes:

  1. Graceful server-unavailability: non-strict -> exit 0 + warning; --strict -> 2.
  2. cwd normalization: identical verdict regardless of invocation dir.
  3. Packaging: the ``mcp-warden-precommit`` console entry point exists.
  4. (README — not unit-tested here.)
  5. Lock write-protection: the lock path is never opened for write; the module
     does not import the pin/lock-writer.

These are NOT mocks of the capture path: the wrapper spawns the real clean /
mutated fixture servers over stdio, exactly like the integrity-gate e2e tests.
"""

from __future__ import annotations

import builtins
import inspect
from pathlib import Path

import yaml

from mcp_warden import precommit

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_LOCK = "tests/fixtures/clean.warden.lock"
CLEAN_SERVER = "tests/fixtures/clean_server.py"
MUTATED_SERVER = "tests/fixtures/mutated_server.py"
HOOKS_YAML = REPO_ROOT / ".pre-commit-hooks.yaml"


# --- arg parsing -------------------------------------------------------------


def test_split_argv_separates_server_cmd():
    own, server = precommit._split_argv(["--lock", "warden.lock", "--", "python", "server.py"])
    assert own == ["--lock", "warden.lock"]
    assert server == ["python", "server.py"]


def test_split_argv_no_separator_yields_empty_server_cmd():
    own, server = precommit._split_argv(["--lock", "warden.lock"])
    assert own == ["--lock", "warden.lock"]
    assert server == []


def test_parser_accepts_lock_timeout_strict():
    parser = precommit._build_parser()
    ns = parser.parse_args(["--lock", "x.lock", "--timeout", "12.5", "--strict"])
    assert ns.lock == "x.lock"
    assert ns.timeout == 12.5
    assert ns.strict is True


def test_parser_defaults():
    ns = precommit._build_parser().parse_args([])
    assert ns.lock == precommit.DEFAULT_LOCK_NAME
    assert ns.timeout == precommit.DEFAULT_TIMEOUT
    assert ns.strict is False


# --- empty server-cmd guidance (exit 2) --------------------------------------


def test_empty_server_cmd_exits_2_with_guidance(capsys):
    rc = precommit.main(["--lock", CLEAN_LOCK])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no MCP server command" in err
    assert ".pre-commit-config.yaml" in err
    assert "--" in err  # the separator is documented in the guidance


# --- clean / drift verdicts (real fixture servers) ---------------------------


def test_clean_server_exits_0(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    rc = precommit.main(["--lock", CLEAN_LOCK, "--", "python", CLEAN_SERVER])
    assert rc == 0


def test_mutated_server_exits_1_drift(monkeypatch, capsys):
    monkeypatch.chdir(REPO_ROOT)
    rc = precommit.main(["--lock", CLEAN_LOCK, "--", "python", MUTATED_SERVER])
    assert rc == 1
    err = capsys.readouterr().err
    assert "DRIFT DETECTED" in err


# --- graceful server-unavailability (binding #1) -----------------------------


def test_server_unavailable_non_strict_exits_0(monkeypatch, capsys):
    monkeypatch.chdir(REPO_ROOT)
    rc = precommit.main(
        ["--lock", CLEAN_LOCK, "--timeout", "8", "--", "this-command-does-not-exist-xyz"]
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "WARNING" in err
    # B3: argv[0] (the executable name) IS shown for debuggability, but the
    # remaining args are redacted. Here there are no extra args, so the bare
    # command name appears.
    assert "this-command-does-not-exist-xyz" in err
    assert "8" in err  # timeout value in the message


def test_server_unavailable_strict_exits_2(monkeypatch, capsys):
    monkeypatch.chdir(REPO_ROOT)
    rc = precommit.main(
        ["--strict", "--lock", CLEAN_LOCK, "--timeout", "8", "--", "this-command-does-not-exist-xyz"]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "this-command-does-not-exist-xyz" in err
    assert "8" in err


# --- missing / invalid lock is a config error in both modes (exit 2) ---------


def test_missing_lock_exits_2(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    rc = precommit.main(["--lock", "tests/fixtures/__nope__.warden.lock", "--", "python", CLEAN_SERVER])
    assert rc == 2


def test_missing_lock_exits_2_even_in_strict(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    rc = precommit.main(
        ["--strict", "--lock", "tests/fixtures/__nope__.warden.lock", "--", "python", CLEAN_SERVER]
    )
    assert rc == 2


# --- cwd normalization (binding #2) ------------------------------------------


def test_cwd_normalized_to_repo_root(monkeypatch):
    """Invoked from a non-root dir INSIDE the repo, the wrapper must chdir to the
    git toplevel so the lock path / server argv resolve identically to a root
    invocation. Mirrors the direct `check` of the same fixtures: clean -> 0.

    `tests/fixtures` is a real subdir of the repo, so `git rev-parse
    --show-toplevel` resolves to the repo root from there.
    """
    monkeypatch.chdir(FIXTURES)  # a non-root dir, but still inside the git repo
    rc = precommit.main(["--lock", CLEAN_LOCK, "--", "python", CLEAN_SERVER])
    assert rc == 0


def test_cwd_normalized_matches_direct_check_drift(monkeypatch):
    """From a non-root dir inside the repo, the mutated server must still yield
    the SAME drift verdict (exit 1) as a direct `check` from the repo root."""
    monkeypatch.chdir(FIXTURES)
    rc = precommit.main(["--lock", CLEAN_LOCK, "--", "python", MUTATED_SERVER])
    assert rc == 1


# --- lock write-protection (binding #5) --------------------------------------


def _install_write_spy(monkeypatch, lock_abspath: Path, writes: list[str]) -> None:
    """Record any WRITE-mode access to ``lock_abspath`` via the paths a Python
    lock-writer could plausibly use: ``builtins.open``, ``Path.open``,
    ``Path.write_text``/``write_bytes``, AND the project's own ``write_lock``
    helper (transitive gap — a future refactor could reach the writer without
    touching the file primitives directly). Scoped to the lock path so unrelated
    logging/temp writes do not trip false positives.
    """
    # Spy on write_lock too: assert the wrapper never invokes the lock WRITER at
    # all (it should only ever read_lock + build an in-memory current lock).
    from mcp_warden import lockfile as _lockfile

    _real_write_lock = _lockfile.write_lock

    def _spy_write_lock(*args, **kwargs):
        writes.append("write_lock() invoked")
        return _real_write_lock(*args, **kwargs)

    monkeypatch.setattr(_lockfile, "write_lock", _spy_write_lock)

    real_open = builtins.open
    real_path_open = Path.open
    real_write_text = Path.write_text
    real_write_bytes = Path.write_bytes

    def _is_write_mode(mode: str) -> bool:
        return any(c in mode for c in ("w", "a", "x", "+"))

    def _resolve(p) -> Path | None:
        try:
            return Path(p).resolve()
        except (TypeError, ValueError):
            return None

    def _builtins_open(file, mode="r", *args, **kwargs):
        if _resolve(file) == lock_abspath and _is_write_mode(mode):
            writes.append(f"open({file!r}, mode={mode!r})")
        return real_open(file, mode, *args, **kwargs)

    def _path_open(self, mode="r", *args, **kwargs):
        if self.resolve() == lock_abspath and _is_write_mode(mode):
            writes.append(f"Path.open({self!r}, mode={mode!r})")
        return real_path_open(self, mode, *args, **kwargs)

    def _path_write_text(self, *args, **kwargs):
        if self.resolve() == lock_abspath:
            writes.append(f"Path.write_text({self!r})")
        return real_write_text(self, *args, **kwargs)

    def _path_write_bytes(self, *args, **kwargs):
        if self.resolve() == lock_abspath:
            writes.append(f"Path.write_bytes({self!r})")
        return real_write_bytes(self, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _builtins_open)
    monkeypatch.setattr(Path, "open", _path_open)
    monkeypatch.setattr(Path, "write_text", _path_write_text)
    monkeypatch.setattr(Path, "write_bytes", _path_write_bytes)


def test_lock_never_opened_for_write_on_clean_run(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    lock_abspath = (REPO_ROOT / CLEAN_LOCK).resolve()
    writes: list[str] = []
    _install_write_spy(monkeypatch, lock_abspath, writes)
    rc = precommit.main(["--lock", CLEAN_LOCK, "--", "python", CLEAN_SERVER])
    assert rc == 0
    assert writes == [], f"lock opened for write on a clean run: {writes}"


def test_lock_never_opened_for_write_on_drift_run(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    lock_abspath = (REPO_ROOT / CLEAN_LOCK).resolve()
    writes: list[str] = []
    _install_write_spy(monkeypatch, lock_abspath, writes)
    rc = precommit.main(["--lock", CLEAN_LOCK, "--", "python", MUTATED_SERVER])
    assert rc == 1
    assert writes == [], f"lock opened for write on a drift run: {writes}"


def test_precommit_module_does_not_import_pin_or_lock_writer():
    """Static guarantee: the wrapper source imports only the check path.

    It must not import the CLI module (which exposes `pin` / `--approve`) nor the
    lock WRITER (`write_lock`). `read_lock`/`build_lock` (in-memory, for diffing)
    are allowed via check_core.
    """
    # Inspect the actual import statements via the AST, not raw text (the module
    # docstring legitimately mentions write_lock / pin when explaining the rule).
    import ast

    tree = ast.parse(inspect.getsource(precommit))
    imported_modules: set[str] = set()
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            imported_modules.add(node.module or "")
            for alias in node.names:
                imported_names.add(alias.name)

    assert "write_lock" not in imported_names, "precommit must never import the lock writer"
    assert "cli" not in imported_modules and ".cli" not in imported_modules, (
        "precommit must not import the CLI module (pin / --approve live there)"
    )
    assert "pin" not in imported_names
    # The only mcp_warden internals it may pull in are capture + check_core.
    assert "check_core" in imported_modules
    assert "capture" in imported_modules


# --- B2: internal pipeline exception -> exit 2, NOT 1 (drift) ----------------


def test_internal_exception_exits_2_not_drift(monkeypatch, capsys):
    """code-audit B2: a generic exception raised inside the check pipeline (e.g.
    a pydantic ValidationError or AttributeError on an unexpected model shape)
    must route to exit 2 (internal error), NEVER exit 1 — because exit 1 means
    ONLY confirmed drift. We monkeypatch the check entry point the wrapper
    actually calls (``precommit.run_check``) so it raises a RuntimeError, and
    assert the wrapper fails closed with a clear internal-error message at 2.
    """
    monkeypatch.chdir(REPO_ROOT)

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated compute_drift explosion")

    monkeypatch.setattr(precommit, "run_check", _boom)

    rc = precommit.main(["--lock", CLEAN_LOCK, "--", "python", CLEAN_SERVER])
    assert rc == 2, "an internal exception must NOT masquerade as a drift verdict (exit 1)"
    err = capsys.readouterr().err
    assert "internal error" in err.lower()
    assert "RuntimeError" in err  # the exception type aids debugging
    assert "NOT a drift" in err  # explicitly disclaims the drift verdict


# --- B3: server argv secrets must NEVER leak to stderr -----------------------


def test_capture_error_does_not_leak_secret_in_argv(monkeypatch, capsys):
    """code-audit B3 (SECURITY): a secret planted in the server argv must NEVER
    appear in stderr. pre-commit captures stderr to logs (~/.pre-commit-logs),
    CI logs, and scrollback. Mirrors the planted-secret convention in
    tests/test_diff.py (sk-PLANTEDSECRET123). We use a non-existent executable so
    capture raises CaptureError (the path that previously shlex.join'd the full
    argv), and assert the planted token is absent from the warning.
    """
    monkeypatch.chdir(REPO_ROOT)
    secret = "SUPERSECRET123"
    rc = precommit.main(
        [
            "--lock",
            CLEAN_LOCK,
            "--timeout",
            "8",
            "--",
            "this-command-does-not-exist-xyz",
            "--token",
            secret,
        ]
    )
    assert rc == 0  # non-strict: server-unavailable -> warn + pass
    err = capsys.readouterr().err
    assert secret not in err, "server argv secret leaked into stderr (B3 regression)"
    assert "SUPERSECRET" not in err
    # The change is still observable: argv[0] + a redaction marker are shown.
    assert "this-command-does-not-exist-xyz" in err
    assert "redacted" in err


def test_redact_server_hides_args_keeps_executable():
    """_redact_server echoes only argv[0] + a redacted arg count (B3 helper)."""
    redacted = precommit._redact_server("node", ["server.js", "--api-key", "SUPERSECRET123"])
    assert "SUPERSECRET123" not in redacted
    assert redacted.startswith("node")
    assert "redacted" in redacted
    # zero-arg case renders the bare command (nothing to redact).
    assert precommit._redact_server("python", []) == "python"


# --- .pre-commit-hooks.yaml structural invariants ----------------------------


def _load_hook() -> dict:
    data = yaml.safe_load(HOOKS_YAML.read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 1, "expected exactly one hook entry"
    return data[0]


def test_hooks_yaml_exists_and_parses():
    assert HOOKS_YAML.exists(), ".pre-commit-hooks.yaml must exist at the repo root"
    _load_hook()  # raises on parse error


def test_hook_id_is_stable():
    assert _load_hook()["id"] == "mcp-warden-check"


def test_hook_entry_points_at_wrapper():
    assert _load_hook()["entry"] == "mcp-warden-precommit"


def test_hook_pass_filenames_is_false():
    # Must be the boolean False, not a truthy string.
    assert _load_hook()["pass_filenames"] is False


def test_hook_always_run_and_serial_and_python():
    hook = _load_hook()
    assert hook["always_run"] is True
    assert hook["require_serial"] is True
    assert hook["language"] == "python"


def test_console_entry_point_declared_in_pyproject():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'mcp-warden-precommit = "mcp_warden.precommit:main"' in text
