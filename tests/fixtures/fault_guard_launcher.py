"""Fault-injecting ``guard`` launcher (TEST FIXTURE ONLY).

Monkeypatches ONE inspection entry point to raise BEFORE handing off to the real
``mcp_warden.cli`` ``guard`` command, then execs the CLI in-process. This forces a
genuine inspection-layer error from inside the spawned guard child WITHOUT adding
any test-only branch to production code (the strict-abort tests spawn this module
instead of ``mcp_warden.cli`` directly).

Usage (argv):
    python fault_guard_launcher.py <SITE> [-- guard args... -- server argv...]

``<SITE>`` selects which inspection function to break:
    inspect-result  -> mcp_warden.guard_result.inspect_result        (result-inspect)
    policy          -> mcp_warden.guard_loop.evaluate_call           (request-policy)
    diverges        -> mcp_warden.guard_result.diverges_from_lock    (list-gate)
    hash            -> mcp_warden.guard_list_gate._hash_live_tools   (list-gate via #5)

Env:
    FAULT_SECRET   -> if set, the injected exception message embeds this value, so
                      the redaction test can assert it never reaches stderr or the
                      client error frame (the abort path must use sanitized fields
                      only, never the original exception text).
"""

from __future__ import annotations

import os
import sys


def _make_raiser(label: str):
    """Build a function that raises a RuntimeError tagged with an optional secret."""
    secret = os.environ.get("FAULT_SECRET", "")

    def _raise(*_args, **_kwargs):  # noqa: ANN002, ANN003 - generic shim
        msg = f"injected {label} fault"
        if secret:
            # The secret lives ONLY in the original exception message; the strict
            # abort path must never echo it (sanitized {site,tool,exc_type} only).
            msg = f"{msg}: {secret}"
        raise RuntimeError(msg)

    return _raise


def _install_fault(site: str) -> None:
    """Monkeypatch the chosen inspection function to raise."""
    if site == "inspect-result":
        import mcp_warden.guard_result as gr

        gr.inspect_result = _make_raiser("inspect_result")  # type: ignore[assignment]
    elif site == "policy":
        import mcp_warden.guard_loop as gl

        gl.evaluate_call = _make_raiser("evaluate_call")  # type: ignore[assignment]
    elif site == "diverges":
        import mcp_warden.guard_list_gate as glg
        import mcp_warden.guard_result as gr

        raiser = _make_raiser("diverges_from_lock")
        glg.diverges_from_lock = raiser  # type: ignore[assignment]
        # guard_result imports diverges_from_lock lazily inside the function, so
        # patching the module attribute is sufficient; also rebind any cached ref.
        if hasattr(gr, "diverges_from_lock"):
            gr.diverges_from_lock = raiser  # type: ignore[assignment]
    elif site == "hash":
        import mcp_warden.guard_list_gate as glg

        glg._hash_live_tools = _make_raiser("_hash_live_tools")  # type: ignore[assignment]
    else:  # pragma: no cover - test misuse
        raise SystemExit(f"unknown fault site: {site!r}")


def main() -> None:
    """Install the fault, then hand argv off to the real guard CLI."""
    if len(sys.argv) < 2:  # pragma: no cover - test misuse
        raise SystemExit("usage: fault_guard_launcher.py <SITE> [guard args...]")
    site = sys.argv[1]
    _install_fault(site)

    # Rewrite argv so the CLI sees: prog guard <rest...>
    cli_args = sys.argv[2:]
    sys.argv = ["mcp-warden", "guard", *cli_args]

    from mcp_warden.cli import app

    app()


if __name__ == "__main__":
    main()
