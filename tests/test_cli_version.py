"""``mcp-warden --version`` flag coverage.

The version flag is a shipped support contract: ``SECURITY.md`` and the
bug-report issue template instruct users to run ``mcp-warden --version`` to
report their installed version, and ``RELEASING.md`` uses it in the post-release
verify step. These tests assert the flag prints the package version and exits 0,
and that adding the eager root callback did not break the subcommands.
"""

from __future__ import annotations

from typer.testing import CliRunner

from mcp_warden import __version__
from mcp_warden.cli import app

runner = CliRunner()

#: Force a wide terminal so rich/typer does not line-wrap the help table (which
#: would split the ``--version`` token across lines under a narrow CI terminal).
#: Matches the established convention in ``tests/test_diff.py``.
_WIDE = {"COLUMNS": "1000"}


def test_version_flag_prints_version_and_exits_zero() -> None:
    """``--version`` prints ``mcp-warden <version>`` and exits 0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert __version__ in result.output
    assert "mcp-warden" in result.output


def test_version_flag_listed_in_help() -> None:
    """``--help`` advertises the ``--version`` flag (wide terminal: no wrap)."""
    result = runner.invoke(app, ["--help"], env=_WIDE)
    assert result.exit_code == 0, result.output
    assert "--version" in result.output


def test_root_callback_does_not_break_subcommands() -> None:
    """The eager root callback must not shadow or break the subcommands.

    A bare unknown subcommand still errors as before (non-zero), proving the
    callback did not turn the app into a no-arg command.
    """
    result = runner.invoke(app, ["definitely-not-a-command"])
    assert result.exit_code != 0
