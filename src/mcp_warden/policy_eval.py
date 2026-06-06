"""Single-sample policy evaluation (POLICY_MODEL.md §4.2, §5).

Evaluates exactly one provided sample call against a :class:`Policy`. No runtime
interception, no DNS resolution, leading-token shell/SQL inspection only. Deny
overrides allow. Exit non-zero on a ``deny`` verdict is the CLI's job.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from .net_rules import SSRF_NETWORKS, extract_host, host_glob_match, parse_ip
from .policy_model import DEFAULT_SQL_DENY, Policy

_SHELL_METACHARS = re.compile(r"[;|`&]|\$\(")
_SQL_READONLY_LEADERS = {"SELECT", "WITH", "EXPLAIN"}

_FS_PATH_ARGS = ["path", "file", "filename", "dest", "target"]
_SHELL_CMD_ARGS = ["command", "cmd", "script", "shell"]
_HTTP_URL_ARGS = ["url", "uri", "endpoint", "host", "hostname"]
_SQL_QUERY_ARGS = ["query", "sql", "statement"]


@dataclass
class Verdict:
    """A policy-evaluation verdict (POLICY_MODEL.md §4.2 example).

    Attributes:
        tool: The evaluated tool name.
        shape: The shape that produced the verdict (or ``"none"``).
        verdict: ``allow`` or ``deny``.
        reason: Human-readable explanation.
        constraint: The specific constraint/code that produced the verdict.
    """

    tool: str
    shape: str
    verdict: str  # allow|deny
    reason: str
    constraint: str

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable verdict object."""
        return {
            "tool": self.tool,
            "shape": self.shape,
            "verdict": self.verdict,
            "reason": self.reason,
            "constraint": self.constraint,
        }


def _auto_detect(arguments: dict[str, Any], candidates: list[str], override: str | None) -> str | None:
    """Pick the argument key holding a value (explicit override or first match)."""
    if override and override in arguments:
        return override
    for cand in candidates:
        if cand in arguments:
            return cand
    return None


def _normalize_path(path: str) -> str:
    """Lexically resolve ``.``/``..`` with no symlink resolution (§2.1)."""
    parts: list[str] = []
    for seg in path.replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    prefix = "/" if path.startswith("/") else ""
    return prefix + "/".join(parts)


def _glob_match(path: str, glob: str) -> bool:
    """Match a normalized path against a ``**``/``*``/``?`` glob."""
    norm_path = _normalize_path(path)
    norm_glob = _normalize_path(glob) if not glob.startswith("/") else glob
    # fnmatch treats * as crossing separators; emulate ** vs * by translating.
    regex = _glob_to_regex(norm_glob)
    return re.fullmatch(regex, norm_path) is not None


def _glob_to_regex(glob: str) -> str:
    """Translate a path glob (``**``/``*``/``?``) to an anchored regex."""
    out: list[str] = []
    i = 0
    while i < len(glob):
        ch = glob[i]
        if ch == "*":
            if glob[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _eval_filesystem_write(tool: str, args: dict[str, Any], cons: dict[str, Any]) -> Verdict:
    """Evaluate a filesystem-write call (POLICY_MODEL.md §2.1, §5)."""
    key = _auto_detect(args, _FS_PATH_ARGS, cons.get("path_arg"))
    path = str(args.get(key, "")) if key else ""
    deny_paths = cons.get("deny_paths") or []
    allow_paths = cons.get("allow_paths")  # None => unconstrained; [] => deny-all

    for glob in deny_paths:
        if _glob_match(path, glob):
            return Verdict(tool, "filesystem-write", "deny", f"path '{path}' matches deny_paths '{glob}'", "POL-FS-DENY")

    if allow_paths is None:
        return Verdict(tool, "filesystem-write", "allow", "no allow_paths constraint", "POL-FS-DENY")
    if len(allow_paths) == 0:
        return Verdict(tool, "filesystem-write", "deny", "empty allow_paths (deny-all)", "POL-FS-DENY")
    for glob in allow_paths:
        if _glob_match(path, glob):
            return Verdict(tool, "filesystem-write", "allow", f"path '{path}' matches allow_paths '{glob}'", "POL-FS-DENY")
    return Verdict(tool, "filesystem-write", "deny", f"path '{path}' not in allow_paths", "POL-FS-DENY")


def _eval_shell_exec(tool: str, args: dict[str, Any], cons: dict[str, Any]) -> Verdict:
    """Evaluate a shell-exec call (POLICY_MODEL.md §2.2, §5). Deny-by-default."""
    key = _auto_detect(args, _SHELL_CMD_ARGS, cons.get("command_arg"))
    command = str(args.get(key, "")) if key else ""

    if _SHELL_METACHARS.search(command):
        return Verdict(tool, "shell-exec", "deny", "command contains shell metacharacters", "POL-SHELL-METACHAR")

    if not cons.get("allow", False):
        return Verdict(tool, "shell-exec", "deny", "shell-exec denied by default (allow=false)", "POL-SHELL-DENY")

    allow_commands = cons.get("allow_commands")
    leading = command.split()[0] if command.split() else ""
    if allow_commands is not None and leading not in allow_commands:
        return Verdict(tool, "shell-exec", "deny", f"command '{leading}' not in allow_commands", "POL-SHELL-DENY")
    return Verdict(tool, "shell-exec", "allow", f"command '{leading}' permitted", "POL-SHELL-DENY")


def _eval_http_request(tool: str, args: dict[str, Any], cons: dict[str, Any]) -> Verdict:
    """Evaluate an http-request call (POLICY_MODEL.md §2.3, §5). No DNS resolution."""
    key = _auto_detect(args, _HTTP_URL_ARGS, cons.get("url_arg"))
    raw = str(args.get(key, "")) if key else ""
    host = extract_host(raw)

    deny_private = cons.get("deny_private", True)
    deny_cidrs = cons.get("deny_cidrs") or []
    allow_hosts = cons.get("allow_hosts")

    ip = parse_ip(host)
    if ip is not None:
        # Explicit deny_cidrs first, then deny_private ranges.
        for cidr in deny_cidrs:
            try:
                if ip in ipaddress.ip_network(cidr):
                    return Verdict(tool, "http-request", "deny", f"host {host} in deny_cidrs {cidr}", "POL-HTTP-SSRF")
            except ValueError:
                continue
        if deny_private:
            for net, label in SSRF_NETWORKS:
                if ip in net:
                    return Verdict(
                        tool, "http-request", "deny",
                        f"host {host} is in deny_private range {net} ({label})", "deny_private",
                    )

    # allow_hosts (host globs / exact). DNS names are NOT resolved (§2.3).
    if allow_hosts is not None:
        if any(host_glob_match(host, pat) for pat in allow_hosts):
            return Verdict(tool, "http-request", "allow", f"host {host} matches allow_hosts", "POL-HTTP-HOST-DENY")
        return Verdict(tool, "http-request", "deny", f"host {host} not in allow_hosts", "POL-HTTP-HOST-DENY")

    if ip is None and host:
        # DNS name, no allow_hosts list -> unresolved note; allow unless denied above.
        return Verdict(
            tool, "http-request", "allow",
            f"host {host} is a DNS name not resolved at design time", "POL-HTTP-DNS-UNRESOLVED",
        )
    return Verdict(tool, "http-request", "allow", f"host {host} permitted", "POL-HTTP-HOST-DENY")


def _eval_sql_query(tool: str, args: dict[str, Any], cons: dict[str, Any]) -> Verdict:
    """Evaluate a sql-query call (POLICY_MODEL.md §2.4, §5). Leading-keyword only."""
    key = _auto_detect(args, _SQL_QUERY_ARGS, cons.get("query_arg"))
    query = str(args.get(key, "")) if key else ""

    if _has_stacked_statements(query):
        return Verdict(tool, "sql-query", "deny", "query contains stacked statements", "POL-SQL-STACKED")

    leading = _leading_sql_keyword(query)
    allow_readonly = cons.get("allow_readonly_only", True)
    deny_statements = [s.upper() for s in (cons.get("deny_statements") or DEFAULT_SQL_DENY)]

    if leading in deny_statements:
        return Verdict(tool, "sql-query", "deny", f"leading keyword '{leading}' is in deny_statements", "POL-SQL-DENY")
    if allow_readonly and leading not in _SQL_READONLY_LEADERS:
        return Verdict(
            tool, "sql-query", "deny",
            f"leading keyword '{leading}' is not read-only (SELECT/WITH/EXPLAIN)", "POL-SQL-DENY",
        )
    return Verdict(tool, "sql-query", "allow", f"leading keyword '{leading}' permitted", "POL-SQL-DENY")


_SHAPE_EVALUATORS = {
    "filesystem_write": _eval_filesystem_write,
    "shell_exec": _eval_shell_exec,
    "http_request": _eval_http_request,
    "sql_query": _eval_sql_query,
}


def evaluate_call(policy: Policy, tool: str, arguments: dict[str, Any], shapes: list[str]) -> list[Verdict]:
    """Evaluate a sample call against the policy for each matched shape.

    Args:
        policy: The loaded policy.
        tool: The tool name from the sample call.
        arguments: The sample call arguments.
        shapes: The snake_case shapes the tool matches (from lock or inference).

    Returns:
        One :class:`Verdict` per shape. The CLI denies overall if ANY verdict is
        ``deny`` (deny overrides allow, §6.3). If no shapes match, returns a
        single ``allow`` verdict with shape ``"none"``.
    """
    if not shapes:
        return [Verdict(tool, "none", "allow", "no high-risk shape matched", "none")]
    verdicts: list[Verdict] = []
    for shape in shapes:
        cons = policy.effective(tool, shape)
        verdicts.append(_SHAPE_EVALUATORS[shape](tool, arguments, cons))
    return verdicts


def overall_denied(verdicts: list[Verdict]) -> bool:
    """Return True if any verdict is a deny (deny overrides allow)."""
    return any(v.verdict == "deny" for v in verdicts)


# --- sql helpers -------------------------------------------------------------


def _leading_sql_keyword(query: str) -> str:
    """Return the first non-whitespace word of a query, uppercased."""
    stripped = query.strip()
    if not stripped:
        return ""
    return re.split(r"\s|\(", stripped, maxsplit=1)[0].upper()


def _has_stacked_statements(query: str) -> bool:
    """Return True if a ``;`` separates two non-comment statements (§2.4)."""
    # Remove trailing semicolons; a single terminal ; is not "stacked".
    body = query.strip().rstrip(";").strip()
    return ";" in body
