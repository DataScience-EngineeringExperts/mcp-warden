# Streamable HTTP guard

`mcp-warden guard --url` gives a POSIX harness a stdio command that mediates one upstream
Streamable HTTP MCP session. It uses the same argument policies, lock digests, result rules,
redaction, and correlation as the launched-stdio guard. Standard input and output carry
newline-delimited MCP frames. The adapter opens outbound connections to the configured URL
and uses the same origin for POST, GET resume, and DELETE.

## Connect a laptop harness

Install a Warden build that exposes `mcp-warden guard --help` with `--url` on the laptop.
Keep the approved lock and policy in a trusted location. Replace the sample URL, executable
and file paths with the actual values. If the provider requires a bearer token, populate
`MCP_UPSTREAM_TOKEN` in the harness launch environment using the existing secret provider.
For an unauthenticated endpoint, omit `--http-token-env MCP_UPSTREAM_TOKEN`.

For Codex, replace the existing direct HTTP entry in `~/.codex/config.toml` with a command
entry. Use an absolute executable path if Warden is outside the harness's PATH.

```toml
[mcp_servers.example]
command = "mcp-warden"
args = ["guard", "--url", "https://mcp.example.com/mcp", "--http-token-env", "MCP_UPSTREAM_TOKEN", "--lock", "/trusted/warden.lock", "--policy", "/trusted/warden-policy.yml"]
env_vars = ["MCP_UPSTREAM_TOKEN"]
```

For Claude Code, use the same scope as the original entry. Back up the original definition
and remove it from that scope before adding the stdio adapter under the same name.

```bash
claude mcp add --scope local --transport stdio example -- \
  mcp-warden guard --url https://mcp.example.com/mcp \
  --http-token-env MCP_UPSTREAM_TOKEN --lock /trusted/warden.lock \
  --policy /trusted/warden-policy.yml
```

Restart the harness and verify that the named server completes initialization and
`tools/list` with the expected pinned tool definitions. Invoke an approved read-only
fixture tool and check both the returned result and the Warden report. For a synthetic
denied call, the harness should receive Warden error `-32001` and the fixture should
receive no call. Until that endpoint is routed and verified, inventory it as unmediated.

## Lifecycle and control boundaries

- The adapter accepts one initialization and supports MCP protocol versions
  `2025-03-26`, `2025-06-18`, and `2025-11-25`. It handles POST JSON replies and SSE,
  both request-scoped and unsolicited. A GET response of 405 means the endpoint
  offers no unsolicited stream. An established unsolicited stream that ends
  without successful resume closes the local session.
- Valid request-scoped progress is forwarded. Client cancellation stops local result
  delivery and posts the cancellation upstream. A delivered result can race with
  cancellation. A failed or timed-out call may have started upstream.
- SSE reconnect uses the last event ID, honors retry delays within the call deadline
  and allows up to four resumes. The adapter never resends the original POST.
  An expired upstream session closes the adapter with a safe error. A restarted
  adapter negotiates a new session without the previous session ID.
- The adapter checks an armed lock on every complete tool listing. A paginated list
  with a lock receives an error because a single page cannot be compared to the
  complete pinned surface. Strict inspection errors and frame overflows close the
  session with error `-32003`. Other transport failures use `-32002`; upstream
  JSON-RPC error codes are retained when valid and their messages are replaced.
- The default deadline is 30 seconds and the default in-flight limit is eight calls.
  `--http-timeout` and `--http-concurrency` adjust those limits. Sessions close after
  65,536 request IDs to keep duplicate-ID rejection bounded. Frames are capped
  before accumulation using `--max-frame-bytes` (1 KiB–8 MiB). Writes apply pipe
  backpressure and stop the session if stdout stalls. EOF, SIGINT, or SIGTERM
  cancels active exchanges and attempts a bounded DELETE for a stateful session.
  DNS inspection evaluates up to 32 hostnames per result in a subprocess with a
  one-second deadline. Each session permits two DNS workers at a time and reaps
  a worker on timeout or cancellation. A DNS deadline closes the session as an
  incomplete inspection.
- Only upstream HTTPS and cleartext loopback HTTP are supported. Redirects, URL
  credentials, query strings, response compression, cookies, and automatic OAuth
  are unsupported. Provider credentials remain in request headers. The adapter
  refuses a body containing a known transport credential before inspection or capture.
- Server-initiated client RPC, task lifecycle, legacy HTTP+SSE, and the opt-in
  universal normalization worker are unsupported. The adapter does not advertise
  client capabilities that require server-to-client requests.
- `--record` explicitly writes inspected-boundary JSON-RPC observations for
  `mcp-warden inspect` to a new mode-0600 file. It excludes HTTP metadata. Frame
  payloads may contain sensitive application data, so retain the file only as
  long as needed. The report buffers up to 1,024 findings and announces truncation.

See the [MCP Streamable HTTP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http).

## Rollback

Stop the harness and disable the named adapter entry. If direct HTTP is needed, restore
the saved server definition in the original scope and restart the harness. Mark the
endpoint unmediated after restoration. For an endpoint that must stay mediated,
leave the entry disabled until the adapter can pass initialization, lock checking,
and the fixture calls again.

## Builder benchmark

Run `PYTHONPATH=src:. python scripts/benchmark_http_guard.py --count 200` from the
repo. It compares warm sequential calls via direct loopback HTTP, guarded loopback
HTTP, and guarded stdio. Both guard paths keep the default policy and inspect the same
response payload. The benchmark excludes process startup and external provider latency.
