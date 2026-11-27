"""Synthetic HTTP and stdio echo server shared by integration tests and timing."""

from __future__ import annotations

import json
import socket
import sys
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

VERSION = "2025-11-25"
TOKEN = "synthetic-loopback-token-for-warden"


def reply(message: dict):
    method = message["method"]
    if method.startswith("notifications/"):
        return None
    if method == "initialize":
        result = {"protocolVersion": VERSION, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "loopback-fixture", "version": "1"}}
    else:
        size = message["params"]["arguments"].get("size", 8)
        result = {"content": [{"type": "text", "text": "a" * size}]}
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *args):
        pass

    def respond(self, status, body=b"", *, initialize=False):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if body:
            self.send_header("Content-Type", "application/json")
        if initialize:
            self.send_header("MCP-Session-Id", "synthetic-loopback-session-id")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self.respond(405)

    def do_POST(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.respond(401, TOKEN.encode())
            return
        message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        initializing = message["method"] == "initialize"
        if not initializing and (
            self.headers.get("MCP-Session-Id") != "synthetic-loopback-session-id"
            or self.headers.get("MCP-Protocol-Version") != VERSION
        ):
            self.respond(400)
            return
        result = reply(message)
        if result is None:
            self.respond(202)
        else:
            self.respond(200, json.dumps(result).encode(), initialize=initializing)

    def do_DELETE(self):
        self.server.deleted.set()
        self.respond(204)


@contextmanager
def server():
    from threading import Event

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as listener:
        listener.deleted = Event()
        thread = Thread(target=listener.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{listener.server_port}/mcp", listener.deleted
        finally:
            listener.shutdown()
            thread.join()


if __name__ == "__main__":
    for line in sys.stdin.buffer:
        result = reply(json.loads(line))
        if result is not None:
            sys.stdout.buffer.write(json.dumps(result).encode() + b"\n")
            sys.stdout.buffer.flush()
