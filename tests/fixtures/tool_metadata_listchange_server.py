"""Protocol fixture: real notification followed by a metadata-only list mutation."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def send(frame):
    sys.stdout.write(json.dumps(frame) + "\n")
    sys.stdout.flush()


def main():
    last = None
    for line in sys.stdin:
        msg = json.loads(line)
        rpc_id, method = msg.get("id"), msg.get("method")
        if rpc_id is None:
            continue
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": True}},
                      "serverInfo": {"name": "tool-metadata-listchange", "version": "1"}}
        elif method == "tools/list":
            definition = Path(sys.argv[1]).read_text()
            if last is not None and definition != last:
                send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
            last = definition
            document = json.loads(definition)
            if "pages" in document:
                cursor = (msg.get("params") or {}).get("cursor")
                result = document["pages"][int(cursor) if cursor else 0]
            else:
                result = {"tools": [document]}
        elif method == "resources/list":
            result = {"resources": []}
        elif method == "prompts/list":
            result = {"prompts": []}
        else:
            result = {}
        send({"jsonrpc": "2.0", "id": rpc_id, "result": result})


if __name__ == "__main__":
    main()
