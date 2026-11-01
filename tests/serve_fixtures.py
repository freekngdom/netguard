#!/usr/bin/env python3
"""Replay a captured Docker API from tests/fixtures/docker.json.

Used by the test suite and by `make smoke` — the app itself is unmodified, only the
transport is replaced, so the tests exercise the real request/parse path.
"""
from __future__ import annotations

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = json.load(open(os.path.join(HERE, "fixtures", "docker.json"), encoding="utf-8"))


def by_name(name: str):
    # inspect first: /containers/json returns `Aliases: null`, which is exactly the
    # production behaviour the app has to work around.
    for key, obj in DATA["inspects"].items():
        if key == name or obj["Id"] == name:
            return obj
    for c in DATA["containers"]:
        if c["Id"] == name or c["Names"][0].lstrip("/") == name:
            return c
    return None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/_ping":
            return self.reply(b"OK", "text/plain")
        if path == "/networks":
            return self.reply(json.dumps(DATA["networks"]))
        if path == "/containers/json":
            return self.reply(json.dumps(DATA["containers"]))
        m = re.match(r"^/containers/([^/]+)/json$", path)
        if m:
            obj = by_name(m.group(1))
            if obj is None:
                self.send_response(404)
                self.end_headers()
                return
            return self.reply(json.dumps(obj))
        self.send_response(404)
        self.end_headers()

    def reply(self, body, ctype="application/json") -> None:
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args) -> None:
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2375
    server = ThreadingHTTPServer(("", port), Handler)
    server.daemon_threads = True
    print("fixture docker API on 0.0.0.0:%d" % port, flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
