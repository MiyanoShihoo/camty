#!/usr/bin/env python3
"""beacon_server.py - local beacon receiver for translet testing.

Logs every GET (raw path + decoded params + client IP) to scripts/beacon_local.log.
Usage: python beacon_server.py   (binds 127.0.0.1:8000, Ctrl-C to stop)
"""

import datetime
import http.server
import os
import socketserver
import urllib.parse

PORT = 8000
HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "beacon_local.log")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        dec = "; ".join("%s=%s" % (k, v[0]) for k, v in sorted(qs.items()))
        line = "%s  GET  %-70s  from=%s  params=[%s]" % (
            now, self.path, self.client_address[0], dec)
        with open(LOG, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # we log ourselves


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    print("beacon server on http://127.0.0.1:%d, log: %s" % (PORT, LOG))
    Server(("127.0.0.1", PORT), Handler).serve_forever()
