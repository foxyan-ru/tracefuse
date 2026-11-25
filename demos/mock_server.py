"""Local mock API so the demo never depends on public services."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"items": [{"id": i, "name": "item-%d" % i} for i in range(10)]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer((HOST, 8080), Handler).serve_forever()
