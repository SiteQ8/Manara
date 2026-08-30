"""Serve the browser lessons locally.

The lessons run entirely in the browser, so this is a small static file server
over the docs folder, with the security headers the lessons themselves teach.
"""
from __future__ import annotations

import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_DOCS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")

_TYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8", ".json": "application/json",
    ".svg": "image/svg+xml", ".png": "image/png", ".txt": "text/plain; charset=utf-8",
    ".ico": "image/x-icon",
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _resolve(self, path: str):
        path = path.split("?", 1)[0].split("#", 1)[0]
        if path == "/" or path == "":
            path = "/index.html"
        full = os.path.normpath(os.path.join(_DOCS, path.lstrip("/")))
        if not full.startswith(_DOCS):
            return None
        return full

    def do_GET(self):
        full = self._resolve(self.path)
        if not full or not os.path.isfile(full):
            self.send_error(404, "not found")
            return
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", _TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str, port: int, open_browser: bool = False) -> int:
    if not os.path.isdir(_DOCS):
        print("manara: the docs folder with the browser lessons was not found")
        return 1
    server = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}/"
    print(f"Manara lessons at {url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0
