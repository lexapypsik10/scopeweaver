"""Intentionally misconfigured, synthetic loopback-only HTTP audit fixture."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class LabHandler(BaseHTTPRequestHandler):
    server_version = "ScopeWeaver-Lab/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://external.invalid/")
            self.end_headers()
            return
        body = (
            b"<!doctype html><title>ScopeWeaver local lab</title><h1>Index of /</h1>"
            b"<p>Synthetic fixture: no real files or credentials.</p>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "lab_session=synthetic-only; Path=/")
        self.send_header(
            "Access-Control-Allow-Origin", self.headers.get("Origin", "https://trusted.invalid")
        )
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS, PUT")
        self.end_headers()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be from 1 to 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler)
    print(f"Synthetic lab at http://127.0.0.1:{args.port}/ — Ctrl+C to stop", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
