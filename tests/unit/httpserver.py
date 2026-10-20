"""A tiny HTTPS file server for definition update tests (localhost only).

Serves an in-memory ``files`` mapping (path -> bytes), with ETag/304
support and injectable error responses.  The certificate is generated per
test session and trusted through ``OFFSCAN_CA_BUNDLE``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import http.server
import ssl
import threading
from pathlib import Path


def make_cert(directory: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class FileServer:
    def __init__(self, directory: Path):
        self.files: dict[str, bytes] = {}
        self.errors: dict[str, tuple[int, dict[str, str]]] = {}
        self.redirects: dict[str, str] = {}
        self.requests: list[str] = []
        self.cert, key = make_cert(directory)
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                server.requests.append(path)
                if path in server.errors:
                    code, headers = server.errors[path]
                    self.send_response(code)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    return
                if path in server.redirects:
                    self.send_response(302)
                    self.send_header("Location", server.redirects[path])
                    self.end_headers()
                    return
                data = server.files.get(path)
                if data is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                etag = '"' + hashlib.sha256(data).hexdigest()[:16] + '"'
                if self.headers.get("If-None-Match") == etag:
                    self.send_response(304)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("ETag", etag)
                self.end_headers()
                self.wfile.write(data)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
