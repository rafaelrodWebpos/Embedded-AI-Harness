"""DNS override for SoftAP clients — capability `bench-dns-override` (fork, CR-TB-05).

While enabled, dnsmasq on the bench AP answers ONE chosen host name (e.g.
`github.com`) with the AP's own address, and an HTTPS server with a
self-signed certificate listens on that address, port 443. A DUT that verifies
certificates must refuse it (its TLS check is what the test exercises); one
that downloads from it has a broken check.

Safety model
------------
* Off by default: at portal start-up and on every `ap_stop`.
* Only AP clients are affected: the override is a dnsmasq `addn-hosts` file
  read by the AP's own dnsmasq, never the Pi's or the LAN's resolver.
* The HTTPS server binds to the AP address only (192.168.4.1:443), never to
  0.0.0.0, so it is not reachable from the LAN side.
* The server sends no file: every request gets a fixed 404 page. Nothing is
  downloaded from it even by a client that skips verification.
* The egress chains (ap_egress) are not touched.

The decisions (host validation, hosts-file text) are pure functions so the
host tier can check them without a Pi.
"""
import http.server
import logging
import os
import re
import signal
import ssl
import subprocess
import threading

import run_dir
import tls_mirror_controller as tls

logger = logging.getLogger("dns_override")

HTTPS_PORT = 443
CERT_DIR = os.environ.get("DNS_OVERRIDE_TLS_DIR", "/var/lib/rfc2217/dns-override-tls")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ── Pure core ─────────────────────────────────────────────────────────────

def parse_request(body):
    """POST body → (enabled, host). `host` is required when enabling; a JSON
    boolean is required for `enabled` (a typo must not switch it on)."""
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        raise ValueError("enabled must be true or false")
    enabled = body["enabled"]
    host = body.get("host")
    if enabled:
        host = validate_host(host)
    return enabled, host if enabled else None


def validate_host(host):
    """A DNS name with at least one dot, lower case, no IP literal, no wildcard."""
    if not isinstance(host, str):
        raise ValueError("host must be a string")
    h = host.strip().lower().rstrip(".")
    if _IPV4_RE.fullmatch(h) or not _HOST_RE.fullmatch(h):     # S6-08: fullmatch, no trailing \n
        raise ValueError("host must be a DNS name such as github.com")
    return h


def hosts_file_text(enabled, host, ap_ip):
    """Content of the dnsmasq addn-hosts file: one line while on, empty while off."""
    return f"{ap_ip} {host}\n" if enabled and host else ""


# ── HTTPS server ──────────────────────────────────────────────────────────

class _Handler(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        body = b"bench-dns-override: no content\n"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = _answer

    def log_message(self, fmt, *args):
        logger.info("https %s", fmt % args)


HANDSHAKE_TIMEOUT_S = 5


class _TLSServer(http.server.ThreadingHTTPServer):
    """S6-09: the listening socket stays plain; each accepted connection does its TLS
    handshake in its own worker thread with a timeout, so a client that opens TCP and
    never sends a ClientHello cannot block accept() for everybody else."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(HANDSHAKE_TIMEOUT_S)
        return sock, addr

    def finish_request(self, request, client_address):
        try:
            tls_sock = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return                                   # bad or slow client: dropped
        self.RequestHandlerClass(tls_sock, client_address, self)


class DnsOverride:
    """State and side effects; `write_file` and `make_server` are injectable."""

    def __init__(self, ap_ip, hosts_file, write_file=None, make_server=None):
        self.ap_ip, self.hosts_file = ap_ip, hosts_file
        self.enabled, self.host = False, None
        self._lock = threading.Lock()
        self._dnsmasq_pid = None
        self._server = None
        self._write = write_file or self._write_file
        self._make_server = make_server or self._https_server

    @staticmethod
    def _write_file(path, text):
        # S6-03: under the root-owned /run/harness, O_NOFOLLOW; 0644 so dnsmasq,
        # possibly without root by then, can re-read it on SIGHUP (not a secret).
        run_dir.ensure_run_dirs()
        run_dir.write_file(path, text, 0o644)

    def _https_server(self):
        os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
        cert, key = os.path.join(CERT_DIR, tls.CERT_FILE), os.path.join(CERT_DIR, tls.KEY_FILE)
        if tls.needs_new_cert(os.path.exists(cert), os.path.exists(key)):
            subprocess.run(tls.openssl_command(cert, key), check=True, capture_output=True, timeout=60)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv = _TLSServer((self.ap_ip, HTTPS_PORT), _Handler, ctx)
        threading.Thread(target=srv.serve_forever, name="dns-override-https", daemon=True).start()
        return srv

    def _hup(self):
        if self._dnsmasq_pid:
            try:
                os.kill(self._dnsmasq_pid, signal.SIGHUP)   # dnsmasq re-reads addn-hosts
            except ProcessLookupError:
                pass

    def _stop_server(self):
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            finally:
                self._server = None

    # -- API --------------------------------------------------------------

    def attach_dnsmasq(self, pid):
        with self._lock:
            self._dnsmasq_pid = pid

    def reset(self):
        """Default state (off): portal start-up and ap_stop."""
        with self._lock:
            self._stop_server()
            self.enabled, self.host = False, None
            self._write(self.hosts_file, "")
            self._hup()

    def set(self, enabled, host=None):
        with self._lock:
            if not enabled:
                self._stop_server()
                self.enabled, self.host = False, None
                self._write(self.hosts_file, "")
                self._hup()
                logger.info("dns override off")
                return
            if self._server is None:
                self._server = self._make_server()
            self.enabled, self.host = True, host
            try:
                self._write(self.hosts_file, hosts_file_text(True, host, self.ap_ip))
                self._hup()
            except Exception:
                self._stop_server()
                self.enabled, self.host = False, None
                self._write(self.hosts_file, "")
                raise
            logger.info("dns override on: %s -> %s", host, self.ap_ip)

    def status(self):
        with self._lock:
            return {"enabled": self.enabled, "host": self.host,
                    "https": f"{self.ap_ip}:{HTTPS_PORT}" if self._server else None}
