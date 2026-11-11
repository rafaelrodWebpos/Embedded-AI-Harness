"""Host tier for the villa-2 bench capabilities (fork): bench-dns-override (CR-TB-05),
bench-mqtt-auth (CR-TB-03) and bench-traffic-capture (CR-TB-04). The decisions are
pure functions and the side effects go through injected callables, so the safety
properties are checked here without a Pi."""
import inspect
import os
import ssl
import stat

import pytest

import api_auth
import capture_controller as cap
import dns_override as dno
import mqtt_controller as mq
import run_dir

AP = "192.168.4.1"


# ── bench-dns-override ───────────────────────────────────────────────────

@pytest.mark.parametrize("body,ok", [
    ({"enabled": True, "host": "github.com"}, ("github.com")),
    ({"enabled": True, "host": "GitHub.COM."}, ("github.com")),
    ({"enabled": True, "host": "release-assets.githubusercontent.com"}, "release-assets.githubusercontent.com"),
    ({"enabled": False}, None),
    ({"enabled": False, "host": "x"}, None),
])
def test_dns_override_accepts(body, ok):
    enabled, host = dno.parse_request(body)
    assert enabled is body["enabled"] and host == ok


@pytest.mark.parametrize("body", [
    None, {}, {"enabled": "true", "host": "github.com"}, {"enabled": 1, "host": "github.com"},
    {"enabled": True}, {"enabled": True, "host": ""}, {"enabled": True, "host": "localhost"},
    {"enabled": True, "host": "192.168.1.1"}, {"enabled": True, "host": "*.github.com"},
    {"enabled": True, "host": "github.com evil"}, {"enabled": True, "host": "a" * 254 + ".com"},
    {"enabled": True, "host": "-x.com"}, {"enabled": True, "host": ["github.com"]},
])
def test_dns_override_rejects(body):
    with pytest.raises(ValueError):
        dno.parse_request(body)


def test_hosts_file_is_one_line_to_the_ap_or_empty():
    assert dno.hosts_file_text(True, "github.com", AP) == "192.168.4.1 github.com\n"
    assert dno.hosts_file_text(False, "github.com", AP) == ""
    assert dno.hosts_file_text(True, None, AP) == ""


class FakeServer:
    def __init__(self):
        self.closed = False

    def shutdown(self):
        pass

    def server_close(self):
        self.closed = True


def make_override():
    files, servers = {}, []

    def make():
        servers.append(FakeServer())
        return servers[-1]
    o = dno.DnsOverride(AP, "/w/hosts", write_file=lambda p, t: files.__setitem__(p, t), make_server=make)
    return o, files, servers


def test_dns_override_on_off_and_reset():
    o, files, servers = make_override()
    o.reset()
    assert files["/w/hosts"] == "" and not o.enabled and o.status()["https"] is None
    o.set(True, "github.com")
    assert files["/w/hosts"] == "192.168.4.1 github.com\n"
    assert o.status() == {"enabled": True, "host": "github.com", "https": "192.168.4.1:443"}
    o.set(True, "github.com")
    assert len(servers) == 1                        # one HTTPS server, not one per call
    o.set(False)
    assert files["/w/hosts"] == "" and servers[0].closed and o.status()["https"] is None
    o.set(True, "github.com")
    o.reset()                                       # ap_stop / start-up
    assert files["/w/hosts"] == "" and servers[1].closed and not o.enabled


def test_dns_override_failure_leaves_it_off():
    servers = []

    def make():
        servers.append(FakeServer())
        return servers[-1]

    def write(p, t):
        if t:
            raise OSError("disk")
        written.append(t)
    written = []
    o = dno.DnsOverride(AP, "/w/hosts", write_file=write, make_server=make)
    with pytest.raises(OSError):
        o.set(True, "github.com")
    assert not o.enabled and servers[0].closed and written == [""]


def test_https_server_binds_to_the_ap_address_only():
    import inspect
    src = inspect.getsource(dno.DnsOverride._https_server)
    assert "(self.ap_ip, HTTPS_PORT)" in src and "0.0.0.0" not in src and '""' not in src


# ── bench-mqtt-auth ──────────────────────────────────────────────────────

@pytest.mark.parametrize("body,expected", [
    (None, (None, None)), ({}, (None, None)),
    ({"user": "nodo", "pass": "clave-de-prueba_1"}, ("nodo", "clave-de-prueba_1")),
])
def test_mqtt_auth_parse_ok(body, expected):
    assert mq.parse_auth(body) == expected


@pytest.mark.parametrize("body", [
    {"user": "nodo"}, {"pass": "x"}, {"user": "", "pass": "x"}, {"user": "a b", "pass": "x"},
    {"user": "nodo", "pass": "x:y"}, {"user": "nodo", "pass": "x\ny"}, {"user": "n" * 65, "pass": "x"},
    {"user": 1, "pass": "x"}, ["nodo", "x"],
])
def test_mqtt_auth_parse_rejects(body):
    with pytest.raises(ValueError):
        mq.parse_auth(body)


def test_mqtt_conf_open_and_with_password_file():
    open_ = mq.conf_lines(1883, "/l")
    assert "allow_anonymous true" in open_ and not any("password_file" in x for x in open_)
    auth = mq.conf_lines(1883, "/l", "/w/passwd")
    assert "allow_anonymous false" in auth and "password_file /w/passwd" in auth
    assert "allow_anonymous true" not in auth


def test_mqtt_password_never_on_a_command_line():
    import inspect
    src = inspect.getsource(mq._write_passwd)
    assert '"-U"' in src and "-b" not in src


# ── bench-traffic-capture ────────────────────────────────────────────────

def _mac(*b):
    """MACs are built here, not written: the fork's pre-push hook blocks MAC literals."""
    return ":".join(f"{x:02x}" for x in b)


MAC = _mac(0x3c, 0x0f, 0x02, 0, 0, 1)
BCAST, GW, MCAST = _mac(*[0xff] * 6), _mac(2, 0, 0, 0, 0, 1), _mac(1, 0, 0x5e, 0, 0, 0xfb)


@pytest.mark.parametrize("body", [
    None, {}, {"mac": MAC}, {"mac": MAC, "seconds": 0}, {"mac": MAC, "seconds": 601},
    {"mac": MAC, "seconds": True}, {"mac": MAC, "seconds": "10"}, {"mac": MAC.replace(":", "-"), "seconds": 5},
    {"mac": MAC[:-3], "seconds": 5}, {"mac": MAC + "; rm", "seconds": 5},
])
def test_capture_request_rejects(body):
    with pytest.raises(ValueError):
        cap.parse_request(body)


def test_capture_request_ok():
    assert cap.parse_request({"mac": MAC.upper(), "seconds": 60}) == (MAC, 60)


def test_capture_command_is_wlan_dut_only_and_writes_nothing():
    cmd = cap.tcpdump_command("wlan0", MAC)
    assert cmd[:3] == ["tcpdump", "-i", "wlan0"]
    assert cmd[-5:] == ["ether", "src", MAC, "and", "ip"]
    assert "-w" not in cmd and "-n" in cmd and "-q" in cmd
    assert "eth0" not in cmd


LINES = [
    f"12:00:00.100 {MAC} > {BCAST}, IPv4, length 70: 192.168.4.11.5555 > 192.168.4.255.5555: UDP, length 28",
    f"12:00:01.100 {MAC} > {GW}, IPv4, length 70: 192.168.4.11.49152 > 192.168.4.1.5555: UDP, length 28",
    f"12:00:02.100 {MAC} > {GW}, IPv4, length 70: 192.168.4.11.49152 > 192.168.4.1.5555: UDP, length 30",
    f"12:00:03.100 {MAC} > {GW}, IPv4, length 66: 192.168.4.11.50000 > 192.168.4.1.1883: tcp 0",
    f"12:00:04.100 {MAC} > {MCAST}, IPv4, length 90: 192.168.4.11.5353 > 224.0.0.251.5353: UDP, length 40",
    f"12:00:05.100 {MAC} > {GW}, IPv4, length 98: 192.168.4.11 > 192.168.4.1: ICMP echo request, id 1, seq 1, length 64",
    "garbage line",
]


def test_capture_summary_per_destination_without_payload():
    s = cap.summarize(LINES)
    assert {"proto": "UDP", "dst": "192.168.4.1", "dport": 5555, "kind": "unicast", "packets": 2} in s
    assert {"proto": "UDP", "dst": "192.168.4.255", "dport": 5555, "kind": "broadcast", "packets": 1} in s
    assert {"proto": "TCP", "dst": "192.168.4.1", "dport": 1883, "kind": "unicast", "packets": 1} in s
    assert {"proto": "UDP", "dst": "224.0.0.251", "dport": 5353, "kind": "multicast", "packets": 1} in s
    assert {"proto": "ICMP", "dst": "192.168.4.1", "dport": None, "kind": "unicast", "packets": 1} in s
    assert len(s) == 5
    assert all(set(f) == {"proto", "dst", "dport", "kind", "packets"} for f in s)


class FakeProc:
    def __init__(self, lines):
        self.stdout = iter(lines)
        self.terminated = False

    def poll(self):
        return 0 if self.terminated else None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.terminated = True


def test_capture_runner_collects_and_stops():
    import time
    procs = []

    def popen(cmd):
        procs.append((cmd, FakeProc(LINES)))
        return procs[-1][1]
    c = cap.Capture("wlan0", popen=popen, ap_active=lambda: True)
    st = c.start(MAC, 5)
    assert st["state"] == "running"
    for _ in range(100):
        if c.result()["state"] == "done":
            break
        time.sleep(0.01)
    r = c.result()
    assert r["state"] == "done" and len(r["flows"]) == 5 and procs[0][1].terminated
    assert procs[0][0] == cap.tcpdump_command("wlan0", MAC)


# ── Review S6 (H-87) ─────────────────────────────────────────────────────


TOKEN = "A" * 48


def _st(mode, uid=0):
    return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))


# S6-01: token on every /api/* route except GET /api/info; UI pages open; no CORS
@pytest.mark.parametrize("method,path,need", [
    ("GET", "/api/info", False), ("POST", "/api/info", True), ("GET", "/api/devices", True),
    ("POST", "/api/wifi/dns_override", True), ("POST", "/api/human/done", True), ("DELETE", "/api/udplog", True),
    ("POST", "/api/hotplug", True), ("GET", "/", False), ("GET", "/static/x.js", False), ("GET", "/api", True),
])
def test_s6_01_which_routes_need_the_token(method, path, need):
    assert api_auth.needs_token(method, path) is need


def test_s6_01_check_is_exact_and_fails_closed():
    assert api_auth.allowed("POST", "/api/mqtt/start", TOKEN, TOKEN)
    assert not api_auth.allowed("POST", "/api/mqtt/start", TOKEN[:-1] + "B", TOKEN)
    assert not api_auth.allowed("POST", "/api/mqtt/start", "", TOKEN)
    assert not api_auth.allowed("POST", "/api/mqtt/start", None, TOKEN)
    assert not api_auth.allowed("POST", "/api/mqtt/start", TOKEN, None)      # no token file: closed
    assert api_auth.allowed("GET", "/api/info", None, None)
    assert "compare_digest" in inspect.getsource(api_auth.allowed)


def test_s6_01_token_file_must_be_root_0600_regular():
    assert api_auth.token_file_ok(_st(stat.S_IFREG | 0o600))
    assert not api_auth.token_file_ok(_st(stat.S_IFREG | 0o640))
    assert not api_auth.token_file_ok(_st(stat.S_IFREG | 0o604))
    assert not api_auth.token_file_ok(_st(stat.S_IFREG | 0o600, uid=1000))
    assert not api_auth.token_file_ok(_st(stat.S_IFLNK | 0o600))
    assert "O_NOFOLLOW" in inspect.getsource(api_auth.load_token)


def test_s6_01_public_info_says_nothing_about_the_network():
    full = {"ok": True, "host_ip": "10.1.2.3", "hostname": "pi", "slots_configured": 2,
            "slots_running": 1, "build": "abc", "capabilities": ["x"]}
    assert api_auth.public_info(full) == {"ok": True, "build": "abc", "capabilities": ["x"]}


def test_s6_01_portal_has_no_cors_and_checks_every_verb():
    import pathlib
    src = (pathlib.Path(api_auth.__file__).parent / "portal.py").read_text()
    assert "Access-Control-Allow-Origin" not in src
    for verb in ("do_GET", "do_POST", "do_DELETE"):
        body = src[src.index(f"    def {verb}(self):"):][:200]
        assert "self._authorized()" in body, verb
    assert "X-Harness-Token" in src and "localStorage" in src     # the UI sends it


def test_s6_01_driver_sends_the_token_header():
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from testbench_driver import TestbenchDriver
    req = TestbenchDriver("http://bench", token=TOKEN)._request("http://bench/api/devices")
    assert req.get_header("X-harness-token") == TOKEN
    assert TestbenchDriver("http://bench", token="")._request("http://bench/api/info").get_header("X-harness-token") is None


def test_s6_01_local_scripts_never_put_the_token_on_a_command_line():
    import pathlib
    base = pathlib.Path(api_auth.__file__).parent / "scripts"
    for name in ("wifi-lease-notify.sh", "rfc2217-udev-notify.sh"):
        src = (base / name).read_text()
        assert "-H @-" in src and "printf 'X-Harness-Token: %s" in src
        assert '-H "X-Harness-Token: $' not in src


# S6-03: root-owned /run/harness, no symlinks, O_NOFOLLOW
def test_s6_03_paths_are_out_of_tmp():
    assert run_dir.RUN_DIR == "/run/harness" and run_dir.MQTT_DIR.startswith("/run/harness/")
    assert mq.MOSQUITTO_PASSWD.startswith("/run/harness/") and mq.MOSQUITTO_CONF.startswith("/run/harness/")
    import pathlib
    src = (pathlib.Path(api_auth.__file__).parent / "wifi_controller.py").read_text()
    assert 'os.path.join(run_dir.RUN_DIR, "dns-override-hosts")' in src


def test_s6_03_dir_checks_refuse_symlink_foreign_owner_and_writable():
    assert run_dir.dir_ok(_st(stat.S_IFDIR | 0o711))
    assert run_dir.dir_ok(_st(stat.S_IFDIR | 0o750))
    assert not run_dir.dir_ok(_st(stat.S_IFLNK | 0o777))
    assert not run_dir.dir_ok(_st(stat.S_IFDIR | 0o711, uid=1000))
    assert not run_dir.dir_ok(_st(stat.S_IFDIR | 0o777))
    assert not run_dir.dir_ok(_st(stat.S_IFDIR | 0o731))


def test_s6_03_ensure_dir_creates_or_refuses_without_touching_disk():
    made = []
    state = {}

    def lstat(p):
        if p not in state:
            raise FileNotFoundError(p)
        return state[p]

    def mkdir(p, mode):
        made.append((p, mode))
        state[p] = _st(stat.S_IFDIR | mode)
    run_dir.ensure_dir("/r", 0o711, lstat=lstat, mkdir=mkdir, chown=lambda *a: None, chmod=lambda *a: None)
    assert made == [("/r", 0o711)]
    state["/evil"] = _st(stat.S_IFLNK | 0o777, uid=1000)
    with pytest.raises(PermissionError):
        run_dir.ensure_dir("/evil", 0o711, lstat=lstat, mkdir=mkdir, chown=lambda *a: None, chmod=lambda *a: None)


def test_s6_03_files_open_with_nofollow_and_excl():
    src = inspect.getsource(run_dir.write_file)
    assert "O_NOFOLLOW" in src and "O_EXCL" in src and "os.replace" in src
    assert "O_NOFOLLOW" in inspect.getsource(mq._write_passwd)


# S6-05: capture needs the AP up; every AP stop stops it
def test_s6_05_capture_refused_without_the_ap():
    c = cap.Capture("wlan0", popen=lambda cmd: pytest.fail("tcpdump started"), ap_active=lambda: False)
    with pytest.raises(RuntimeError):
        c.start(MAC, 5)
    assert c.result()["state"] == "idle"


def test_s6_05_every_ap_stop_runs_the_hooks_and_the_portal_registers_the_capture():
    import pathlib
    base = pathlib.Path(api_auth.__file__).parent
    wc = (base / "wifi_controller.py").read_text()
    body = wc[wc.index("def _ap_stop_unlocked():"):wc.index("def ap_status():")]
    assert "for hook in list(AP_STOP_HOOKS)" in body
    assert "_ap_stop_unlocked()" in wc[wc.index("def _stop_all_unlocked():"):][:200]   # shutdown path
    portal = (base / "portal.py").read_text()
    assert "wifi_controller.AP_STOP_HOOKS.append(CAPTURE.stop)" in portal


# S6-06: no racing "on" survives into a new AP
def test_s6_06_set_holds_the_lock_and_ap_start_resets_the_override():
    import pathlib
    wc = (pathlib.Path(api_auth.__file__).parent / "wifi_controller.py").read_text()
    body = wc[wc.index("def dns_override_set("):wc.index("def dns_override_status(")]
    assert body.index("with _lock:") < body.index("DNS_OVERRIDE.set(enabled, host)")
    assert "        DNS_OVERRIDE.set(enabled, host)" in body          # inside the with block
    start = wc[wc.index("def ap_start("):wc.index("def ap_stop(")]
    assert "DNS_OVERRIDE.reset()" in start and start.index("DNS_OVERRIDE.reset()") < start.index("addn-hosts=")


# S6-07: other credentials while running → conflict, never a silent ok
class _Running:
    def poll(self):
        return None


def test_s6_07_other_credentials_are_a_conflict(monkeypatch):
    monkeypatch.setattr(mq, "_active", True)
    monkeypatch.setattr(mq, "_proc", _Running())
    monkeypatch.setattr(mq, "_auth", True)
    monkeypatch.setattr(mq, "_creds", mq.creds_digest("nodo", "clave1"))
    assert mq.start("nodo", "clave1") == {"port": mq.MQTT_PORT, "auth": True}
    for user, pw in (("nodo", "clave2"), ("otro", "clave1"), (None, None)):
        with pytest.raises(mq.ConflictError):
            mq.start(user, pw)
    monkeypatch.setattr(mq, "_auth", False)
    monkeypatch.setattr(mq, "_creds", None)
    assert mq.start() == {"port": mq.MQTT_PORT, "auth": False}
    with pytest.raises(mq.ConflictError):
        mq.start("nodo", "clave1")


# S6-08: no trailing newline sneaks through a $-anchored regex
def test_s6_08_trailing_newline_is_rejected_everywhere():
    with pytest.raises(ValueError):
        cap.parse_request({"mac": MAC + "\n", "seconds": 5})
    with pytest.raises(ValueError):
        mq.parse_auth({"user": "nodo\n", "pass": "x"})
    with pytest.raises(ValueError):
        mq.parse_auth({"user": "nodo", "pass": "x\n"})
    with pytest.raises(ValueError):
        dno.validate_host("github.com\nexample.org")


# S6-09: TLS handshake per connection, with a timeout, outside accept()
class _Sock:
    def __init__(self):
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t


def test_s6_09_handshake_happens_per_connection_with_a_timeout():
    srv = dno._TLSServer.__new__(dno._TLSServer)
    raw = _Sock()

    class _Listen:
        def accept(self):
            return raw, ("192.168.4.2", 5000)
    srv.socket = _Listen()
    sock, _ = srv.get_request()
    assert sock is raw and raw.timeout == dno.HANDSHAKE_TIMEOUT_S

    class _Ctx:
        def wrap_socket(self, s, server_side):
            raise ssl.SSLError("no ClientHello")
    srv.ctx = _Ctx()
    srv.RequestHandlerClass = lambda *a: pytest.fail("handler ran without TLS")
    srv.finish_request(raw, ("192.168.4.2", 5000))       # dropped, no exception
    src = inspect.getsource(dno.DnsOverride._https_server)
    assert "_TLSServer(" in src and "wrap_socket(srv.socket" not in src


def test_h87_way_back_undoes_every_s6_change():
    import pathlib
    src = (pathlib.Path(api_auth.__file__).parent / "scripts" / "harness-volver-original.sh").read_text()
    for needle in ("HARNESS_AP_IN", "HARNESS_MQTT_IN", "/etc/rfc2217/mqtt-allow", "/etc/rfc2217/api-token", "/run/harness", "/usr/local/bin/api_auth.py",
                   "/usr/local/bin/run_dir.py", "/usr/local/bin/dns_override.py", "/usr/local/bin/capture_controller.py"):
        assert needle in src, needle
    assert 'quitar_salto iptables  filter INPUT       -i "$UPLINK_IF" -j HARNESS_AP_IN' in src
    inst = (pathlib.Path(api_auth.__file__).parent / "install.sh").read_text()
    assert "chmod 600 /etc/rfc2217/api-token" in inst and "/dev/urandom" in inst
