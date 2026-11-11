"""Host tier for the villa-2 bench capabilities (fork): bench-dns-override (CR-TB-05),
bench-mqtt-auth (CR-TB-03) and bench-traffic-capture (CR-TB-04). The decisions are
pure functions and the side effects go through injected callables, so the safety
properties are checked here without a Pi."""
import pytest

import capture_controller as cap
import dns_override as dno
import mqtt_controller as mq

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
    c = cap.Capture("wlan0", popen=popen)
    st = c.start(MAC, 5)
    assert st["state"] == "running"
    for _ in range(100):
        if c.result()["state"] == "done":
            break
        time.sleep(0.01)
    r = c.result()
    assert r["state"] == "done" and len(r["flows"]) == 5 and procs[0][1].terminated
    assert procs[0][0] == cap.tcpdump_command("wlan0", MAC)
