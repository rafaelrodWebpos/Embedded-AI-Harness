"""Host tier for AP egress (bench-ap-internet, bench-sntp-block): the rule sets
are pure data and the side effects go through an injected runner, so the safety
properties are checked here without a Pi."""
import ipaddress

import pytest

import ap_egress as eg

WLAN, UP, SUB = "wlan0", "eth0", "192.168.4.0/24"


def rules(internet, sntp=False):
    return eg.fwd_rules(internet, sntp, WLAN, UP, SUB)


# ── Rule sets ────────────────────────────────────────────────────────────

def test_off_is_a_single_drop():
    assert rules(False) == [["-j", "DROP"]]
    assert rules(False, sntp=True) == [["-j", "DROP"]]
    assert eg.nat_rules(False, UP, SUB) == []


def test_on_exact_order():
    r = rules(True)
    assert r[0] == ["-o", WLAN, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
    assert r[1] == ["-o", WLAN, "-j", "DROP"]
    assert r[2] == ["-d", SUB, "-j", "ACCEPT"]
    assert r[3:3 + len(eg.BLOCKED_DESTINATIONS)] == [["-d", n, "-j", "DROP"] for n in eg.BLOCKED_DESTINATIONS]
    assert r[-2] == ["-o", UP, "-j", "ACCEPT"]
    assert r[-1] == ["-j", "DROP"]
    assert len(r) == 3 + len(eg.BLOCKED_DESTINATIONS) + 2
    assert eg.nat_rules(True, UP, SUB) == [["-s", SUB, "-o", UP, "-j", "MASQUERADE"]]


def test_sntp_block_comes_before_any_accept_of_new_traffic():
    r = rules(True, sntp=True)
    i = r.index(["-p", "udp", "-m", "udp", "--dport", "123", "-j", "DROP"])
    accepts = [k for k, x in enumerate(r) if x[-1] == "ACCEPT" and "conntrack" not in x]
    assert i < min(accepts)
    assert ["-p", "udp", "-m", "udp", "--dport", "123", "-j", "DROP"] not in rules(True, sntp=False)


@pytest.mark.parametrize("net", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                 "100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4"])
def test_every_private_range_is_dropped_before_the_uplink_accept(net):
    r = rules(True)
    up = r.index(["-o", UP, "-j", "ACCEPT"])
    assert r.index(["-d", net, "-j", "DROP"]) < up


def _first_verdict(r, dst, out_if, proto="tcp", dport=443):
    """Tiny evaluator of the chain for a NEW packet from the AP (-i wlan0)."""
    for x in r:
        if "-o" in x and x[x.index("-o") + 1] != out_if:
            continue
        if "conntrack" in x:
            continue                     # a NEW packet never matches ESTABLISHED
        if "-d" in x and ipaddress.ip_address(dst) not in ipaddress.ip_network(x[x.index("-d") + 1]):
            continue
        if "-p" in x and (x[x.index("-p") + 1] != proto or int(x[x.index("--dport") + 1]) != dport):
            continue
        return x[-1]
    return "FALLTHROUGH"


@pytest.mark.parametrize("dst", ["192.168.1.1", "10.1.2.3", "172.20.0.5",
                                 "169.254.1.1", "100.64.0.1", "127.0.0.1", "239.255.255.250"])
def test_lan_and_special_destinations_are_never_reachable(dst):
    for sntp in (False, True):
        assert _first_verdict(rules(True, sntp), dst, UP) == "DROP"
        assert _first_verdict(rules(False, sntp), dst, UP) == "DROP"


@pytest.mark.parametrize("dst", ["1.1.1.1", "140.82.112.3", "162.159.200.1"])
def test_public_destinations_pass_only_when_on(dst):
    assert _first_verdict(rules(True), dst, UP) == "ACCEPT"
    assert _first_verdict(rules(False), dst, UP) == "DROP"


def test_sntp_to_a_public_server_is_dropped_only_when_blocked():
    assert _first_verdict(rules(True, sntp=False), "162.159.200.1", UP, "udp", 123) == "ACCEPT"
    assert _first_verdict(rules(True, sntp=True), "162.159.200.1", UP, "udp", 123) == "DROP"
    assert _first_verdict(rules(True, sntp=True), "162.159.200.1", UP, "udp", 53) == "ACCEPT"


def test_other_interfaces_than_the_uplink_are_dropped():
    assert _first_verdict(rules(True), "1.1.1.1", "usb0") == "DROP"


def test_nothing_new_enters_the_ap_from_outside():
    r = rules(True)
    assert r.index(["-o", WLAN, "-j", "DROP"]) == 1


def test_restore_script_flushes_only_its_own_chains():
    s = eg.restore_script(True, True, WLAN, UP, SUB)
    assert s.splitlines()[0:2] == ["*filter", f":{eg.CHAIN_FWD} - [0:0]"]
    assert f"*nat\n:{eg.CHAIN_NAT} - [0:0]\n" in s
    assert s.count("COMMIT") == 2
    for line in s.splitlines():
        assert line in ("*filter", "*nat", "COMMIT") or line.startswith((":HARNESS_AP_", ":HARNESS_MQTT_")) \
            or line.startswith(f"-A {eg.CHAIN_FWD} ") or line.startswith(f"-A {eg.CHAIN_NAT} ") \
            or line.startswith(f"-A {eg.CHAIN_IN} ") or line.startswith(f"-A {eg.CHAIN_MQTT} ")
    # S6-04: the INPUT chain drops the AP subnet from the uplink, internet on or off
    for internet in (False, True):
        assert f"-A {eg.CHAIN_IN} -d {SUB} -j DROP" in eg.restore_script(internet, False, WLAN, UP, SUB).splitlines()
    assert eg.restore6_script() == f"*filter\n:{eg.CHAIN_FWD6} - [0:0]\n-A {eg.CHAIN_FWD6} -j DROP\nCOMMIT\n"


def test_dns_servers_are_public_only_and_empty_when_off():
    assert eg.servers_file_text(False) == ""
    for line in eg.servers_file_text(True).splitlines():
        ip = ipaddress.ip_address(line.split("=", 1)[1])
        assert ip.is_global


@pytest.mark.parametrize("body,key,ok", [
    ({"enabled": True}, "enabled", True), ({"enabled": False}, "enabled", True),
    ({"enabled": "false"}, "enabled", False), ({"enabled": 1}, "enabled", False),
    ({}, "enabled", False), (None, "enabled", False), ({"blocked": True}, "blocked", True),
])
def test_post_bodies_take_a_json_boolean_only(body, key, ok):
    if ok:
        assert eg.parse_flag(body, key) is body[key]
    else:
        with pytest.raises(ValueError):
            eg.parse_flag(body, key)


# ── Side effects through a fake runner ───────────────────────────────────

class FakeHost:
    """Records commands; keeps the hook rules and the ip_forward value."""

    def __init__(self, forward="0"):
        self.cmds, self.stdin, self.hooks = [], [], set()
        self.forward = forward
        self.files = {}

    def run(self, cmd, stdin=None):
        self.cmds.append(cmd)
        if stdin is not None:
            self.stdin.append((cmd[0], stdin))
        if cmd[0] in ("iptables", "ip6tables") and "-C" in cmd:
            return (0 if tuple(cmd) in self.hooks else 1), "", ""
        if cmd[0] in ("iptables", "ip6tables") and "-I" in cmd:
            k = cmd.index("-I")
            self.hooks.add(tuple(cmd[:k] + ["-C", cmd[k + 1]] + cmd[k + 3:]))
            return 0, "", ""
        if cmd[0] == "sysctl":
            self.forward = cmd[-1].split("=")[1]
        return 0, "", ""

    def read(self, path):
        assert path == "/proc/sys/net/ipv4/ip_forward"
        return self.forward + "\n"

    def write(self, path, text):
        self.files[path] = text


def make(host):
    return eg.Egress(WLAN, UP, SUB, "/w/dns-servers", run=host.run, read_file=host.read, write_file=host.write)


def test_reset_installs_drop_chains_and_hooks_once():
    h = FakeHost()
    e = make(h)
    e.reset()
    e.reset()
    inserts = [c for c in h.cmds if "-I" in c]
    assert len(inserts) == len(eg.hook_rules(WLAN))          # idempotent: hooks inserted once
    assert all(c[c.index("-I") + 2] == "1" for c in inserts)  # at position 1
    assert h.stdin[0] == ("iptables-restore", eg.restore_script(False, False, WLAN, UP, SUB))
    assert h.files["/w/dns-servers"] == ""
    assert h.forward == "0"
    assert not e.internet and not e.sntp_blocked


def test_chains_are_restored_before_the_jumps_are_inserted():
    h = FakeHost()
    make(h).reset()
    first_restore = next(i for i, c in enumerate(h.cmds) if c[0] == "iptables-restore")
    first_insert = next(i for i, c in enumerate(h.cmds) if "-I" in c)
    assert first_restore < first_insert


def test_internet_on_then_off_restores_ip_forward():
    h = FakeHost(forward="0")
    e = make(h)
    e.reset()
    e.set_internet(True)
    assert h.forward == "1"
    assert h.stdin[-2] == ("iptables-restore", eg.restore_script(True, False, WLAN, UP, SUB))
    assert h.files["/w/dns-servers"] == eg.servers_file_text(True)
    e.set_internet(False)
    assert h.forward == "0"
    assert h.stdin[-2] == ("iptables-restore", eg.restore_script(False, False, WLAN, UP, SUB))
    assert h.files["/w/dns-servers"] == ""


def test_ip_forward_already_on_is_left_on():
    h = FakeHost(forward="1")
    e = make(h)
    e.set_internet(True)
    e.set_internet(False)
    assert h.forward == "1"


def test_reset_clears_sntp_block_and_internet():
    h = FakeHost()
    e = make(h)
    e.set_internet(True)
    e.set_sntp_block(True)
    assert h.stdin[-2] == ("iptables-restore", eg.restore_script(True, True, WLAN, UP, SUB))
    e.reset()
    assert not e.internet and not e.sntp_blocked
    assert h.stdin[-2] == ("iptables-restore", eg.restore_script(False, False, WLAN, UP, SUB))
    assert h.forward == "0"


def test_status_compares_the_listing_with_the_expected_rules():
    h = FakeHost()
    e = make(h)
    e.set_internet(True)
    good = "\n".join(eg.expected_listing(True, False, WLAN, UP, SUB))
    orig = h.run

    good_in = "\n".join([f"-N {eg.CHAIN_IN}", f"-A {eg.CHAIN_IN} -d {SUB} -j DROP"])

    def run(cmd, stdin=None):
        if cmd[:3] == ["iptables", "-w", "-S"]:
            if cmd[3] == eg.CHAIN_MQTT:
                return 0, f"-N {eg.CHAIN_MQTT}\n-A {eg.CHAIN_MQTT} -j DROP", ""
            return 0, (good_in if cmd[3] == eg.CHAIN_IN else good), ""
        return orig(cmd, stdin)
    e._run = run
    st = e.status()
    assert st["internet"] is True and st["lan_blocked"] is True and st["rules_ok"] is True
    e._run = lambda cmd, stdin=None: (0, "-N HARNESS_AP_FWD\n-A HARNESS_AP_FWD -j ACCEPT", "") \
        if cmd[:3] == ["iptables", "-w", "-S"] else orig(cmd, stdin)
    assert e.status()["rules_ok"] is False


def test_a_failing_restore_raises():
    h = FakeHost()
    e = make(h)
    e._run = lambda cmd, stdin=None: (1, "", "boom") if cmd[0] == "iptables-restore" else h.run(cmd, stdin)
    with pytest.raises(RuntimeError):
        e.set_internet(True)


# ── wifi_controller wiring ───────────────────────────────────────────────

def test_wifi_controller_has_no_unfiltered_nat_left():
    import pathlib
    src = (pathlib.Path(eg.__file__).parent / "wifi_controller.py").read_text()
    assert "MASQUERADE" not in src
    assert "iptables" not in src
    assert "ip_forward" not in src
    assert "_enable_nat" not in src


def test_a_failing_sysctl_leaves_egress_closed():
    h = FakeHost()
    e = make(h)
    e.reset()
    orig = h.run
    e._run = lambda cmd, stdin=None: (1, "", "denied") if cmd[0] == "sysctl" else orig(cmd, stdin)
    with pytest.raises(RuntimeError):
        e.set_internet(True)
    assert e.internet is False
    assert h.stdin[-2] == ("iptables-restore", eg.restore_script(False, False, WLAN, UP, SUB))


def test_s6_04_input_hook_on_the_uplink_at_position_1():
    hooks = eg.hook_rules(WLAN, UP)
    assert ("iptables", "filter", "INPUT", ["-i", UP, "-j", eg.CHAIN_IN]) in hooks
    h = FakeHost()
    make(h).reset()
    ins = [c for c in h.cmds if "-I" in c and "INPUT" in c]
    assert ins and ins[0][ins[0].index("-I") + 2] == "1" and ins[0][-1] == eg.CHAIN_IN
    assert eg.in_rules(SUB) == [["-d", SUB, "-j", "DROP"]]


# S6-02 (H-87): on the uplink only the laptop reaches the test broker
@pytest.mark.parametrize("text,ip", [
    ("10.0.0.7\n", "10.0.0.7"), ("# laptop\n10.0.0.7\n", "10.0.0.7"), ("", None), ("10.0.0.7\n10.0.0.8", None),
    ("0.0.0.0", None), ("10.0.0.255", None), ("224.0.0.1", None), ("127.0.0.1", None), ("10.0.0.0/24", None),
    ("laptop", None), ("10.0.0.7 # x", None),
])
def test_s6_02_allow_file_is_one_unicast_host(text, ip):
    assert eg.parse_mqtt_allow(text) == ip


def test_s6_02_mqtt_chain_accepts_only_the_laptop_then_drops():
    assert eg.mqtt_rules("10.0.0.7") == [["-s", "10.0.0.7", "-j", "ACCEPT"], ["-j", "DROP"]]
    assert eg.mqtt_rules(None) == [["-j", "DROP"]]          # fail closed
    hook = ("iptables", "filter", "INPUT", ["-i", UP, "-p", "tcp", "--dport", "1883", "-j", eg.CHAIN_MQTT])
    assert hook in eg.hook_rules(WLAN, UP)
    sc = eg.restore_script(False, False, WLAN, UP, SUB, "10.0.0.7").splitlines()
    assert sc.index(f"-A {eg.CHAIN_MQTT} -s 10.0.0.7 -j ACCEPT") < sc.index(f"-A {eg.CHAIN_MQTT} -j DROP")


def test_s6_02_egress_reads_the_allow_file_at_every_apply():
    h = FakeHost()
    files = {"/etc/allow": "10.0.0.7\n"}

    def read(path):
        if path == "/etc/allow":
            if path not in files:
                raise FileNotFoundError(path)
            return files[path]
        return h.read(path)
    e = eg.Egress(WLAN, UP, SUB, "/w/dns-servers", run=h.run, read_file=read, write_file=h.write,
                  mqtt_allow_file="/etc/allow")
    e.reset()
    assert f"-A {eg.CHAIN_MQTT} -s 10.0.0.7 -j ACCEPT" in h.stdin[-2][1]
    del files["/etc/allow"]                     # file gone: read fails -> drop all
    e.reset()
    assert f"-A {eg.CHAIN_MQTT} -s" not in h.stdin[-2][1] and f"-A {eg.CHAIN_MQTT} -j DROP" in h.stdin[-2][1]
