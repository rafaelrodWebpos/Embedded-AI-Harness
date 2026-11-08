"""AP egress control — internet access for SoftAP clients, never the LAN.

Capabilities `bench-ap-internet` (switch the AP's internet egress on and off by
API, and report it) and `bench-sntp-block` (block and unblock UDP/123 from the
AP network on demand).

Safety model
------------
* Default is OFF: at portal start-up and on every `ap_stop` egress is switched
  off and the SNTP block is cleared.
* Everything lives in dedicated chains hooked at position 1 of FORWARD (IPv4)
  and FORWARD (IPv6), ahead of any older rule, so a stale ACCEPT left by an
  older portal can never let AP traffic through:

    HARNESS_AP_FWD   filter, entered for -i <wlan> and -o <wlan>
    HARNESS_AP_NAT   nat, hooked from POSTROUTING (MASQUERADE only while on)
    HARNESS_AP_FWD6  ip6 filter, always DROP (the AP serves no IPv6)

* With egress ON, traffic from the AP may leave by the uplink only towards
  public addresses: every private, link-local, CGNAT, loopback, multicast and
  reserved range is dropped first, except the AP's own subnet. Nothing new may
  enter the AP from outside; only replies (ESTABLISHED,RELATED) come back.
* With egress OFF the chain is a single DROP: the AP is an island even if some
  other code sets net.ipv4.ip_forward=1.
* Chains are rewritten atomically with `iptables-restore --noflush`, so there is
  no window in which the chain is empty.
* DNS for AP clients goes through dnsmasq on the Pi; its upstream servers come
  from a `servers-file` that is public resolvers while egress is on and empty
  while off (dnsmasq re-reads it on SIGHUP). The LAN's resolver is never used.

The rule sets are produced by pure functions (`fwd_rules`, `nat_rules`,
`restore_script`) so the host tier can check them without a Pi.
"""
import logging
import os
import signal
import subprocess
import threading

logger = logging.getLogger("ap_egress")

CHAIN_FWD = "HARNESS_AP_FWD"
CHAIN_NAT = "HARNESS_AP_NAT"
CHAIN_FWD6 = "HARNESS_AP_FWD6"

# Destinations an AP client may never reach through the uplink (RFC 1918,
# RFC 6598, RFC 3927, loopback, "this network", multicast and reserved).
BLOCKED_DESTINATIONS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

PUBLIC_DNS = ("1.1.1.1", "8.8.8.8")
SNTP_PORT = "123"


# ── Pure rule builders ────────────────────────────────────────────────────

def fwd_rules(internet: bool, sntp_blocked: bool, wlan: str, uplink: str,
              ap_subnet: str) -> list:
    """Rules of HARNESS_AP_FWD, in order, as argument lists after `-A CHAIN`."""
    if not internet:
        return [["-j", "DROP"]]
    rules = [
        # Replies to connections the AP clients opened; nothing new comes in.
        ["-o", wlan, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ["-o", wlan, "-j", "DROP"],
    ]
    if sntp_blocked:
        rules.append(["-p", "udp", "-m", "udp", "--dport", SNTP_PORT, "-j", "DROP"])
    # The AP's own subnet is allowed explicitly before the private ranges drop.
    rules.append(["-d", ap_subnet, "-j", "ACCEPT"])
    rules += [["-d", net, "-j", "DROP"] for net in BLOCKED_DESTINATIONS]
    rules.append(["-o", uplink, "-j", "ACCEPT"])
    rules.append(["-j", "DROP"])
    return rules


def nat_rules(internet: bool, uplink: str, ap_subnet: str) -> list:
    """Rules of HARNESS_AP_NAT, as argument lists after `-A CHAIN`."""
    if not internet:
        return []
    return [["-s", ap_subnet, "-o", uplink, "-j", "MASQUERADE"]]


def hook_rules(wlan: str) -> list:
    """Jumps into the dedicated chains: (binary, table, chain, args)."""
    return [
        ("iptables", "filter", "FORWARD", ["-i", wlan, "-j", CHAIN_FWD]),
        ("iptables", "filter", "FORWARD", ["-o", wlan, "-j", CHAIN_FWD]),
        ("iptables", "nat", "POSTROUTING", ["-j", CHAIN_NAT]),
        ("ip6tables", "filter", "FORWARD", ["-i", wlan, "-j", CHAIN_FWD6]),
        ("ip6tables", "filter", "FORWARD", ["-o", wlan, "-j", CHAIN_FWD6]),
    ]


def restore_script(internet: bool, sntp_blocked: bool, wlan: str, uplink: str,
                   ap_subnet: str) -> str:
    """Input for `iptables-restore --noflush`: declaring a chain flushes only that
    chain, and the whole table is committed at once."""
    out = ["*filter", f":{CHAIN_FWD} - [0:0]"]
    out += [" ".join(["-A", CHAIN_FWD] + r)
            for r in fwd_rules(internet, sntp_blocked, wlan, uplink, ap_subnet)]
    out += ["COMMIT", "*nat", f":{CHAIN_NAT} - [0:0]"]
    out += [" ".join(["-A", CHAIN_NAT] + r) for r in nat_rules(internet, uplink, ap_subnet)]
    out.append("COMMIT")
    return "\n".join(out) + "\n"


def restore6_script() -> str:
    return "\n".join(["*filter", f":{CHAIN_FWD6} - [0:0]", f"-A {CHAIN_FWD6} -j DROP", "COMMIT"]) + "\n"


def expected_listing(internet: bool, sntp_blocked: bool, wlan: str, uplink: str,
                     ap_subnet: str) -> list:
    """What `iptables -S HARNESS_AP_FWD` prints for this state (for rules_ok)."""
    return [f"-N {CHAIN_FWD}"] + [" ".join(["-A", CHAIN_FWD] + r)
                                  for r in fwd_rules(internet, sntp_blocked, wlan, uplink, ap_subnet)]


def servers_file_text(internet: bool) -> str:
    return "".join(f"server={s}\n" for s in PUBLIC_DNS) if internet else ""


# ── Applying them ─────────────────────────────────────────────────────────

class Egress:
    """State and side effects. `run` and `fs` are injectable for the host tier."""

    def __init__(self, wlan: str, uplink: str, ap_subnet: str, servers_file: str,
                 run=None, read_file=None, write_file=None):
        self.wlan, self.uplink, self.ap_subnet = wlan, uplink, ap_subnet
        self.servers_file = servers_file
        self.internet = False
        self.sntp_blocked = False
        self._saved_forward = None
        self._dnsmasq_pid = None
        self._lock = threading.Lock()
        self._run = run or self._subprocess_run
        self._read = read_file or self._read_file
        self._write = write_file or self._write_file

    # -- low level ----------------------------------------------------------

    @staticmethod
    def _subprocess_run(cmd, stdin=None):
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=False)
        return r.returncode, r.stdout, r.stderr

    @staticmethod
    def _read_file(path):
        with open(path) as f:
            return f.read()

    @staticmethod
    def _write_file(path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, path)

    def _ensure_hooks(self):
        for binary, table, chain, args in hook_rules(self.wlan):
            if self._run([binary, "-w", "-t", table, "-C", chain] + args)[0] != 0:
                rc, _, err = self._run([binary, "-w", "-t", table, "-I", chain, "1"] + args)
                if rc != 0:
                    raise RuntimeError(f"{binary} -I {chain}: {err.strip()}")

    def _apply_rules(self):
        rc, _, err = self._run(["iptables-restore", "-w", "--noflush"],
                               stdin=restore_script(self.internet, self.sntp_blocked, self.wlan,
                                                    self.uplink, self.ap_subnet))
        if rc != 0:
            raise RuntimeError(f"iptables-restore: {err.strip()}")
        rc, _, err = self._run(["ip6tables-restore", "-w", "--noflush"], stdin=restore6_script())
        if rc != 0:
            raise RuntimeError(f"ip6tables-restore: {err.strip()}")
        # Chains first (a jump to a missing chain is refused), then the jumps.
        self._ensure_hooks()

    def _set_forward(self, on: bool):
        path = "/proc/sys/net/ipv4/ip_forward"
        if on:
            if self._saved_forward is None:
                self._saved_forward = self._read(path).strip() or "0"
            self._sysctl("1")
        elif self._saved_forward is not None:
            self._sysctl(self._saved_forward)
            self._saved_forward = None

    def _sysctl(self, value):
        rc, _, err = self._run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"])
        if rc != 0:
            raise RuntimeError(f"sysctl ip_forward={value}: {err.strip()}")

    def _update_dns(self):
        self._write(self.servers_file, servers_file_text(self.internet))
        if self._dnsmasq_pid:
            try:
                os.kill(self._dnsmasq_pid, signal.SIGHUP)
            except ProcessLookupError:
                pass

    # -- API ------------------------------------------------------------------

    def attach_dnsmasq(self, pid):
        """Called by wifi_controller after it starts dnsmasq for the AP."""
        with self._lock:
            self._dnsmasq_pid = pid

    def reset(self):
        """Default state: egress off, SNTP not blocked. Portal start-up and ap_stop."""
        with self._lock:
            self.internet = False
            self.sntp_blocked = False
            self._apply_rules()
            self._set_forward(False)
            self._update_dns()
            logger.info("AP egress reset: internet=off sntp_blocked=off")

    def set_internet(self, enabled: bool):
        with self._lock:
            self.internet = bool(enabled)
            try:
                self._apply_rules()
                self._set_forward(self.internet)
                self._update_dns()
            except Exception:
                # Never leave a half-applied "on": fall back to the closed state.
                self.internet = False
                self._apply_rules()
                raise
            logger.info("AP egress internet=%s", self.internet)

    def set_sntp_block(self, blocked: bool):
        with self._lock:
            self.sntp_blocked = bool(blocked)
            self._apply_rules()
            logger.info("AP egress sntp_blocked=%s", self.sntp_blocked)

    def status(self) -> dict:
        with self._lock:
            rc, out, _ = self._run(["iptables", "-w", "-S", CHAIN_FWD])
            listed = [ln.strip() for ln in out.splitlines() if ln.strip()] if rc == 0 else []
            want = expected_listing(self.internet, self.sntp_blocked, self.wlan,
                                    self.uplink, self.ap_subnet)
            hooks_ok = all(self._run([b, "-w", "-t", t, "-C", c] + a)[0] == 0
                           for b, t, c, a in hook_rules(self.wlan))
            return {
                "internet": self.internet,
                "sntp_blocked": self.sntp_blocked,
                "lan_blocked": True,
                "rules_ok": listed == want and hooks_ok,
                "rules": listed,
            }


def parse_flag(body, key):
    """The POST bodies take a JSON boolean and nothing else: a typo such as
    {"enabled": "false"} must not switch egress on."""
    if not isinstance(body, dict) or key not in body:
        raise ValueError(f"missing {key}")
    if not isinstance(body[key], bool):
        raise ValueError(f"{key} must be true or false")
    return body[key]
