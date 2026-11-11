"""Traffic capture on the bench AP — capability `bench-traffic-capture` (fork, CR-TB-04).

Captures, for a bounded time, the IPv4 traffic SENT by one DUT (by its MAC) on
the AP interface, and reports a summary per destination: protocol, destination
address and port, unicast or broadcast, and a packet count. Payloads are never
stored or returned.

Safety model
------------
* Only the AP interface (wlan0), never the uplink: nothing from the LAN is seen.
* Only frames whose source MAC is the DUT's (`ether src <mac>`), so other AP
  clients are not captured.
* Bounded: 1-600 s; one capture at a time; tcpdump runs with `-n` (no name
  lookups), `-l` and without `-w` (nothing written to disk).
* Off by default; a running capture is stopped on every ap_stop.

The command builder and the line parser are pure functions so the host tier can
check them without a Pi.
"""
import logging
import re
import shutil
import subprocess
import threading
import time

logger = logging.getLogger("capture")

MAX_SECONDS = 600
_BROADCAST = ":".join(["ff"] * 6)
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
# tcpdump -n -e -l -q line, e.g. (MACs written as <src> and <dst> here):
# 12:00:00.1 <src> > <dst>, IPv4, length 70: 192.168.4.11.5555 > 192.168.4.255.5555: UDP, length 28
_LINE_RE = re.compile(
    r"^\S+\s+(?P<smac>[0-9a-f:]{17})\s+>\s+(?P<dmac>[0-9a-f:]{17}),\s+IPv4,\s+length\s+\d+:\s+"
    r"(?P<src>\d+\.\d+\.\d+\.\d+)(?:\.(?P<sport>\d+))?\s+>\s+(?P<dst>\d+\.\d+\.\d+\.\d+)(?:\.(?P<dport>\d+))?:\s+"
    r"(?P<proto>[A-Za-z0-9]+)")


# ── Pure core ─────────────────────────────────────────────────────────────

def parse_request(body):
    """POST /api/capture/start body → (mac, seconds)."""
    if not isinstance(body, dict):
        raise ValueError("body must be a JSON object")
    mac = body.get("mac")
    secs = body.get("seconds")
    if not isinstance(mac, str) or not _MAC_RE.match(mac.lower()):
        raise ValueError("mac must be six two-digit hex groups separated by colons")
    if isinstance(secs, bool) or not isinstance(secs, int) or not 1 <= secs <= MAX_SECONDS:
        raise ValueError(f"seconds must be an integer 1-{MAX_SECONDS}")
    return mac.lower(), secs


def tcpdump_command(iface, mac):
    """Headers only (-q), no name lookups (-n), link headers for broadcast (-e),
    line-buffered (-l), IPv4 frames from the DUT only. No -w: nothing on disk."""
    return ["tcpdump", "-i", iface, "-n", "-e", "-l", "-q", "-p", "ether", "src", mac, "and", "ip"]


def parse_line(line):
    """One tcpdump line → (proto, dst, dport, kind) or None if it is not IPv4."""
    m = _LINE_RE.match(line.strip())
    if not m:
        return None
    proto = m.group("proto").upper()
    if proto.startswith("UDP"):
        proto = "UDP"
    elif proto in ("FLAGS", "TCP"):
        proto = "TCP"
    dst = m.group("dst")
    if m.group("dmac") == _BROADCAST or dst.endswith(".255") or dst == "255.255.255.255":
        kind = "broadcast"
    elif 224 <= int(dst.split(".")[0]) <= 239:
        kind = "multicast"
    else:
        kind = "unicast"
    dport = int(m.group("dport")) if m.group("dport") else None
    return proto, dst, dport, kind


def summarize(lines):
    """Lines → sorted list of {proto, dst, dport, kind, packets}."""
    counts = {}
    for ln in lines:
        k = parse_line(ln)
        if k:
            counts[k] = counts.get(k, 0) + 1
    return [{"proto": p, "dst": d, "dport": dp, "kind": kd, "packets": n}
            for (p, d, dp, kd), n in sorted(counts.items(), key=lambda x: (x[0][1], x[0][2] or 0, x[0][0]))]


# ── Runner ────────────────────────────────────────────────────────────────

class Capture:
    """One capture at a time; `popen` is injectable for the host tier."""

    def __init__(self, iface, popen=None, clock=time.time):
        self.iface = iface
        self._popen = popen or (lambda cmd: subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True))
        self._clock = clock
        self._lock = threading.Lock()
        self._proc = None
        self._state = {"state": "idle"}

    @staticmethod
    def available():
        return shutil.which("tcpdump") is not None

    def start(self, mac, seconds):
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                raise RuntimeError("a capture is already running")
            proc = self._popen(tcpdump_command(self.iface, mac))
            self._proc = proc
            self._state = {"state": "running", "mac": mac, "seconds": seconds,
                           "started": self._clock()}
        threading.Thread(target=self._collect, args=(proc, mac, seconds), daemon=True).start()
        return dict(self._state)

    def _collect(self, proc, mac, seconds):
        lines = []
        timer = threading.Timer(seconds, self._stop_proc, args=(proc,))
        timer.start()
        try:
            for ln in proc.stdout:
                lines.append(ln)
                if len(lines) > 200000:          # bound memory; the summary is what matters
                    break
        finally:
            timer.cancel()
            self._stop_proc(proc)
        with self._lock:
            if self._proc is proc:
                self._proc = None
                self._state = {"state": "done", "mac": mac, "seconds": seconds,
                               "flows": summarize(lines)}
        logger.info("capture done: %d lines", len(lines))

    @staticmethod
    def _stop_proc(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def stop(self):
        """Stop a running capture (ap_stop); its partial result is kept."""
        with self._lock:
            proc = self._proc
        if proc is not None:
            self._stop_proc(proc)

    def result(self):
        with self._lock:
            return dict(self._state)
