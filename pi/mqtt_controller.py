"""
MQTT Controller — manages a mosquitto broker for ESP32 MQTT client testing.

Used by the portal to start/stop a local MQTT broker accessible to devices
on the testbench WiFi AP.
"""

import logging
import os
import pwd
import re
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MQTT_PORT = 1883
WORK_DIR = "/tmp/mqtt-tester"
MOSQUITTO_CONF = os.path.join(WORK_DIR, "mosquitto.conf")
MOSQUITTO_LOG = os.path.join(WORK_DIR, "mosquitto.log")
# bench-mqtt-auth (fork, CR-TB-03): temporary password file, only while a
# broker started with credentials runs; deleted on stop.
MOSQUITTO_PASSWD = os.path.join(WORK_DIR, "passwd")
_CRED_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_active = False
_proc = None
_auth = False


# ---------------------------------------------------------------------------
# Pure core (bench-mqtt-auth)
# ---------------------------------------------------------------------------

def parse_auth(body):
    """POST /api/mqtt/start body → (user, password) or (None, None) for an open
    broker. Both or neither; test credentials only: [A-Za-z0-9._-]{1,64}."""
    if not body:
        return None, None
    if not isinstance(body, dict):
        raise ValueError("body must be a JSON object")
    user, pw = body.get("user"), body.get("pass")
    if user is None and pw is None:
        return None, None
    if not (isinstance(user, str) and isinstance(pw, str)
            and _CRED_RE.match(user) and _CRED_RE.match(pw)):
        raise ValueError("user and pass: both, 1-64 characters of [A-Za-z0-9._-]")
    return user, pw


def conf_lines(port, log_path, passwd_path=None):
    """mosquitto.conf for the test broker: open, or with a password file."""
    lines = [f"listener {port}"]
    if passwd_path:
        lines += ["allow_anonymous false", f"password_file {passwd_path}"]
    else:
        lines += ["allow_anonymous true"]
    lines += [f"log_dest file {log_path}", "log_type all"]
    return lines


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_work_dir():
    os.makedirs(WORK_DIR, exist_ok=True)


def _kill_proc(proc, timeout=5.0):
    """Terminate a subprocess, SIGKILL if it won't die."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        return
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass


def _kill_existing():
    """Kill a previously-started *test* broker, and only that (best effort).

    The pattern is matched against our own config path, not the bare word
    "mosquitto". A broad `pkill -f mosquitto` also kills a system
    `mosquitto.service` or any other broker on the host — a test fixture must
    never take down infrastructure it does not own.

    This reclaims the port after a portal restart, where the old broker is still
    running but `_proc` no longer refers to it.
    """
    try:
        subprocess.run(
            ["pkill", "-f", f"mosquitto -c {MOSQUITTO_CONF}"],
            capture_output=True, timeout=5, check=False,
        )
        time.sleep(0.3)
    except Exception:
        pass


def _port_owner() -> str:
    """Describe what is listening on MQTT_PORT, or '' if nothing is."""
    try:
        out = subprocess.run(
            ["ss", "-tlnp", f"sport = :{MQTT_PORT}"],
            capture_output=True, timeout=5, check=False,
        ).stdout.decode(errors="replace")
    except Exception:
        return ""
    lines = [ln for ln in out.splitlines()[1:] if ln.strip()]
    return lines[0].strip() if lines else ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _write_passwd(user, pw):
    """Plain `user:pass` in a 0600 file, then hashed in place by mosquitto_passwd
    -U, so the password never appears on a command line."""
    fd = os.open(MOSQUITTO_PASSWD, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"{user}:{pw}\n")
    r = subprocess.run(["mosquitto_passwd", "-U", MOSQUITTO_PASSWD],
                       capture_output=True, timeout=10, check=False)
    if r.returncode != 0:
        _remove_passwd()
        raise RuntimeError("mosquitto_passwd failed")
    # mosquitto started as root may drop to its own user before reading the file
    try:
        pw_ent = pwd.getpwnam("mosquitto")
        os.chown(MOSQUITTO_PASSWD, pw_ent.pw_uid, pw_ent.pw_gid)
    except (KeyError, PermissionError):
        pass
    os.chmod(MOSQUITTO_PASSWD, 0o600)


def _remove_passwd():
    try:
        os.remove(MOSQUITTO_PASSWD)
    except FileNotFoundError:
        pass


def start(user=None, password=None):
    """Start the mosquitto MQTT broker, open or (bench-mqtt-auth) with one
    user. Returns dict with port and auth."""
    global _active, _proc, _auth

    with _lock:
        if _active and _proc is not None and _proc.poll() is None:
            if bool(user) != _auth:
                raise RuntimeError("the broker is already running with another auth mode; stop it first")
            return {"port": MQTT_PORT, "auth": _auth}

        _ensure_work_dir()
        _kill_existing()

        # If something still holds the port it is not ours, so refuse rather than
        # kill it. Silently killing a broker we did not start is how a test run
        # takes down a service somebody else depends on.
        owner = _port_owner()
        if owner:
            raise RuntimeError(
                f"port {MQTT_PORT} is already in use by a broker this service did "
                f"not start; stop it first. Listener: {owner}")

        # Write mosquitto config — listen on all interfaces; open, or with the
        # temporary password file (bench-mqtt-auth)
        _remove_passwd()
        if user:
            _write_passwd(user, password)
        with open(MOSQUITTO_CONF, "w") as f:
            f.write("\n".join(conf_lines(MQTT_PORT, MOSQUITTO_LOG, MOSQUITTO_PASSWD if user else None)) + "\n")

        # Start mosquitto
        _proc = subprocess.Popen(
            ["mosquitto", "-c", MOSQUITTO_CONF],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        # Wait for it to initialise
        time.sleep(1.0)
        if _proc.poll() is not None:
            out = _proc.stdout.read().decode(errors="replace")
            _active = False
            _remove_passwd()
            raise RuntimeError(f"mosquitto failed to start: {out[:500]}")

        _active = True
        _auth = bool(user)
        logger.info("MQTT broker started on port %d (auth=%s)", MQTT_PORT, _auth)
        return {"port": MQTT_PORT, "auth": _auth}


def stop():
    """Stop the mosquitto broker."""
    global _active, _proc

    global _auth
    with _lock:
        _kill_proc(_proc)
        _proc = None
        _active = False
        _auth = False
        _remove_passwd()
        logger.info("MQTT broker stopped")


def status():
    """Return broker status dict."""
    global _active

    with _lock:
        running = _active and _proc is not None and _proc.poll() is None
        # If process died unexpectedly, update state
        if _active and not running:
            _active = False
        return {
            "running": running,
            "port": MQTT_PORT if running else None,
            "auth": _auth if running else False,
        }
