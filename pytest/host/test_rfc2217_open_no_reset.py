"""villa-2, upstream #86 (fix from upstream PR #87): opening a native-USB port
must not reset a running ESP32.

The USB-Serial/JTAG controller resets the chip while RTS=1 and DTR=0. The
kernel raises both lines on open and pyserial applies DTR before RTS, so the
old "DTR low first" sequence passed through (DTR 0, RTS 1) and rebooted the
DUT ~2 s after every hotplug add. This runs the proxy's real start-up against
a fake port that records every line state and fails on the reset combination.
"""
import importlib
import pathlib
import sys
import types

import pytest

RESET = (False, True)          # (DTR, RTS) that resets an ESP32 over USB-Serial/JTAG
ROOT = pathlib.Path(__file__).resolve().parents[2]


class FakeSerial:
    def __init__(self):
        self.trace, self.is_open = [], False
        self._dtr = self._rts = True
        self.timeout = self.write_timeout = self.baudrate = None

    def _line(self):
        if self.is_open:
            self.trace.append((self._dtr, self._rts))

    @property
    def dtr(self):
        return self._dtr

    @dtr.setter
    def dtr(self, v):
        self._dtr = bool(v)
        self._line()

    @property
    def rts(self):
        return self._rts

    @rts.setter
    def rts(self, v):
        self._rts = bool(v)
        self._line()

    def open(self):
        want_dtr, want_rts = self._dtr, self._rts
        self.is_open = True
        self._dtr = self._rts = True          # the CDC ACM driver raises both on open
        self.trace.append((True, True))
        self.dtr = want_dtr                   # pyserial: DTR first, then RTS
        self.rts = want_rts

    def get_settings(self):
        return {}


class Stop(Exception):
    pass


@pytest.fixture
def proxy(monkeypatch):
    port = FakeSerial()
    fake_serial = types.ModuleType("serial")
    fake_serial.serial_for_url = lambda *a, **k: port
    fake_serial.rfc2217 = types.ModuleType("serial.rfc2217")
    monkeypatch.setitem(sys.modules, "serial", fake_serial)
    monkeypatch.setitem(sys.modules, "serial.rfc2217", fake_serial.rfc2217)
    sys.modules.pop("plain_rfc2217_server", None)
    mod = importlib.import_module("plain_rfc2217_server")
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)

    class FakeSocket:
        def __init__(self, *a, **k):
            pass

        def setsockopt(self, *a):
            pass

        def bind(self, *a):
            raise Stop        # start-up done; the server loop is not under test

    monkeypatch.setattr(mod.socket, "socket", FakeSocket)
    monkeypatch.setattr(sys, "argv", ["plain_rfc2217_server", "/dev/ttyACM0", "-p", "4001"])
    return mod, port


def test_startup_never_forms_the_reset_combination(proxy):
    mod, port = proxy
    with pytest.raises(Stop):
        mod.main()
    assert port.trace, "the port was never opened"
    assert RESET not in port.trace, f"reset combination during open: {port.trace}"
    assert port.trace[-1] == (False, False), f"lines not left idle: {port.trace}"


def test_disconnect_drops_rts_before_dtr():
    src = (ROOT / "pi" / "plain_rfc2217_server.py").read_text()
    block = src[src.index('logging.info("Client disconnected")'):]
    assert block.index("ser.rts = False") < block.index("ser.dtr = False"), \
        "client disconnect must drop RTS before DTR (#86)"
