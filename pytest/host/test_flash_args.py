"""villa-2, upstream #52: /api/flash applies every option of a flash_args line.

Before, only the first ``--option value`` of a line was read, so an ESP-IDF
flash_args ("--flash-mode dio --flash-freq 80m --flash-size 8MB" on one line)
flashed at the handler's default 40m with the size left as found.
"""
import io
import json
import pathlib
import sys
import urllib.request

import pytest

import flash_args
import multipart_body

ROOT = pathlib.Path(__file__).resolve().parents[2]
IDF_FLASH_ARGS = """--flash-mode dio --flash-freq 80m --flash-size 8MB
0x0 bootloader/bootloader.bin
0x20000 nodo_clima.bin
0x8000 partition_table/partition-table.bin
0xf000 ota_data_initial.bin
"""


def test_esp_idf_one_line_options_all_applied():
    opts, pairs = flash_args.parse(IDF_FLASH_ARGS)
    assert opts == {"flash_mode": "dio", "flash_freq": "80m", "flash_size": "8MB"}
    assert pairs == [("0x0", "bootloader/bootloader.bin"), ("0x20000", "nodo_clima.bin"),
                     ("0x8000", "partition_table/partition-table.bin"), ("0xf000", "ota_data_initial.bin")]


@pytest.mark.parametrize("line", [
    "--flash-mode qio --flash-freq 40m --flash-size 16MB",
    "--flash_mode qio --flash_freq 40m --flash_size 16MB",
    "--flash-mode=qio --flash-freq=40m --flash-size=16MB",
    "--flash-size 16MB --flash-mode qio --flash-freq 40m",
    "--unknown --flash-mode qio --other x --flash-freq 40m --flash-size 16MB",
])
def test_forms_order_and_unknown_options(line):
    opts, pairs = flash_args.parse(line)
    assert opts == {"flash_mode": "qio", "flash_freq": "40m", "flash_size": "16MB"}
    assert pairs == []


def test_one_option_per_line_and_later_lines_override():
    opts, _ = flash_args.parse("--flash-mode dio\n--flash-freq 40m\n# comment\n\n--flash-freq 80m\n")
    assert opts == {"flash_mode": "dio", "flash_freq": "80m"}


def test_option_without_value_and_non_numeric_offset_ignored():
    opts, pairs = flash_args.parse("--flash-mode\nbootloader bootloader.bin\n0x10 a.bin\n")
    assert opts == {}
    assert pairs == [("0x10", "a.bin")]


def test_empty_and_none():
    assert flash_args.parse("") == ({}, [])
    assert flash_args.parse(None) == ({}, [])


def test_handler_uses_the_parser():
    src = (ROOT / "pi" / "portal.py").read_text()
    assert "flash_args.parse(flash_args_text)" in src
    assert 'tokens[0] in ("--flash_freq", "--flash-freq")' not in src, "the first-option-only loop is back"
    assert "flash_args.py" in (ROOT / "pi" / "install.sh").read_text()


def test_driver_sends_options_the_portal_reads(monkeypatch, tmp_path):
    sys.path.insert(0, str(ROOT / "pytest"))
    import testbench_driver

    sent = {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        sent["body"] = req.data
        sent["ctype"] = req.headers.get("Content-type") or req.headers.get("Content-Type")
        return Resp(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    img = tmp_path / "nodo_clima.bin"
    img.write_bytes(b"\xe9app\n")
    tb = testbench_driver.TestbenchDriver("http://bench.invalid:8080")
    assert tb.flash("SLOT1", {"0x20000": str(img)}, chip="esp32s3",
                    flash_args="--flash-mode dio --flash-freq 80m --flash-size 8MB")["ok"]
    boundary = sent["ctype"].split("boundary=", 1)[1]
    parts = {h.split('name="', 1)[1].split('"', 1)[0]: c
             for h, c in multipart_body.parts(sent["body"], boundary)}
    assert parts["bin@0x20000"] == b"\xe9app\n"
    opts, pairs = flash_args.parse(parts["flash_args"].decode())
    assert opts == {"flash_mode": "dio", "flash_freq": "80m", "flash_size": "8MB"} and pairs == []
