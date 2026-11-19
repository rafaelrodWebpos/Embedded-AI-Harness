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
])
def test_forms_and_order(line):
    opts, pairs = flash_args.parse(line)
    assert opts == {"flash_mode": "qio", "flash_freq": "40m", "flash_size": "16MB"}
    assert pairs == []


def test_one_option_per_line_and_later_lines_override():
    opts, _ = flash_args.parse("--flash-mode dio\n--flash-freq 40m\n# comment\n\n--flash-freq 80m\n")
    assert opts == {"flash_mode": "dio", "flash_freq": "80m"}


# A-3 (review 2026-11-18): a line with tokens left over is rejected, not skipped
@pytest.mark.parametrize("text", [
    "0x0 bootloader.bin extra",                      # image line with a third token
    "0x0",                                           # image line without a file
    "bootloader bootloader.bin",                     # not an offset → checked as offset later, but 2 tokens ok
    "--flash-mode dio stray",                        # value-less stray token
    "--unknown --flash-mode qio",                    # unknown option
    "--other x --flash-freq 40m",                    # unknown option with a value
    "--flash-mode",                                  # option without a value
    "--flash-mode --flash-freq 80m",                 # option followed by another option
    "--flash-mode=",                                 # empty value
])
def test_strict_lines(text):
    if text == "bootloader bootloader.bin":
        opts, pairs = flash_args.parse(text)         # A-3 is about token count; the offset is A-2's job
        with pytest.raises(ValueError):
            flash_args.check_offset(pairs[0][0], "8MB")
        return
    with pytest.raises(ValueError):
        flash_args.parse(text)


# A-1: closed lists, for flash_args and for the form fields (same function)
@pytest.mark.parametrize("mode", ["qio", "qout", "dio", "dout", "keep"])
def test_modes_accepted(mode):
    flash_args.check_options(mode, "80m", "8MB")


@pytest.mark.parametrize("mode,freq,size", [
    ("DIO", "80m", "8MB"), ("dio;rm", "80m", "8MB"), ("", "80m", "8MB"), ("fastread", "80m", "8MB"),
    ("dio", "80M", "8MB"), ("dio", "80", "8MB"), ("dio", "80m ", "8MB"), ("dio", "--erase-all", "8MB"),
    ("dio", "80m", "8mb"), ("dio", "80m", "8MB;x"), ("dio", "80m", "auto"), ("dio", "80m", ""),
    ("dio", "-1m", "8MB"),
])
def test_values_outside_the_lists_rejected(mode, freq, size):
    with pytest.raises(ValueError):
        flash_args.check_options(mode, freq, size)


@pytest.mark.parametrize("freq,size", [("keep", "keep"), ("40m", "detect"), ("120m", "16MB"), ("20m", "2MB")])
def test_other_valid_values(freq, size):
    flash_args.check_options("dio", freq, size)


# A-2: offsets
@pytest.mark.parametrize("off", ["0x0", "0", "0x1000", "0x8000", "0xf000", "0x20000", "0x7ff000", "4096"])
def test_offsets_accepted(off):
    flash_args.check_offset(off, "8MB")


@pytest.mark.parametrize("off,size", [
    ("-0x1000", "8MB"), ("+0x1000", "8MB"), ("0x1_000", "8MB"), ("1_000", "8MB"), ("0x", "8MB"),
    ("0x100", "8MB"), ("0x20001", "8MB"), ("100", "8MB"),            # not aligned
    ("0x800000", "8MB"), ("0x1000000", "8MB"),                       # at/after the end of 8MB
    ("0x8000000", "keep"), ("0o10000", "8MB"), ("0b1", "8MB"), (" 0x0", "8MB"), ("", "8MB"),
])
def test_offsets_rejected(off, size):
    with pytest.raises(ValueError):
        flash_args.check_offset(off, size)


def test_offset_value():
    assert flash_args.check_offset("0x20000", "8MB") == 0x20000
    assert flash_args.check_offset("4096", "detect") == 4096


def test_empty_and_none():
    assert flash_args.parse("") == ({}, [])
    assert flash_args.parse(None) == ({}, [])


def test_handler_uses_the_parser():
    src = (ROOT / "pi" / "portal.py").read_text()
    assert "flash_args.parse(flash_args_text)" in src
    assert "flash_args.check_options(flash_mode, flash_freq, flash_size)" in src
    assert "flash_args.check_offset(offset, flash_size)" in src and "pairs + offset_files" in src
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
