"""villa-2: multipart parts keep uploaded binaries byte-exact.

Regression for the strip() bug: a firmware image ending in 0x0a lost its last
byte through POST /api/flash, and the DUT bootloader rejected it with
"Image hash failed" (2026-11-15).
"""
import inspect
import pathlib

import pytest

import multipart_body

BOUNDARY = "----wbTEST"


def driver_body(fields, files, boundary=BOUNDARY):
    """The body exactly as TestbenchDriver.flash builds it (CRLF everywhere)."""
    out = []
    for name, value in fields:
        out.append(f"--{boundary}\r\nContent-Disposition: form-data; "
                   f'name="{name}"\r\n\r\n{value}\r\n'.encode())
    for name, filename, blob in files:
        out.append(f"--{boundary}\r\nContent-Disposition: form-data; "
                   f'name="{name}"; filename="{filename}"\r\n'
                   f"Content-Type: application/octet-stream\r\n\r\n".encode() + blob + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out)


def contents(body, boundary=BOUNDARY):
    return [c for _, c in multipart_body.parts(body, boundary)]


@pytest.mark.parametrize("last", range(256))
def test_every_final_byte_survives(last):
    blob = bytes(range(64)) * 3 + bytes([last])
    body = driver_body([("slot", "SLOT1")], [("bin@0x20000", "app.bin", blob)])
    got = contents(body)
    assert got[1] == blob, f"final byte {last:#04x}: {len(got[1])} bytes back, {len(blob)} sent"
    assert got[0] == b"SLOT1"


@pytest.mark.parametrize("tail", [b"\r\n", b"\n\n", b"\r\n\r\n", b"\n", b"\r", b" \t\x0b\x0c", b"--", b"\r\n--"])
def test_whitespace_and_dash_tails_survive(tail):
    blob = b"\xe9firmware" + tail
    body = driver_body([], [("bin@0x0", "a.bin", blob), ("bin@0x8000", "b.bin", tail + b"x" + tail)])
    assert contents(body) == [blob, tail + b"x" + tail]


@pytest.mark.parametrize("lead", [b"\r\n", b"\n", b" ", b"\t"])
def test_leading_whitespace_survives(lead):
    blob = lead + b"payload"
    assert contents(driver_body([], [("bin@0x0", "a.bin", blob)])) == [blob]


def test_release_image_tail_from_2026_11_15():
    # The last 16 bytes of the image that failed (SHA-256 digest ending in 0x0a)
    blob = b"\x00" * 1024 + bytes.fromhex("60b6a606d5e7a0699076466c7095680a")
    assert contents(driver_body([], [("bin@0x20000", "nodo_clima.bin", blob)])) == [blob]


def test_lf_only_client_and_preamble_epilogue():
    body = (b"preamble\n--B\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\n\n"
            b"abc\n\n--B--\nepilogue")
    assert multipart_body.parts(body, "B") == [
        ('Content-Disposition: form-data; name="f"; filename="x"', b"abc\n")]


def test_empty_file_and_part_without_blank_line():
    body = (b"--B\r\nContent-Disposition: form-data; name=\"e\"; filename=\"e\"\r\n\r\n\r\n"
            b"--B\r\nno blank line here\r\n--B--\r\n")
    assert contents(body, "B") == [b""]


def test_portal_handlers_use_the_byte_exact_parser():
    src = (pathlib.Path(__file__).resolve().parents[2] / "pi" / "portal.py").read_text()
    # _parse_multipart, _handle_firmware_upload, _handle_flash and _handle_ota
    assert src.count("multipart_body.parts(body, boundary)") == 4
    assert "for part in parts_raw" not in src and "parts_raw" not in src, "a multipart loop still splits by hand"
    installer = (pathlib.Path(__file__).resolve().parents[2] / "pi" / "install.sh").read_text()
    assert "multipart_body.py" in installer


def test_parts_signature():
    assert list(inspect.signature(multipart_body.parts).parameters) == ["body", "boundary"]
