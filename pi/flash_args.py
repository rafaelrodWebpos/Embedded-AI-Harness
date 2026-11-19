"""Parse and check what /api/flash passes to esptool write-flash.

villa-2 fix for upstream #52: the /api/flash handler looked only at the first
``--option value`` of a line and ``continue``d. ESP-IDF writes all three flash
options on ONE line::

    --flash-mode dio --flash-freq 80m --flash-size 8MB
    0x0 bootloader/bootloader.bin
    ...

so only the mode was applied and the image was flashed at the handler's
default 40m with the size left as found. ``parse`` reads every option on
every line, in the ``--flash-freq 80m``, ``--flash_freq 80m`` and
``--flash-freq=80m`` forms.

Review of 2026-11-18 (A-1..A-3): everything that reaches the esptool command
line is checked against a closed list, and anything else is a ``ValueError``
that the handler answers with 400:

* A-1 ``check_options``: flash_mode in {qio, qout, dio, dout, keep};
  flash_freq ``<n>m`` or keep; flash_size ``<n>MB``, keep or detect. Applied
  to flash_args and to the form fields alike.
* A-2 ``check_offset``: hex ``0x…`` or plain decimal (no sign, no ``_``),
  aligned to 0x1000 (0x0 allowed) and below the flash size.
* A-3 ``parse``: a line with tokens left over, an unknown option or an
  option without a value is an error, not something to skip.
"""
import re

OPTIONS = {"flash_mode", "flash_freq", "flash_size"}
_MODE = {"qio", "qout", "dio", "dout", "keep"}
_FREQ = re.compile(r"^\d+m$|^keep$")
_SIZE = re.compile(r"^(\d+)MB$|^keep$|^detect$")
_OFFSET = re.compile(r"^0[xX][0-9a-fA-F]+$|^[0-9]+$")
SECTOR = 0x1000
# keep/detect leave the size unknown here: bound offsets by the largest flash
# an ESP32-family module ships with, so nonsense offsets still fail.
UNKNOWN_SIZE_LIMIT = 128 * 1024 * 1024


def parse(text: str) -> tuple[dict, list]:
    """Return ``(options, pairs)`` or raise ``ValueError``.

    ``options`` maps ``flash_mode`` / ``flash_freq`` / ``flash_size`` to the
    value found (later lines override earlier ones). ``pairs`` is the list of
    ``(offset, path)`` image lines, in order, with the offset as written.
    Values are not checked here; see ``check_options`` and ``check_offset``.
    """
    options: dict = {}
    pairs: list = []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if tokens[0].startswith("--"):
            i = 0
            while i < len(tokens):
                tok = tokens[i]
                if not tok.startswith("--"):
                    raise ValueError(f"flash_args line {n}: unexpected token '{tok}'")
                key, eq, value = tok[2:].partition("=")
                key = key.replace("-", "_")
                if key not in OPTIONS:
                    raise ValueError(f"flash_args line {n}: unknown option '{tok}'")
                if not eq:
                    if i + 1 >= len(tokens) or tokens[i + 1].startswith("--"):
                        raise ValueError(f"flash_args line {n}: '{tok}' without a value")
                    value, i = tokens[i + 1], i + 1
                if not value:
                    raise ValueError(f"flash_args line {n}: '{tok}' without a value")
                options[key] = value
                i += 1
            continue
        if len(tokens) != 2:
            raise ValueError(f"flash_args line {n}: expected '<offset> <file>', got {len(tokens)} tokens")
        pairs.append((tokens[0], tokens[1]))
    return options, pairs


def check_options(flash_mode: str, flash_freq: str, flash_size: str) -> None:
    """A-1: raise ``ValueError`` unless every value is in the closed list."""
    if flash_mode not in _MODE:
        raise ValueError(f"flash_mode '{flash_mode}' not in {sorted(_MODE)}")
    if not _FREQ.match(flash_freq or ""):
        raise ValueError(f"flash_freq '{flash_freq}' is not '<n>m' or 'keep'")
    if not _SIZE.match(flash_size or ""):
        raise ValueError(f"flash_size '{flash_size}' is not '<n>MB', 'keep' or 'detect'")


def flash_bytes(flash_size: str) -> int:
    """Size in bytes for '<n>MB'; the unknown-size bound for keep/detect."""
    m = _SIZE.match(flash_size or "")
    if m and m.group(1):
        return int(m.group(1)) * 1024 * 1024
    return UNKNOWN_SIZE_LIMIT


def check_offset(offset: str, flash_size: str) -> int:
    """A-2: the offset as an int, or ``ValueError``."""
    if not _OFFSET.match(offset or ""):
        raise ValueError(f"offset '{offset}' is not hex 0x... or decimal (no sign, no '_')")
    value = int(offset, 16) if offset[:2].lower() == "0x" else int(offset, 10)
    if value % SECTOR:
        raise ValueError(f"offset {offset} is not aligned to 0x{SECTOR:x}")
    limit = flash_bytes(flash_size)
    if value >= limit:
        raise ValueError(f"offset {offset} is beyond the flash size (0x{limit:x})")
    return value
