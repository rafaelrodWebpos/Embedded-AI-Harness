"""Parse esptool's @flash_args text (the build/flash_args that ESP-IDF writes).

villa-2 fix for upstream #52: the /api/flash handler looked only at the first
``--option value`` of a line and ``continue``d. ESP-IDF writes all three flash
options on ONE line::

    --flash-mode dio --flash-freq 80m --flash-size 8MB
    0x0 bootloader/bootloader.bin
    ...

so only the mode was applied and the image was flashed at the handler's
default 40m with the size left as found. ``parse`` reads every option on
every line, in the ``--flash-freq 80m``, ``--flash_freq 80m`` and
``--flash-freq=80m`` forms. Unknown options are ignored.
"""

OPTIONS = {"flash_mode", "flash_freq", "flash_size"}


def parse(text: str) -> tuple[dict, list]:
    """Return ``(options, pairs)``.

    ``options`` maps ``flash_mode`` / ``flash_freq`` / ``flash_size`` to the
    value found (later lines override earlier ones). ``pairs`` is the list of
    ``(offset, path)`` image lines, in order, with the offset as written.
    """
    options: dict = {}
    pairs: list = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if tokens[0].startswith("--"):
            i = 0
            while i < len(tokens):
                tok = tokens[i]
                if not tok.startswith("--"):
                    i += 1
                    continue
                key, eq, value = tok[2:].partition("=")
                key = key.replace("-", "_")
                if not eq:
                    nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
                    if nxt and not nxt.startswith("--"):
                        value, i = nxt, i + 1
                if key in OPTIONS and value:
                    options[key] = value
                i += 1
            continue
        if len(tokens) >= 2:
            try:
                int(tokens[0], 0)
            except ValueError:
                continue
            pairs.append((tokens[0], tokens[1]))
    return options, pairs
