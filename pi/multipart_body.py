"""Split a multipart/form-data body into its parts without touching the content.

villa-2 fix: the portal handlers stripped every part with ``bytes.strip()``,
which also removed trailing whitespace bytes (``\\n \\r \\t space \\x0b
\\x0c``) of an uploaded binary. A firmware image whose last byte is ``0x0a``
lost it; esptool padded with ``0xFF`` and the bootloader rejected the image
with "Image hash failed" (found 2026-11-15 on a release image).

The delimiter is CRLF ``--boundary`` (RFC 2046 §5.1.1): the CRLF before a
delimiter belongs to the delimiter, not to the content. Exactly that line
break (CRLF, or a bare LF from lenient clients) is removed, and nothing else.
"""


def parts(body: bytes, boundary: str) -> list[tuple[str, bytes]]:
    """Return ``[(headers_text, content), ...]`` for each body part.

    The preamble before the first delimiter and the epilogue after the close
    delimiter are ignored. A part without a blank line between its headers
    and its content is skipped. Content bytes are returned exactly as sent.
    """
    out = []
    chunks = body.split(b"--" + boundary.encode())
    for chunk in chunks[1:]:              # chunks[0] is the preamble
        if chunk.startswith(b"--"):       # close delimiter: the rest is epilogue
            break
        # Line break that ends the delimiter line (transport padding aside)
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        elif chunk.startswith(b"\n"):
            chunk = chunk[1:]
        # Line break that starts the next delimiter
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        elif chunk.endswith(b"\n"):
            chunk = chunk[:-1]
        if b"\r\n\r\n" in chunk:
            header_section, content = chunk.split(b"\r\n\r\n", 1)
        elif b"\n\n" in chunk:
            header_section, content = chunk.split(b"\n\n", 1)
        else:
            continue
        out.append((header_section.decode("utf-8", errors="replace"), content))
    return out
