"""Portal API token — fork villa-2, review S6 finding S6-01.

Every /api/* request must carry the bench token in the `X-Harness-Token` header,
except `GET /api/info`, which stays open but only says whether the portal is up
and which capabilities and build it has (nothing about the network or the
slots). The web UI pages themselves (`/`, static files) are served without a
token; their JavaScript adds the header with the token the operator typed once.

The token is a random secret generated on the Pi by install.sh
(`/etc/rfc2217/api-token`, root, 0600) and copied by the owner into the laptop's
.env as TESTBENCH_TOKEN. It is never in git, never logged, never in a response.

Fail closed: without a readable token file every protected route is refused.
The decisions are pure functions so the host tier checks them without a Pi.
"""
import hmac
import os
import stat

TOKEN_FILE = os.environ.get("HARNESS_TOKEN_FILE", "/etc/rfc2217/api-token")
HEADER = "X-Harness-Token"
OPEN_ROUTES = {("GET", "/api/info")}
MIN_LEN = 32


def needs_token(method, path):
    """True for every /api/* route except the open ones; False for the UI pages."""
    if not path.startswith("/api/") and path != "/api":
        return False
    return (method.upper(), path) not in OPEN_ROUTES


def allowed(method, path, presented, expected):
    """Constant-time check. `expected` None (no token file) refuses every protected route."""
    if not needs_token(method, path):
        return True
    if not expected or not presented:
        return False
    return hmac.compare_digest(presented.encode(), expected.encode())


def token_file_ok(st, uid=0):
    """The token file must be a regular file owned by root with no group/other bits."""
    return (stat.S_ISREG(st.st_mode) and st.st_uid == uid
            and (st.st_mode & 0o077) == 0)


def load_token(path=TOKEN_FILE):
    """Read the token, refusing a symlink, a wrong owner or loose permissions."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        if not token_file_ok(os.fstat(fd)):
            return None
        tok = os.read(fd, 256).decode("ascii", "replace").strip()
    finally:
        os.close(fd)
    return tok if len(tok) >= MIN_LEN and tok.isalnum() else None


def public_info(full):
    """What GET /api/info may say without a token: ok, build, capabilities."""
    return {k: full[k] for k in ("ok", "build", "capabilities") if k in full}
