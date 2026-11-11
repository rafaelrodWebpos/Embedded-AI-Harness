"""Root-owned runtime directory for the fork's files — review S6 finding S6-03.

villa-2 files that root writes (the DNS-override hosts file, the test broker's
config and password file) live under /run/harness instead of predictable /tmp
paths, so an unprivileged local user cannot plant a symlink there:

  /run/harness           root:root  0711  (traversable, not listable or writable)
  /run/harness/mqtt      root:<mosquitto group> 0750  (mosquitto.conf, passwd)

0711 rather than 0700 because dnsmasq (re-reading its addn-hosts file on SIGHUP)
and mosquitto may run without root by then and must reach their file. Every
file is opened with O_NOFOLLOW; an existing directory that is a symlink, is not
owned by root or is writable by others is refused (fail closed).
"""
import grp
import os
import stat

RUN_DIR = os.environ.get("HARNESS_RUN_DIR", "/run/harness")
MQTT_DIR = os.path.join(RUN_DIR, "mqtt")


def dir_ok(st, uid=0):
    """A real directory, owned by root, not writable by group or others."""
    return stat.S_ISDIR(st.st_mode) and st.st_uid == uid and (st.st_mode & 0o022) == 0


def ensure_dir(path, mode, gid=None, uid=0, lstat=os.lstat, mkdir=os.mkdir, chown=os.chown, chmod=os.chmod):
    """Create (or check) a root-owned directory; refuse symlinks and foreign owners."""
    try:
        st = lstat(path)
    except FileNotFoundError:
        mkdir(path, mode)
        if gid is not None:
            chown(path, uid, gid)
        chmod(path, mode)
        st = lstat(path)
    if not dir_ok(st, uid):
        raise PermissionError(f"{path}: not a root-owned directory (refused)")
    return path


def ensure_run_dirs():
    ensure_dir(RUN_DIR, 0o711)
    try:
        gid = grp.getgrnam("mosquitto").gr_gid
    except KeyError:
        gid = 0
    ensure_dir(MQTT_DIR, 0o750, gid=gid)


def write_file(path, text, mode=0o644, gid=None):
    """Replace a file atomically without following symlinks: a fresh temp file
    opened O_CREAT|O_EXCL|O_NOFOLLOW, then rename over the target."""
    tmp = path + ".tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, text.encode())
        if gid is not None:
            os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def mosquitto_gid():
    try:
        return grp.getgrnam("mosquitto").gr_gid
    except KeyError:
        return None
