"""Safety checks shared by the fixture tools.

The fixture scripts rewrite login tokens, create accounts and delete data.
They must only ever touch the throwaway fixture: files under the fixture
directories and the local test server. Every tool validates through this
module BEFORE it opens a file for writing or makes a request.
"""
import os
import stat
import urllib.error
import urllib.parse
import urllib.request

# /tmp itself is a symbolic link on macOS (to /private/tmp). The roots are
# named by their real location so that "not reached through a link" can be
# checked literally; on Linux this is plain /tmp.
TMP = os.path.realpath("/tmp")
FIXTURE_ROOT = os.path.join(TMP, "bww-fixture")
DEV_ROOT = os.path.join(TMP, "bww-dev")
FIXTURE_ROOTS = (FIXTURE_ROOT, DEV_ROOT)
FIXTURE_HOSTS = ("127.0.0.1", "localhost")
FIXTURE_PORT = 18087


class SafetyError(Exception):
    pass


MARKER = ".bww-fixture-root"


def _trusted_root(root):
    """Establish that root is a fixture directory, looking only at root itself.

    The decision does not depend on any candidate path: root must be a real
    directory (not a symbolic link, and not reached through one), owned by the
    current user, and carry the marker file that create_root() puts there. A
    real vault directory has no marker, so pointing an allowed name at one
    (/tmp/bww-fixture -> ~/.config/Bitwarden CLI) is refused.
    """
    if not os.path.isabs(root) or os.path.normpath(root) != root:
        raise SafetyError(f"fixture root {root!r} must be an absolute, normalized path")
    try:
        st = os.lstat(root)
    except OSError as e:
        raise SafetyError(f"fixture root {root!r}: {e.strerror}; create it with safety.create_root()")
    if stat.S_ISLNK(st.st_mode):
        raise SafetyError(f"refusing fixture root {root!r}: it is a symbolic link")
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise SafetyError(f"refusing fixture root {root!r}: not a directory owned by you")
    if st.st_mode & 0o022:
        raise SafetyError(f"refusing fixture root {root!r}: others can write to it")
    if os.path.realpath(root) != root:
        raise SafetyError(f"refusing fixture root {root!r}: it is reached through a symbolic link")
    try:
        mark = os.lstat(os.path.join(root, MARKER))
    except OSError:
        raise SafetyError(f"refusing fixture root {root!r}: it is not marked as a fixture directory "
                          f"(no {MARKER}; only safety.create_root() makes one)")
    if not stat.S_ISREG(mark.st_mode) or mark.st_uid != os.getuid():
        raise SafetyError(f"refusing fixture root {root!r}: its marker is not a regular file owned by you")


def create_root(root, roots=FIXTURE_ROOTS):
    """Create and mark a fixture root. An existing directory is never adopted:
    it passes only if it already carries the marker."""
    if root not in roots:
        raise SafetyError(f"refusing {root!r}: not one of the fixture directories {roots}")
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    else:
        fd = os.open(os.path.join(root, MARKER), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    _trusted_root(root)
    return root


def fixture_path(path, roots=FIXTURE_ROOTS):
    """Return the normalized form of path if it lies inside a fixture root.

    ".." is resolved lexically first, so /tmp/bww-fixture/../../home/me is
    simply outside. The root it falls under must then be a trusted fixture
    directory (_trusted_root), and nothing on the way from the root to the
    path may be a symbolic link: not the root, not an intermediate directory,
    not the last component (a data.json linked to a real vault).
    """
    if not path or not os.path.isabs(path):
        raise SafetyError(f"refusing {path!r}: an absolute path is required")
    absolute = os.path.normpath(path)
    for root in roots:
        if absolute == root or absolute.startswith(root + os.sep):
            _trusted_root(root)
            real = os.path.realpath(absolute)
            if real != absolute:
                raise SafetyError(f"refusing {path!r}: a symbolic link on the way leads to {real!r}")
            return absolute
    raise SafetyError(f"refusing {path!r}: outside the fixture directories {roots}")


def _open_dir(path, roots):
    """Validate a file path and open its directory, pinned by descriptor."""
    path = fixture_path(path, roots)
    directory, name = os.path.split(path)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        here, there = os.fstat(fd), os.lstat(directory)
        if (here.st_dev, here.st_ino) != (there.st_dev, there.st_ino):
            raise SafetyError(f"refusing {path!r}: its directory changed while it was checked")
    except BaseException:
        os.close(fd)
        raise
    return fd, name


def read_file(path, roots=FIXTURE_ROOTS):
    """Read a fixture file. The single way fixture tools read what they will rewrite."""
    fd, name = _open_dir(path, roots)
    try:
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(f) as fh:
            return fh.read()
    finally:
        os.close(fd)


def write_file(path, text, roots=FIXTURE_ROOTS):
    """Replace a fixture file. The single way fixture tools write: the path is
    validated, the directory is pinned, and the new content replaces the name
    (a link planted there meanwhile is replaced, not followed)."""
    fd, name = _open_dir(path, roots)
    tmp = f".{name}.safety-{os.getpid()}"
    try:
        f = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(f, "w") as fh:
            fh.write(text)
        os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        os.close(fd)


def fixture_url(url, hosts=FIXTURE_HOSTS, port=FIXTURE_PORT):
    """Return the origin (https://host:port) if url is the local fixture server.

    The URL is parsed, not prefix-matched: https://127.0.0.1:18087@remote.example
    has the host remote.example and is refused, as is any user information,
    another scheme, host or port, and anything after the origin.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        got_port = parts.port
    except ValueError as e:
        raise SafetyError(f"refusing {url!r}: {e}")
    if parts.scheme != "https":
        raise SafetyError(f"refusing {url!r}: scheme must be https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise SafetyError(f"refusing {url!r}: user information in the URL")
    if parts.hostname not in hosts:
        raise SafetyError(f"refusing {url!r}: host {parts.hostname!r} is not the local fixture server")
    if got_port != port:
        raise SafetyError(f"refusing {url!r}: port {got_port!r} is not the fixture port {port}")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise SafetyError(f"refusing {url!r}: only the server origin is expected")
    return f"https://{parts.hostname}:{port}"


def same_origin(url, origin):
    """Whether url points at exactly the given fixture origin."""
    try:
        return fixture_url(urllib.parse.urlsplit(url)._replace(path="", query="", fragment="").geturl()) == origin
    except SafetyError:
        return False


class SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only within the fixture origin."""

    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not same_origin(newurl, self.origin):
            raise urllib.error.HTTPError(req.full_url, code, f"refusing redirect to {newurl!r}: outside {self.origin}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def opener(origin, ssl_context):
    """A urllib opener that can only talk to the fixture origin."""
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context), SameOriginRedirects(origin))
