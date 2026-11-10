#!/usr/bin/env python3
"""Tests for the fixture safety checks. They touch no vault and no network."""
import io
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "fixture"))
import safety  # noqa: E402


class Paths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = os.path.realpath(self.tmp.name)
        self.fixture = os.path.join(base, "fixture")       # stands in for /tmp/bww-fixture
        self.real = os.path.join(base, "home", "Bitwarden CLI")  # stands in for the real vault
        self.roots = (self.fixture,)
        safety.create_root(self.fixture, self.roots)
        os.makedirs(os.path.join(self.fixture, "alice"))
        os.makedirs(self.real)
        self.real_data = os.path.join(self.real, "data.json")
        with open(self.real_data, "w") as f:
            f.write('{"real":"vault"}')

    def tearDown(self):
        self.tmp.cleanup()

    def test_inside(self):
        inside = os.path.join(self.fixture, "alice")
        self.assertEqual(safety.fixture_path(inside, self.roots), inside)
        self.assertEqual(safety.fixture_path(inside + "/./x/..", self.roots), inside)
        self.assertEqual(safety.fixture_path(self.fixture, self.roots), self.fixture)
        # not there yet is fine, as long as it would be inside
        self.assertTrue(safety.fixture_path(os.path.join(self.fixture, "new", "dir"), self.roots))

    def test_dotdot_traversal(self):
        for p in (self.fixture + "/../home/Bitwarden CLI", self.fixture + "/alice/../../home/Bitwarden CLI",
                  self.fixture + "x", self.fixture + "-other/alice", "/", "", "relative/path"):
            with self.assertRaises(safety.SafetyError, msg=p):
                safety.fixture_path(p, self.roots)

    def test_reviewed_example(self):
        with self.assertRaises(safety.SafetyError):
            safety.fixture_path(safety.FIXTURE_ROOT + "/../../home/someone/.config/Bitwarden CLI")

    def test_symlink_escape(self):
        link = os.path.join(self.fixture, "looks-harmless")
        os.symlink(self.real, link)
        for p in (link, os.path.join(link, "data.json")):
            with self.assertRaises(safety.SafetyError, msg=p):
                safety.fixture_path(p, self.roots)
        # a data.json inside a fixture dir that is itself a link to a real vault
        os.symlink(self.real_data, os.path.join(self.fixture, "alice", "data.json"))
        with self.assertRaises(safety.SafetyError):
            safety.fixture_path(os.path.join(self.fixture, "alice", "data.json"), self.roots)

    def test_root_redirected_onto_a_real_vault(self):
        """The allowed name itself points at a real vault: the reviewed case."""
        base = os.path.dirname(self.fixture)
        redirected = os.path.join(base, "redirected")
        os.symlink(self.real, redirected)
        roots = (redirected,)
        for p in (redirected, os.path.join(redirected, "data.json")):
            with self.assertRaises(safety.SafetyError, msg=p):
                safety.fixture_path(p, roots)
        for fn in (safety.read_file, lambda p, r: safety.write_file(p, "x", r)):
            with self.assertRaises(safety.SafetyError):
                fn(os.path.join(redirected, "data.json"), roots)
        with self.assertRaises(safety.SafetyError):
            safety.create_root(redirected, roots)  # an existing target is never adopted
        # a parent of the root is a link: the root is "reached through" one
        os.symlink(base, os.path.join(base, "alias"))
        aliased = os.path.join(base, "alias", "fixture")
        with self.assertRaises(safety.SafetyError):
            safety.fixture_path(os.path.join(aliased, "alice"), (aliased,))
        self.assertEqual(open(self.real_data).read(), '{"real":"vault"}')

    def test_unmarked_directory_is_not_a_fixture(self):
        plain = os.path.join(os.path.dirname(self.fixture), "plain")
        os.makedirs(plain)
        with self.assertRaises(safety.SafetyError):
            safety.fixture_path(plain, (plain,))
        with self.assertRaises(safety.SafetyError):
            safety.create_root(plain, (plain,))
        with self.assertRaises(safety.SafetyError):
            safety.create_root(plain + "-other", (plain,))  # not an allowed name

    def test_write_refuses_every_escape(self):
        """Links at an intermediate directory and at data.json: refused before any write."""
        before = open(self.real_data).read()
        os.symlink(self.real, os.path.join(self.fixture, "bob"))          # intermediate directory
        os.symlink(self.real_data, os.path.join(self.fixture, "alice", "data.json"))  # the file itself
        for p in (os.path.join(self.fixture, "bob", "data.json"), os.path.join(self.fixture, "alice", "data.json"),
                  self.fixture + "/alice/../../home/Bitwarden CLI/data.json"):
            with self.assertRaises(safety.SafetyError, msg=p):
                safety.write_file(p, "overwritten", self.roots)
            with self.assertRaises(safety.SafetyError, msg=p):
                safety.read_file(p, self.roots)
        self.assertEqual(open(self.real_data).read(), before)
        os.remove(os.path.join(self.fixture, "alice", "data.json"))
        ok = os.path.join(self.fixture, "alice", "data.json")
        safety.write_file(ok, "fixture data", self.roots)
        self.assertEqual(safety.read_file(ok, self.roots), "fixture data")
        self.assertFalse(os.path.islink(ok))

    def test_expire_session_refuses_before_touching(self):
        """The token-rewriting tool itself: traversal and a planted link are refused, the target is not modified."""
        before = open(self.real_data).read()
        script = os.path.join(HERE, "expire_session.py")
        safety.create_root(safety.DEV_ROOT)
        planted = tempfile.mkdtemp(dir=safety.DEV_ROOT, prefix="safety-test-")
        try:
            os.symlink(self.real_data, os.path.join(planted, "data.json"))
            for target in (safety.DEV_ROOT + "/.." + self.real, safety.FIXTURE_ROOT + "/../.." + self.real, planted):
                p = subprocess.run([sys.executable, script, target, "clock"], capture_output=True, text=True)
                self.assertNotEqual(p.returncode, 0, target)
                self.assertIn("refusing", p.stderr, target)
                self.assertEqual(open(self.real_data).read(), before, target)
        finally:
            os.remove(os.path.join(planted, "data.json"))
            os.rmdir(planted)


class Urls(unittest.TestCase):
    def test_fixture_origin(self):
        for u in ("https://127.0.0.1:18087", "https://127.0.0.1:18087/", "https://localhost:18087"):
            self.assertTrue(safety.fixture_url(u).startswith("https://"))

    def test_rejected(self):
        for u in (
            "https://127.0.0.1:18087@remote.example",       # the reviewed example: host is remote.example
            "https://127.0.0.1:18087@remote.example:18087",
            "https://user:pw@127.0.0.1:18087",              # user information at all
            "https://user@127.0.0.1:18087",
            "http://127.0.0.1:18087",                       # scheme
            "https://127.0.0.1:443", "https://127.0.0.1",   # port
            "https://127.0.0.1.remote.example:18087", "https://remote.example:18087", "https://[::1]:18087",
            "https://127.0.0.1:18087/api", "https://127.0.0.1:18087/?x=1", "https://127.0.0.1:18087#f",
            "https://127.0.0.1:notaport", "", "127.0.0.1:18087", "file:///etc/passwd",
        ):
            with self.assertRaises(safety.SafetyError, msg=u):
                safety.fixture_url(u)

    def test_redirects(self):
        origin = "https://127.0.0.1:18087"
        handler = safety.SameOriginRedirects(origin)
        req = urllib.request.Request(origin + "/identity/connect/token", data=b"secret=1", method="POST")
        for target in ("https://remote.example/steal", "https://127.0.0.1:18087@remote.example/", "http://127.0.0.1:18087/x",
                       "https://127.0.0.1:9999/x", "https://user@127.0.0.1:18087/x"):
            with self.assertRaises(urllib.error.HTTPError, msg=target):
                handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, target)
        # a redirect that stays on the fixture origin is followed
        get = urllib.request.Request(origin + "/a")
        self.assertIsNotNone(handler.redirect_request(get, io.BytesIO(), 302, "Found", {}, origin + "/b"))

    def test_vw_api_refuses_before_any_request(self):
        """The API tool with the reviewed URL: it exits before it could send anything."""
        env = dict(os.environ, BWW_FIXTURE_URL="https://127.0.0.1:18087@remote.example")
        p = subprocess.run([sys.executable, os.path.join(HERE, "fixture", "vw_api.py"), "register", "x@example.test", "pw"],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("refusing", p.stderr)


if __name__ == "__main__":
    unittest.main()
