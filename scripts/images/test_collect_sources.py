"""Offline tests for collect_sources.py (parsing and checks; no network)."""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect_sources as cs  # noqa: E402

APK_DB = """C:Q1abc=
P:busybox
V:1.37.0-r31
o:busybox
c:c3ef5d10e6ef6528852c51f0564963e2f8c1be19
L:GPL-2.0-only
F:bin

P:ssl_client
V:1.37.0-r31
o:busybox
c:c3ef5d10e6ef6528852c51f0564963e2f8c1be19
L:GPL-2.0-only
"""

DPKG = """Package: bash
Status: install ok installed
Version: 5.2.15-2+b13

Package: libssl3
Status: install ok installed
Source: openssl
Version: 3.0.22-1~deb12u1

Package: libattr1
Status: install ok installed
Source: attr (1:2.5.1-4)
Version: 1:2.5.1-4

Package: gone
Status: deinstall ok config-files
Version: 1.0
"""

DSC = """Format: 3.0 (quilt)
Source: attr
Checksums-Sha256:
 aaa 10 attr_2.5.1.orig.tar.xz
 bbb 20 attr_2.5.1-4.debian.tar.xz
Files:
 ccc 10 attr_2.5.1.orig.tar.xz
"""


class Parsing(unittest.TestCase):
    def test_apk_installed_keeps_origin_and_commit(self):
        pkgs = cs.parse_apk_installed(APK_DB)
        self.assertEqual([p["name"] for p in pkgs], ["busybox", "ssl_client"])
        self.assertEqual({p["origin"] for p in pkgs}, {"busybox"})
        self.assertEqual(pkgs[0]["commit"], "c3ef5d10e6ef6528852c51f0564963e2f8c1be19")

    def test_apk_package_without_commit_is_an_error(self):
        with self.assertRaises(cs.SourceError):
            cs.parse_apk_installed("P:x\nV:1\no:x\n")

    def test_dpkg_status_maps_binaries_to_exact_sources(self):
        got = {(p["source"], p["source_version"]) for p in cs.parse_dpkg_status(DPKG)}
        # binNMU suffix dropped, Source field honoured, epochs kept,
        # packages that are not installed ignored.
        self.assertEqual(got, {("bash", "5.2.15-2"), ("openssl", "3.0.22-1~deb12u1"), ("attr", "1:2.5.1-4")})

    def test_source_entries(self):
        self.assertEqual(cs.parse_source_entry("services-6.4::https://x/y/services"), ("services-6.4", "https://x/y/services"))
        self.assertEqual(cs.parse_source_entry("https://h/busybox-1.37.0.tar.bz2"), ("busybox-1.37.0.tar.bz2", "https://h/busybox-1.37.0.tar.bz2"))
        self.assertEqual(cs.parse_source_entry("bbsuid.c"), ("bbsuid.c", None))

    def test_unsafe_names_are_refused(self):
        for bad in ["../x", "a/b", "", ".."]:
            with self.assertRaises(cs.SourceError):
                cs.safe_name(bad)

    def test_apkbuild_sources_and_sums_must_match(self):
        cs.check_apkbuild({"a.tar.gz": "https://h/a.tar.gz"}, {"a.tar.gz": "x"}, "o")
        cs.check_apkbuild({}, {}, "meta-package")
        for sources, sums in [({}, {"a.tar.gz": "x"}), ({"a": None}, {}), ({"a": None}, {"b": "x"})]:
            with self.assertRaises(cs.SourceError):
                cs.check_apkbuild(sources, sums, "o")

    def test_dsc_checksums(self):
        self.assertEqual(cs.parse_dsc_sha256(DSC), {"attr_2.5.1.orig.tar.xz": "aaa", "attr_2.5.1-4.debian.tar.xz": "bbb"})

    def test_archive_names(self):
        self.assertEqual(cs.archive_name("ninja", "1.13.2", "https://codeload.github.com/n/n/tar.gz/3441b6"), "ninja-1.13.2.tar.gz")
        self.assertEqual(cs.archive_name("glib", "2.88.3", "https://d/glib-2.88.3.tar.xz"), "glib-2.88.3.tar.xz")


class Checks(unittest.TestCase):
    def test_fetch_checked_rejects_wrong_content_and_tries_the_mirror(self):
        body = {"https://up/f": b"tampered", "https://mirror/f": b"right"}

        def fake_download(url, dest, tries=5):
            dest.write_bytes(body[url])

        want = hashlib.sha512(b"right").hexdigest()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(cs, "download", fake_download):
            used = cs.fetch_checked(["https://up/f", "https://mirror/f"], Path(d) / "f", "sha512", want)
            self.assertEqual(used, "https://mirror/f")
            with self.assertRaises(cs.SourceError):
                cs.fetch_checked(["https://up/f"], Path(d) / "g", "sha512", want)
            self.assertFalse((Path(d) / "g").exists())

    def test_plain_http_is_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(cs.SourceError):
            cs.download("http://example.invalid/x", Path(d) / "x")

    def test_image_must_be_pinned_by_digest(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit):
            cs.main(["--image", "ghcr.io/a/b:tag", "--kind", "egress", "--out", d])


if __name__ == "__main__":
    unittest.main()
