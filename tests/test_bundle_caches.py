"""Installed helpers leave a clean release directory after uninstall."""
import importlib.util
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "lib/bundle.py"


class TestBundleCaches(unittest.TestCase):
    def test_external_sb_is_never_claimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "lib"
            cli = base / "bin/sb"
            cli.parent.mkdir()
            external = base / "external"
            contents = b'#!/bin/sh\nSBKIT_VERSION="1.0"\n'
            external.write_bytes(contents)
            for kind in ("file", "link", "dangling"):
                if kind == "file":
                    cli.write_bytes(contents)
                else:
                    cli.symlink_to(external if kind == "link" else base / "missing")
                for args in (("publish", ROOT, root, cli), ("uninstall", root, cli)):
                    result = subprocess.run([sys.executable, BUNDLE, *args], capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(os.path.lexists(cli))
                    self.assertEqual(external.read_bytes(), contents)
                if kind == "file":
                    self.assertEqual(cli.read_bytes(), contents)
                cli.unlink()
            self.assertFalse(root.exists())

    def test_cache_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            installed = base / "lib"
            cli = base / "bin/sb"
            subprocess.run([sys.executable, BUNDLE, "publish", ROOT, installed, cli], check=True)
            lib = (installed / "VERSION").resolve().parent / "lib"
            cache = lib / "__pycache__"
            source = lib / "config_gen.py"

            # Exercise new installed commands with bytecode writing enabled.
            env = os.environ.copy()
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            subprocess.run([sys.executable, "-X", "pycache_prefix=", lib / "route_ownership.py",
                            "check", base / "config", base / "rules", base / "units", cli,
                            base / "backups", "off", "", ""], check=True, env=env)
            subprocess.run([sys.executable, "-X", "pycache_prefix=", lib / "managed_files.py",
                            "check-takeover", base / "acme"], check=True, env=env)
            self.assertFalse(cache.exists())
            cache.mkdir()
            name = Path(importlib.util.cache_from_source(str(source))).name
            old = cache / name
            py_compile.compile(str(source), cfile=str(old), doraise=True)
            other = cache / "operator.cpython-311.pyc"
            other.write_bytes(b"user data")
            bad = cache / "config_gen.cpython-38.pyc"
            # This filename may match the running interpreter on Ubuntu 20.04.
            if bad == old:
                bad = cache / "config_gen.cpython-39.pyc"
            bad.write_bytes(b"unrelated data")
            subprocess.run([sys.executable, BUNDLE, "uninstall", installed, cli], check=True)
            self.assertFalse(old.exists())
            self.assertEqual(other.read_bytes(), b"user data")
            self.assertEqual(bad.read_bytes(), b"unrelated data")


if __name__ == "__main__":
    unittest.main()
