#!/usr/bin/env python3
"""Unit & regression tests for sb-kit config generator & SNI helper (stdlib only)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
CONFIG_GEN = ROOT / "lib" / "config_gen.py"
SNI_PROBE = ROOT / "lib" / "sni_probe.py"
sys.path.insert(0, str(ROOT / "lib"))
import config_gen  # noqa: E402


def run_gen(*args: str, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    merged_env.pop("SB_CF_TOKEN", None)
    if env:
        merged_env.update(env)
    return subprocess.run(
        [sys.executable, str(CONFIG_GEN), *args],
        capture_output=True,
        text=True,
        env=merged_env,
        check=check,
    )


class TestSbKitConfigGen(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.conf_dir = base / "conf"
        self.meta_dir = base / "meta"
        self.state_dir = base / "state"
        self.conf_dir.mkdir()
        self.meta_dir.mkdir()
        self.state_dir.mkdir()
        self.dirs = [
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir),
            "--state-dir", str(self.state_dir),
        ]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_base_config_default_and_block_cn(self) -> None:
        out_default = Path(self.tmp.name) / "config.json"
        run_gen("base-config", "--out", str(out_default))
        cfg = json.loads(out_default.read_text(encoding="utf-8"))
        self.assertEqual(cfg["log"]["level"], "error")
        self.assertEqual(cfg["route"]["final"], "direct")
        self.assertNotIn("rule_set", cfg["route"])
        self.assertTrue(any(r.get("ip_is_private") for r in cfg["route"]["rules"]))
        self.assertTrue(any(r.get("protocol") == "bittorrent" for r in cfg["route"]["rules"]))

        out_cn = Path(self.tmp.name) / "config_cn.json"
        run_gen("base-config", "--out", str(out_cn), "--cn-srs", "/etc/sing-box/rules/geoip-cn.srs")
        cfg_cn = json.loads(out_cn.read_text(encoding="utf-8"))
        self.assertEqual(cfg_cn["route"]["rule_set"][0]["tag"], "geoip-cn")
        self.assertTrue(any(r.get("rule_set") == ["geoip-cn"] for r in cfg_cn["route"]["rules"]))

    def test_vless_reality_real_x25519_perms_and_modify(self) -> None:
        res = run_gen(
            "add",
            "--proto", "vless-reality",
            "--port", "443",
            "--ip", "1.2.3.4",
            "--country", "US",
            "--sni", "www.mozilla.org",
            "--conf-dir", str(self.conf_dir),
            "--meta-dir", str(self.meta_dir),
            "--state-dir", str(self.state_dir),
        )
        self.assertIn("TAG=vless-reality-443", res.stdout)
        self.assertIn("#US-VLESS-443", res.stdout)

        meta_path = self.meta_dir / "vless-reality-443.json"
        self.assertEqual(stat.S_IMODE(meta_path.stat().st_mode), 0o600)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))

        # Verify pure-Python X25519 actually derived pub from priv (not fake random bytes).
        priv_bytes = base64.urlsafe_b64decode(meta["private_key"] + "==")
        derived_pub = base64.urlsafe_b64encode(
            config_gen.x25519(priv_bytes, (9).to_bytes(32, "little"))
        ).decode("ascii").rstrip("=")
        self.assertEqual(meta["public_key"], derived_pub)

        conf = json.loads((self.conf_dir / "vless-reality-443.json").read_text(encoding="utf-8"))
        ib = conf["inbounds"][0]
        self.assertEqual(ib["listen_port"], 443)
        self.assertEqual(ib["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(ib["tls"]["reality"]["max_time_difference"], "5m")
        self.assertEqual(len(ib["tls"]["reality"]["short_id"][0]), 16)
        self.assertNotIn("outbounds", conf)

        # Modify port + SNI + rotate creds
        old_uuid = ib["users"][0]["uuid"]
        mod = run_gen(
            "modify",
            "--tag", "vless-reality-443",
            "--port", "8443",
            "--sni", "www.freebsd.org",
            "--rotate-creds",
            "--conf-dir", str(self.conf_dir),
            "--meta-dir", str(self.meta_dir),
            "--state-dir", str(self.state_dir),
        )
        self.assertIn("TAG=vless-reality-8443", mod.stdout)
        self.assertIn("#US-VLESS-8443", mod.stdout)
        self.assertFalse((self.conf_dir / "vless-reality-443.json").exists())
        new_conf = json.loads((self.conf_dir / "vless-reality-8443.json").read_text(encoding="utf-8"))
        self.assertNotEqual(new_conf["inbounds"][0]["users"][0]["uuid"], old_uuid)
        self.assertEqual(new_conf["inbounds"][0]["tls"]["server_name"], "www.freebsd.org")

    def test_modify_preserves_dns01_token_and_recovers_legacy_meta(self) -> None:
        run_gen(
            "add", "--proto", "hy2", "--port", "8443", "--ip", "1.2.3.4",
            "--country", "JP", "--domain", "hy.example.com", "--sb-ver", "1.14.4",
            "--hop-range", "35000:36000", "--masquerade", "https://www.debian.org",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
            env={"SB_CF_TOKEN": "secret-cf-token-1"},
        )
        c1 = json.loads((self.conf_dir / "hy2-8443.json").read_text(encoding="utf-8"))
        self.assertEqual(c1["inbounds"][0]["tls"]["certificate_provider"]["dns01_challenge"]["api_token"], "secret-cf-token-1")
        self.assertEqual(c1["inbounds"][0]["masquerade"], "https://www.debian.org")

        # Simulate legacy meta missing cf_token -> modify must still recover it from conf!
        m_path = self.meta_dir / "hy2-8443.json"
        legacy_meta = json.loads(m_path.read_text(encoding="utf-8"))
        legacy_meta.pop("cf_token", None)
        m_path.write_text(json.dumps(legacy_meta), encoding="utf-8")

        mod = run_gen(
            "modify", "--tag", "hy2-8443", "--port", "8448",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("HOP_RANGE=35000:36000", mod.stdout)
        c2 = json.loads((self.conf_dir / "hy2-8448.json").read_text(encoding="utf-8"))
        self.assertEqual(c2["inbounds"][0]["tls"]["certificate_provider"]["dns01_challenge"]["api_token"], "secret-cf-token-1")
        self.assertEqual(c2["inbounds"][0]["masquerade"], "https://www.debian.org")

        # Clear hop-range explicitly
        mod2 = run_gen(
            "modify", "--tag", "hy2-8448", "--clear-hop-range",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("HOP_RANGE=\n", mod2.stdout)

    def test_self_signed_cert_reused_on_modify_and_rotated_on_flag(self) -> None:
        r1 = run_gen(
            "add", "--proto", "hy2", "--port", "8445", "--ip", "1.2.3.4",
            "--country", "JP", "--self-signed",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("pinSHA256=", r1.stdout)
        m1 = json.loads((self.meta_dir / "hy2-8445.json").read_text(encoding="utf-8"))
        self.assertTrue((Path(m1["self_cert"]).parent / ".managed-by-sb-kit").is_file())

        # Port change alone must REUSE the existing cert & keep pinSHA256 identical.
        run_gen(
            "modify", "--tag", "hy2-8445", "--port", "8449",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        m2 = json.loads((self.meta_dir / "hy2-8449.json").read_text(encoding="utf-8"))
        self.assertEqual(m2["pin_sha256"], m1["pin_sha256"])
        self.assertEqual(m2["self_cert"], m1["self_cert"])
        self.assertEqual(m2["self_key"], m1["self_key"])
        old_key = Path(m2["self_key"]).read_bytes()

        # Explicit --rotate-creds re-issues cert & changes pinSHA256.
        run_gen(
            "modify", "--tag", "hy2-8449", "--rotate-creds",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        m3 = json.loads((self.meta_dir / "hy2-8449.json").read_text(encoding="utf-8"))
        self.assertNotEqual(m3["pin_sha256"], m1["pin_sha256"])
        self.assertNotEqual(m3["self_cert"], m2["self_cert"])
        # A failed restart may restore the previous metadata and inbound.
        old_der = ssl.PEM_cert_to_DER_cert(Path(m2["self_cert"]).read_text())
        self.assertEqual(hashlib.sha256(old_der).hexdigest(), m2["pin_sha256"].replace(":", "").lower())
        self.assertEqual(Path(m2["self_key"]).read_bytes(), old_key)

    def test_legacy_self_signed_port_reuse_and_rejected_edits(self) -> None:
        def add(port: str, check: bool = True) -> subprocess.CompletedProcess[str]:
            return run_gen("add", "--proto", "hy2", "--port", port, "--ip", "192.0.2.1",
                           "--self-signed", *self.dirs, check=check)

        add("8445")
        # Early versions named certificate files after the tag and did not store their paths in meta.
        old_tag = "hy2-8445"
        path = self.meta_dir / f"{old_tag}.json"
        old = json.loads(path.read_text())
        tls = json.loads((self.conf_dir / path.name).read_text())
        for field, key, suffix in (("self_cert", "certificate_path", ".crt"), ("self_key", "key_path", ".key")):
            legacy = self.state_dir / "certs" / (old_tag + suffix)
            Path(old.pop(field)).rename(legacy)
            tls["inbounds"][0]["tls"][key] = str(legacy)
        path.write_text(json.dumps(old))
        (self.conf_dir / path.name).write_text(json.dumps(tls))

        run_gen("modify", "--tag", old_tag, "--port", "8449", *self.dirs)
        add("8445")
        moved = json.loads((self.meta_dir / "hy2-8449.json").read_text())
        replacement = json.loads(path.read_text())
        self.assertNotEqual(replacement["self_cert"], moved["self_cert"])
        der = ssl.PEM_cert_to_DER_cert(Path(moved["self_cert"]).read_text())
        self.assertEqual(hashlib.sha256(der).hexdigest(), old["pin_sha256"].replace(":", "").lower())

        before = {p: p.read_bytes() for p in self.state_dir.rglob("*") if p.is_file()}
        self.assertNotEqual(add("8445", check=False).returncode, 0)
        clashing = run_gen("modify", "--tag", "hy2-8449", "--port", "8445",
                           "--rotate-creds", *self.dirs, check=False)
        self.assertNotEqual(clashing.returncode, 0)
        self.assertEqual(before, {p: p.read_bytes() for p in self.state_dir.rglob("*") if p.is_file()})

        legacy_cert = Path(moved["self_cert"])
        legacy_cert.write_bytes(Path(replacement["self_cert"]).read_bytes())
        mismatched = run_gen("regen", *self.dirs, check=False)
        self.assertNotEqual(mismatched.returncode, 0)
        self.assertIn("fingerprint mismatch", mismatched.stderr)
        legacy_cert.write_bytes(before[legacy_cert])
        Path(moved["self_key"]).unlink()
        broken = run_gen("regen", *self.dirs, check=False)
        self.assertNotEqual(broken.returncode, 0)
        self.assertIn("self-signed certificate or key missing", broken.stderr)
        self.assertFalse(Path(moved["self_key"]).exists())

    def test_regen_upgrades_113_acme_to_114_certificate_provider(self) -> None:
        run_gen(
            "add", "--proto", "hy2", "--port", "8444", "--ip", "1.2.3.4",
            "--country", "JP", "--domain", "hy13.example.com", "--sb-ver", "1.13.14",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
            env={"SB_CF_TOKEN": "token-113"},
        )
        c13 = json.loads((self.conf_dir / "hy2-8444.json").read_text(encoding="utf-8"))
        self.assertIn("acme", c13["inbounds"][0]["tls"])
        self.assertNotIn("certificate_provider", c13["inbounds"][0]["tls"])

        reg = run_gen(
            "regen", "--sb-ver", "1.14.4",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("COUNT=1", reg.stdout)
        c14 = json.loads((self.conf_dir / "hy2-8444.json").read_text(encoding="utf-8"))
        self.assertIn("certificate_provider", c14["inbounds"][0]["tls"])
        self.assertNotIn("acme", c14["inbounds"][0]["tls"])
        self.assertEqual(c14["inbounds"][0]["tls"]["certificate_provider"]["dns01_challenge"]["api_token"], "token-113")

    def test_normalize_ips_v4_v6_and_rejects_injection(self) -> None:
        ok = run_gen("normalize-ips", "1.2.3.4, 10.0.0.0/8, 2001:db8::1, 2001:db8::/32")
        self.assertIn("V4=1.2.3.4, 10.0.0.0/8", ok.stdout)
        self.assertIn("V6=2001:db8::1, 2001:db8::/32", ok.stdout)

        bad = run_gen("normalize-ips", "1.2.3.4; rm -rf /", check=False)
        self.assertNotEqual(bad.returncode, 0)

    def test_regen_invalid_late_metadata_keeps_entire_batch(self) -> None:
        run_gen("add", "--proto", "hy2", "--port", "8444", "--domain", "hy.example.com",
                "--sb-ver", "1.13.14", "--ip", "192.0.2.1", *self.dirs)
        run_gen("add", "--proto", "socks", "--port", "30001", "--ip", "192.0.2.1", *self.dirs)
        path = self.meta_dir / "socks-30001.json"
        old = json.loads(path.read_text())
        missing_password = dict(old)
        del missing_password["password"]
        for bad in ("{", "[]", json.dumps(missing_password), json.dumps(dict(old, tag="socks-30002"))):
            with self.subTest(metadata=bad[:2]):
                path.write_text(bad)
                snapshots = {p: p.read_bytes() for p in Path(self.tmp.name).rglob("*.json")}
                result = run_gen("regen", "--sb-ver", "1.14.4", *self.dirs, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(path.name, result.stderr)
                self.assertNotIn("REGEN=", result.stdout)
                self.assertEqual(snapshots, {p: p.read_bytes() for p in Path(self.tmp.name).rglob("*.json")})

    def test_batch_publish_io_failure_restores_originals(self) -> None:
        existing = self.conf_dir / "a.json"
        new = self.conf_dir / "b.json"
        failing = self.meta_dir / "b.json"
        existing.write_bytes(b"original\n")
        original_inode = existing.stat().st_ino
        replace = os.replace

        def fail_on_last_commit(source: Path, dest: Path) -> None:
            if dest == failing:
                raise OSError("simulated commit failure")
            replace(source, dest)

        files = [(existing, {}, 0o640), (new, {}, 0o640), (failing, {}, 0o600)]
        with mock.patch.object(config_gen.os, "replace", side_effect=fail_on_last_commit):
            with self.assertRaisesRegex(OSError, "simulated commit failure"):
                config_gen.publish_node_files(files)
        self.assertEqual(existing.read_bytes(), b"original\n")
        self.assertEqual(existing.stat().st_ino, original_inode)
        self.assertEqual(list(self.conf_dir.iterdir()), [existing])
        self.assertEqual(list(self.meta_dir.iterdir()), [])

    def test_naive_anytls_ss2022_sip002_socks_and_yaml_escaping(self) -> None:
        r_naive = run_gen(
            "add", "--proto", "naive", "--port", "9443", "--ip", "1.2.3.4",
            "--country", "SG", "--domain", "nv.example.com", "--sb-ver", "1.14.4",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("URI=naive+https://", r_naive.stdout)
        self.assertIn("QUIC_URI=naive+quic://", r_naive.stdout)

        run_gen(
            "add", "--proto", "anytls", "--port", "10443", "--ip", "1.2.3.4",
            "--country", "HK", "--domain", "at.example.com", "--remark", 'HK "Quoted" \\ Node',
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )

        r_ss = run_gen(
            "add", "--proto", "ss2022", "--port", "38001", "--ip", "1.2.3.4",
            "--country", "US", "--whitelist", "9.9.9.9,2001:db8::1",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        uri = next(line[4:] for line in r_ss.stdout.splitlines() if line.startswith("URI="))
        parsed = urllib.parse.urlsplit(uri)
        ss_meta = json.loads((self.meta_dir / "ss2022-38001.json").read_text())
        self.assertEqual(parsed.username, ss_meta["method"])
        self.assertEqual(urllib.parse.unquote(parsed.password), ss_meta["password"])
        ss_meta["password"] = "+/8="
        special_uri, _ = config_gen.format_uri(ss_meta)
        self.assertEqual(urllib.parse.urlsplit(special_uri).password, "%2B%2F8%3D")

        r_socks = run_gen(
            "add", "--proto", "socks", "--port", "38002", "--ip", "1.2.3.4",
            "--country", "US", "--whitelist", "9.9.9.9",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("URI=socks5://", r_socks.stdout)
        self.assertIn("BROWSER=1.2.3.4:38002:", r_socks.stdout)

        links = run_gen("links", "--meta-dir", str(self.meta_dir))
        self.assertIn("指纹浏览器格式: 1.2.3.4:38002:", links.stdout)

        yml = run_gen("yaml", "--meta-dir", str(self.meta_dir))
        self.assertIn(r'name: "HK \"Quoted\" \\ Node"', yml.stdout)
        self.assertIn("type: anytls", yml.stdout)
        self.assertIn("type: socks5", yml.stdout)

    def test_sni_probe_country_rtt_mapping(self) -> None:
        out_us = subprocess.check_output(
            [sys.executable, str(SNI_PROBE), "--country-info", "--country", "US"], text=True
        ).strip()
        self.assertEqual(out_us, "US|160")
        out_jp = subprocess.check_output(
            [sys.executable, str(SNI_PROBE), "--country-info", "--country", "JP"], text=True
        ).strip()
        self.assertEqual(out_jp, "JP|75")


if __name__ == "__main__":
    unittest.main()
