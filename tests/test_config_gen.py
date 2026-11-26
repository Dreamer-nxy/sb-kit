#!/usr/bin/env python3
"""Unit tests for sb-kit config generator & SNI helper (stdlib only)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_GEN = ROOT / "lib" / "config_gen.py"
SNI_PROBE = ROOT / "lib" / "sni_probe.py"


def run_gen(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CONFIG_GEN), *args],
        capture_output=True,
        text=True,
        check=True,
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

    def test_vless_reality_add_and_modify(self) -> None:
        res = run_gen(
            "add",
            "--proto", "vless-reality",
            "--port", "443",
            "--ip", "1.2.3.4",
            "--country", "US",
            "--sni", "www.stanford.edu",
            "--conf-dir", str(self.conf_dir),
            "--meta-dir", str(self.meta_dir),
            "--state-dir", str(self.state_dir),
        )
        self.assertIn("TAG=vless-reality-443", res.stdout)
        self.assertIn("URI=vless://", res.stdout)
        self.assertIn("#US-VLESS-443", res.stdout)

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

    def test_hy2_acme_114_vs_113_and_self_signed(self) -> None:
        # sing-box 1.14 uses certificate_provider
        run_gen(
            "add", "--proto", "hy2", "--port", "8443", "--ip", "1.2.3.4",
            "--country", "JP", "--domain", "hy.example.com", "--sb-ver", "1.14.4",
            "--hop-range", "35000:36000",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        c14 = json.loads((self.conf_dir / "hy2-8443.json").read_text(encoding="utf-8"))
        self.assertIn("certificate_provider", c14["inbounds"][0]["tls"])
        self.assertEqual(c14["inbounds"][0]["tls"]["certificate_provider"]["type"], "acme")

        # sing-box 1.13 uses tls.acme + Cloudflare DNS-01
        run_gen(
            "add", "--proto", "hy2", "--port", "8444", "--ip", "1.2.3.4",
            "--country", "JP", "--domain", "hy2.example.com", "--sb-ver", "1.13.14",
            "--cf-token", "dummy-token",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        c13 = json.loads((self.conf_dir / "hy2-8444.json").read_text(encoding="utf-8"))
        self.assertIn("acme", c13["inbounds"][0]["tls"])
        self.assertEqual(c13["inbounds"][0]["tls"]["acme"]["dns01_challenge"]["provider"], "cloudflare")

        # Randomized self-signed cert fallback
        res_ss = run_gen(
            "add", "--proto", "hy2", "--port", "8445", "--ip", "1.2.3.4",
            "--country", "JP", "--self-signed",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("insecure=1", res_ss.stdout)
        self.assertIn("pinSHA256=", res_ss.stdout)

    def test_naive_anytls_ss2022_socks_and_exports(self) -> None:
        r_naive = run_gen(
            "add", "--proto", "naive", "--port", "9443", "--ip", "1.2.3.4",
            "--country", "SG", "--domain", "nv.example.com", "--sb-ver", "1.14.4",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("URI=naive+https://", r_naive.stdout)
        self.assertIn("QUIC_URI=naive+quic://", r_naive.stdout)
        c_naive = json.loads((self.conf_dir / "naive-9443.json").read_text(encoding="utf-8"))
        self.assertEqual(c_naive["inbounds"][0]["quic_congestion_control"], "bbr")

        r_any = run_gen(
            "add", "--proto", "anytls", "--port", "9444", "--ip", "1.2.3.4",
            "--country", "HK", "--domain", "at.example.com", "--sb-ver", "1.14.4",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("URI=anytls://", r_any.stdout)

        r_ss = run_gen(
            "add", "--proto", "ss2022", "--port", "38001", "--ip", "1.2.3.4",
            "--country", "US", "--whitelist", "9.9.9.9",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("URI=ss://", r_ss.stdout)

        r_socks = run_gen(
            "add", "--proto", "socks", "--port", "38002", "--ip", "1.2.3.4",
            "--country", "US", "--whitelist", "9.9.9.9",
            "--conf-dir", str(self.conf_dir), "--meta-dir", str(self.meta_dir), "--state-dir", str(self.state_dir),
        )
        self.assertIn("URI=socks5://", r_socks.stdout)
        self.assertIn("BROWSER=1.2.3.4:38002:", r_socks.stdout)

        # Verify links & yaml export
        links = run_gen("links", "--meta-dir", str(self.meta_dir))
        self.assertIn("指纹浏览器格式: 1.2.3.4:38002:", links.stdout)
        self.assertIn("naive+https://", links.stdout)

        yml = run_gen("yaml", "--meta-dir", str(self.meta_dir))
        self.assertIn("proxies:", yml.stdout)
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
