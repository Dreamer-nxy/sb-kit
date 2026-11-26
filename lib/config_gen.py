#!/usr/bin/env python3
"""Pure sing-box config generator, in-place modifier, and share-link / YAML exporter.

Zero external dependencies (Python 3 stdlib only).
Supports sing-box 1.13.x and 1.14.x+ (automatically adapts ACME `acme` vs `certificate_provider`).
Protocols:
  - vless-reality : VLESS + REALITY + xtls-rprx-vision
  - hy2           : Hysteria 2
  - naive         : NaiveProxy (HTTP/2 + HTTP/3 QUIC BBR)
  - anytls        : AnyTLS (sing-box 1.12+)
  - ss2022        : Shadowsocks-2022 (2022-blake3-aes-256-gcm)
  - socks         : Socks5 (username + password, fingerprint-browser friendly)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


PROTO_LABELS = {
    "vless-reality": "VLESS",
    "hy2": "Hy2",
    "naive": "Naive",
    "anytls": "AnyTLS",
    "ss2022": "SS2022",
    "socks": "Socks",
}


def parse_semver(ver: str) -> Tuple[int, int]:
    cleaned = (ver or "").strip().lstrip("v")
    parts = cleaned.split(".")
    try:
        return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return (1, 14)


def random_alnum(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def format_host_for_uri(host: str) -> str:
    h = host.strip()
    if ":" in h and not h.startswith("["):
        return f"[{h}]"
    return h


def atomic_write_json(path: Path, data: Dict[str, Any], mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def generate_reality_keypair(sb_bin: Optional[str]) -> Tuple[str, str]:
    if sb_bin and os.path.isfile(sb_bin) and os.access(sb_bin, os.X_OK):
        out = subprocess.check_output([sb_bin, "generate", "reality-keypair"], text=True)
        priv = pub = ""
        for line in out.splitlines():
            if "PrivateKey" in line:
                priv = line.split(":", 1)[1].strip()
            elif "PublicKey" in line:
                pub = line.split(":", 1)[1].strip()
        if priv and pub:
            return priv, pub
    # Fallback for local dry-run/unit-test environments without sing-box installed.
    priv = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    pub = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return priv, pub


def generate_self_signed_cert(state_dir: Path, tag: str) -> Tuple[str, str, str]:
    cert_dir = state_dir / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / f"{tag}.crt"
    key_path = cert_dir / f"{tag}.key"
    # Randomized CN/O and non-fixed validity to avoid well-known script fingerprints.
    rand_cn = f"{secrets.token_hex(4)}.local"
    days = str(365 + secrets.randbelow(700))
    if shutil.which("openssl"):
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-days", days, "-nodes",
                "-keyout", str(key_path),
                "-out", str(cert_path),
                "-subj", f"/CN={rand_cn}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        fp_out = subprocess.check_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-sha256", "-fingerprint"],
            text=True,
        )
        pin_sha256 = fp_out.split("=", 1)[1].strip()
    else:
        cert_path.write_text("DRY_RUN_CERT\n", encoding="utf-8")
        key_path.write_text("DRY_RUN_KEY\n", encoding="utf-8")
        pin_sha256 = "00" * 32
    os.chmod(cert_path, 0o644)
    os.chmod(key_path, 0o640)
    return str(cert_path), str(key_path), pin_sha256


def build_tls_object(
    sb_ver: str,
    state_dir: Path,
    tag: str,
    domain: str = "",
    cert: str = "",
    key: str = "",
    email: str = "",
    cf_token: str = "",
    self_signed: bool = False,
    alpn: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    tls: Dict[str, Any] = {"enabled": True}
    extra_meta: Dict[str, Any] = {"tls_mode": "acme", "pin_sha256": ""}
    if alpn:
        tls["alpn"] = alpn

    if cert and key:
        tls["certificate_path"] = cert
        tls["key_path"] = key
        if domain:
            tls["server_name"] = domain
        extra_meta["tls_mode"] = "custom-cert"
        return tls, extra_meta

    if self_signed or not domain:
        cert_path, key_path, pin = generate_self_signed_cert(state_dir, tag)
        tls["certificate_path"] = cert_path
        tls["key_path"] = key_path
        extra_meta["tls_mode"] = "self-signed"
        extra_meta["pin_sha256"] = pin
        return tls, extra_meta

    tls["server_name"] = domain
    acme_dir = str(state_dir / "acme")
    major, minor = parse_semver(sb_ver)
    acme_cfg: Dict[str, Any] = {
        "domain": [domain],
        "provider": "letsencrypt",
        "data_directory": acme_dir,
    }
    if email:
        acme_cfg["email"] = email
    if cf_token:
        acme_cfg["dns01_challenge"] = {
            "provider": "cloudflare",
            "api_token": cf_token,
        }
        extra_meta["tls_mode"] = "acme-dns01"

    if (major, minor) >= (1, 14):
        acme_cfg["type"] = "acme"
        tls["certificate_provider"] = acme_cfg
    else:
        tls["acme"] = acme_cfg

    return tls, extra_meta


def cmd_base_config(args: argparse.Namespace) -> int:
    rules: List[Dict[str, Any]] = [
        {"action": "sniff", "timeout": "300ms"},
        {"ip_is_private": True, "action": "reject"},
        {"port": [25], "action": "reject"},
        {"protocol": "bittorrent", "action": "reject"},
    ]
    route: Dict[str, Any] = {
        "rules": rules,
        "final": "direct",
    }
    if args.cn_srs:
        route["rule_set"] = [
            {
                "tag": "geoip-cn",
                "type": "local",
                "format": "binary",
                "path": args.cn_srs,
            }
        ]
        rules.append({"rule_set": ["geoip-cn"], "action": "reject"})

    cfg = {
        "log": {
            "output": args.log_file,
            "level": args.log_level,
            "timestamp": True,
        },
        "outbounds": [
            {
                "tag": "direct",
                "type": "direct",
            }
        ],
        "route": route,
    }
    atomic_write_json(Path(args.out), cfg, mode=0o640)
    return 0


def format_uri(meta: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Return (primary_uri, extra_lines) for clean terminal display."""
    proto = meta["proto"]
    port = meta["port"]
    ip = meta["ip"]
    domain = meta.get("domain", "")
    remark = urllib.parse.quote(meta.get("remark", meta["tag"]), safe="-_.")
    extras: List[str] = []

    if proto == "vless-reality":
        host = format_host_for_uri(ip)
        params = urllib.parse.urlencode([
            ("encryption", "none"),
            ("flow", "xtls-rprx-vision"),
            ("security", "reality"),
            ("sni", meta["sni"]),
            ("fp", "chrome"),
            ("pbk", meta["public_key"]),
            ("sid", meta["short_id"]),
            ("type", "tcp"),
        ])
        return f"vless://{meta['uuid']}@{host}:{port}?{params}#{remark}", extras

    if proto == "hy2":
        host = domain if domain else format_host_for_uri(ip)
        q: List[Tuple[str, str]] = []
        if domain:
            q.append(("sni", domain))
        if meta.get("tls_mode") == "self-signed":
            q.append(("insecure", "1"))
            if meta.get("pin_sha256"):
                q.append(("pinSHA256", meta["pin_sha256"]))
        if meta.get("hop_range"):
            q.append(("mport", meta["hop_range"].replace(":", "-")))
        qs = f"?{urllib.parse.urlencode(q)}" if q else ""
        pw = urllib.parse.quote(meta["password"], safe="")
        return f"hysteria2://{pw}@{host}:{port}{qs}#{remark}", extras

    if proto == "naive":
        host = domain if domain else format_host_for_uri(ip)
        user = urllib.parse.quote(meta["username"], safe="")
        pw = urllib.parse.quote(meta["password"], safe="")
        h2 = f"naive+https://{user}:{pw}@{host}:{port}#{remark}"
        h3 = f"naive+quic://{user}:{pw}@{host}:{port}#{remark}-QUIC"
        extras.append(f"QUIC_URI={h3}")
        return h2, extras

    if proto == "anytls":
        host = domain if domain else format_host_for_uri(ip)
        q = []
        if domain:
            q.append(("sni", domain))
        if meta.get("tls_mode") == "self-signed":
            q.append(("insecure", "1"))
        qs = f"?{urllib.parse.urlencode(q)}" if q else ""
        pw = urllib.parse.quote(meta["password"], safe="")
        return f"anytls://{pw}@{host}:{port}{qs}#{remark}", extras

    if proto == "ss2022":
        host = format_host_for_uri(ip)
        userinfo = base64.urlsafe_b64encode(
            f"{meta['method']}:{meta['password']}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        return f"ss://{userinfo}@{host}:{port}#{remark}", extras

    if proto == "socks":
        host = format_host_for_uri(ip)
        user = urllib.parse.quote(meta["username"], safe="")
        pw = urllib.parse.quote(meta["password"], safe="")
        fp_line = f"{ip}:{port}:{meta['username']}:{meta['password']}"
        extras.append(f"BROWSER={fp_line}")
        return f"socks5://{user}:{pw}@{host}:{port}#{remark}", extras

    raise ValueError(f"Unsupported protocol: {proto}")


def build_inbound_and_meta(
    proto: str,
    port: int,
    ip: str,
    country: str,
    sb_ver: str,
    state_dir: Path,
    sb_bin: Optional[str] = None,
    sni: str = "",
    domain: str = "",
    cert: str = "",
    key: str = "",
    email: str = "",
    cf_token: str = "",
    self_signed: bool = False,
    hop_range: str = "",
    whitelist: str = "",
    remark: str = "",
    existing_meta: Optional[Dict[str, Any]] = None,
    rotate_creds: bool = False,
) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    tag = f"{proto}-{port}"
    cc = (country or "VPS").upper()
    default_remark = f"{cc}-{PROTO_LABELS.get(proto, proto)}-{port}"
    final_remark = remark or (
        existing_meta.get("remark", default_remark) if existing_meta and not remark else default_remark
    )
    # If port changed and remark was the auto-generated default, refresh the port suffix.
    if existing_meta and not remark:
        old_default = f"{existing_meta.get('country', cc)}-{PROTO_LABELS.get(proto, proto)}-{existing_meta.get('port')}"
        if existing_meta.get("remark") == old_default:
            final_remark = default_remark

    meta: Dict[str, Any] = {
        "tag": tag,
        "proto": proto,
        "port": port,
        "ip": ip,
        "country": cc,
        "remark": final_remark,
        "sb_ver": sb_ver,
    }

    if proto == "vless-reality":
        if not sni:
            raise ValueError("vless-reality requires --sni")
        if existing_meta and not rotate_creds:
            user_uuid = existing_meta["uuid"]
            priv_key = existing_meta["private_key"]
            pub_key = existing_meta["public_key"]
            short_id = existing_meta["short_id"]
        else:
            user_uuid = str(uuid.uuid4())
            priv_key, pub_key = generate_reality_keypair(sb_bin)
            short_id = secrets.token_hex(8)
        inbound: Dict[str, Any] = {
            "type": "vless",
            "tag": tag,
            "listen": "::",
            "listen_port": port,
            "users": [
                {
                    "name": "default",
                    "uuid": user_uuid,
                    "flow": "xtls-rprx-vision",
                }
            ],
            "tls": {
                "enabled": True,
                "server_name": sni,
                "reality": {
                    "enabled": True,
                    "handshake": {
                        "server": sni,
                        "server_port": 443,
                    },
                    "private_key": priv_key,
                    "short_id": [short_id],
                    "max_time_difference": "5m",
                },
            },
        }
        meta.update({
            "uuid": user_uuid,
            "sni": sni,
            "private_key": priv_key,
            "public_key": pub_key,
            "short_id": short_id,
        })

    elif proto == "hy2":
        password = (
            existing_meta["password"]
            if (existing_meta and not rotate_creds and existing_meta.get("password"))
            else random_alnum(24)
        )
        tls, tls_meta = build_tls_object(
            sb_ver=sb_ver,
            state_dir=state_dir,
            tag=tag,
            domain=domain,
            cert=cert,
            key=key,
            email=email,
            cf_token=cf_token,
            self_signed=self_signed,
            alpn=["h3"],
        )
        inbound = {
            "type": "hysteria2",
            "tag": tag,
            "listen": "::",
            "listen_port": port,
            "ignore_client_bandwidth": True,
            "users": [{"name": "default", "password": password}],
            "tls": tls,
        }
        meta.update({
            "password": password,
            "domain": domain,
            "cert": cert,
            "key": key,
            "email": email,
            "hop_range": hop_range,
            **tls_meta,
        })

    elif proto == "naive":
        if not domain and not (cert and key):
            raise ValueError("naive requires --domain (ACME) or --cert/--key")
        username = (
            existing_meta["username"]
            if (existing_meta and not rotate_creds and existing_meta.get("username"))
            else f"u{secrets.token_hex(4)}"
        )
        password = (
            existing_meta["password"]
            if (existing_meta and not rotate_creds and existing_meta.get("password"))
            else random_alnum(24)
        )
        tls, tls_meta = build_tls_object(
            sb_ver=sb_ver,
            state_dir=state_dir,
            tag=tag,
            domain=domain,
            cert=cert,
            key=key,
            email=email,
            cf_token=cf_token,
            self_signed=False,
        )
        inbound = {
            "type": "naive",
            "tag": tag,
            "listen": "::",
            "listen_port": port,
            "users": [{"username": username, "password": password}],
            "quic_congestion_control": "bbr",
            "tls": tls,
        }
        meta.update({
            "username": username,
            "password": password,
            "domain": domain,
            "cert": cert,
            "key": key,
            "email": email,
            **tls_meta,
        })

    elif proto == "anytls":
        password = (
            existing_meta["password"]
            if (existing_meta and not rotate_creds and existing_meta.get("password"))
            else random_alnum(24)
        )
        tls, tls_meta = build_tls_object(
            sb_ver=sb_ver,
            state_dir=state_dir,
            tag=tag,
            domain=domain,
            cert=cert,
            key=key,
            email=email,
            cf_token=cf_token,
            self_signed=self_signed,
        )
        inbound = {
            "type": "anytls",
            "tag": tag,
            "listen": "::",
            "listen_port": port,
            "users": [{"name": "default", "password": password}],
            "tls": tls,
        }
        meta.update({
            "password": password,
            "domain": domain,
            "cert": cert,
            "key": key,
            "email": email,
            **tls_meta,
        })

    elif proto == "ss2022":
        method = "2022-blake3-aes-256-gcm"
        password = (
            existing_meta["password"]
            if (existing_meta and not rotate_creds and existing_meta.get("password"))
            else base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        )
        inbound = {
            "type": "shadowsocks",
            "tag": tag,
            "listen": "::",
            "listen_port": port,
            "method": method,
            "password": password,
        }
        meta.update({
            "method": method,
            "password": password,
            "whitelist": whitelist,
        })

    elif proto == "socks":
        username = (
            existing_meta["username"]
            if (existing_meta and not rotate_creds and existing_meta.get("username"))
            else f"sb{secrets.token_hex(4)}"
        )
        password = (
            existing_meta["password"]
            if (existing_meta and not rotate_creds and existing_meta.get("password"))
            else random_alnum(18)
        )
        inbound = {
            "type": "socks",
            "tag": tag,
            "listen": "::",
            "listen_port": port,
            "users": [{"username": username, "password": password}],
        }
        meta.update({
            "username": username,
            "password": password,
            "whitelist": whitelist,
        })

    else:
        raise ValueError(f"Unsupported protocol: {proto}")

    return tag, {"inbounds": [inbound]}, meta


def cmd_add(args: argparse.Namespace) -> int:
    tag, conf_obj, meta = build_inbound_and_meta(
        proto=args.proto,
        port=args.port,
        ip=args.ip,
        country=args.country,
        sb_ver=args.sb_ver,
        state_dir=Path(args.state_dir),
        sb_bin=args.sb_bin,
        sni=args.sni,
        domain=args.domain,
        cert=args.cert,
        key=args.key,
        email=args.email,
        cf_token=args.cf_token,
        self_signed=args.self_signed,
        hop_range=args.hop_range,
        whitelist=args.whitelist,
        remark=args.remark,
    )
    atomic_write_json(Path(args.conf_dir) / f"{tag}.json", conf_obj, mode=0o640)
    atomic_write_json(Path(args.meta_dir) / f"{tag}.json", meta, mode=0o600)

    uri, extras = format_uri(meta)
    print(f"TAG={tag}")
    print(f"URI={uri}")
    for line in extras:
        print(line)
    return 0


def cmd_modify(args: argparse.Namespace) -> int:
    meta_path = Path(args.meta_dir) / f"{args.tag}.json"
    if not meta_path.is_file():
        print(f"ERROR: metadata not found: {meta_path}", file=sys.stderr)
        return 1

    old_meta = json.loads(meta_path.read_text(encoding="utf-8"))
    proto = old_meta["proto"]
    new_port = args.port if args.port else int(old_meta["port"])
    new_sni = args.sni if args.sni else old_meta.get("sni", "")
    new_domain = args.domain if args.domain else old_meta.get("domain", "")
    new_whitelist = (
        "" if args.clear_whitelist
        else (args.whitelist if args.whitelist is not None else old_meta.get("whitelist", ""))
    )

    new_tag, conf_obj, new_meta = build_inbound_and_meta(
        proto=proto,
        port=new_port,
        ip=old_meta["ip"],
        country=old_meta.get("country", "VPS"),
        sb_ver=args.sb_ver or old_meta.get("sb_ver", "1.14.4"),
        state_dir=Path(args.state_dir),
        sb_bin=args.sb_bin,
        sni=new_sni,
        domain=new_domain,
        cert=old_meta.get("cert", ""),
        key=old_meta.get("key", ""),
        email=old_meta.get("email", ""),
        cf_token=args.cf_token or "",
        self_signed=(old_meta.get("tls_mode") == "self-signed"),
        hop_range=old_meta.get("hop_range", ""),
        whitelist=new_whitelist,
        remark=args.remark or "",
        existing_meta=old_meta,
        rotate_creds=args.rotate_creds,
    )

    old_conf = Path(args.conf_dir) / f"{args.tag}.json"
    new_conf = Path(args.conf_dir) / f"{new_tag}.json"
    new_meta_path = Path(args.meta_dir) / f"{new_tag}.json"

    atomic_write_json(new_conf, conf_obj, mode=0o640)
    atomic_write_json(new_meta_path, new_meta, mode=0o600)
    if new_tag != args.tag:
        old_conf.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)

    uri, extras = format_uri(new_meta)
    print(f"OLD_TAG={args.tag}")
    print(f"TAG={new_tag}")
    print(f"PROTO={proto}")
    print(f"PORT={new_port}")
    print(f"WHITELIST={new_whitelist}")
    print(f"URI={uri}")
    for line in extras:
        print(line)
    return 0


def load_all_meta(meta_dir: Path) -> List[Dict[str, Any]]:
    if not meta_dir.is_dir():
        return []
    items: List[Dict[str, Any]] = []
    for p in sorted(meta_dir.glob("*.json")):
        try:
            items.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            continue
    return items


def cmd_links(args: argparse.Namespace) -> int:
    items = load_all_meta(Path(args.meta_dir))
    if not items:
        print("(当前没有已配置的节点)")
        return 0
    for meta in items:
        uri, extras = format_uri(meta)
        print(f"[{meta['tag']}]")
        print(uri)
        for line in extras:
            if line.startswith("BROWSER="):
                print(f"指纹浏览器格式: {line.split('=', 1)[1]}")
            elif line.startswith("QUIC_URI="):
                print(line.split("=", 1)[1])
        print()
    return 0


def cmd_yaml(args: argparse.Namespace) -> int:
    items = load_all_meta(Path(args.meta_dir))
    if not items:
        print("# (当前没有已配置的节点)")
        return 0
    print("proxies:")
    for m in items:
        proto = m["proto"]
        name = m.get("remark", m["tag"])
        server = m.get("domain") or m["ip"]
        port = m["port"]
        if proto == "vless-reality":
            print(f'  - name: "{name}"')
            print("    type: vless")
            print(f'    server: "{m["ip"]}"')
            print(f"    port: {port}")
            print(f'    uuid: "{m["uuid"]}"')
            print("    network: tcp")
            print("    tls: true")
            print("    udp: true")
            print("    flow: xtls-rprx-vision")
            print(f'    servername: "{m["sni"]}"')
            print("    client-fingerprint: chrome")
            print("    reality-opts:")
            print(f'      public-key: "{m["public_key"]}"')
            print(f'      short-id: "{m["short_id"]}"')
        elif proto == "hy2":
            print(f'  - name: "{name}"')
            print("    type: hysteria2")
            print(f'    server: "{server}"')
            print(f"    port: {port}")
            print(f'    password: "{m["password"]}"')
            if m.get("domain"):
                print(f'    sni: "{m["domain"]}"')
            if m.get("tls_mode") == "self-signed":
                print("    skip-cert-verify: true")
            if m.get("hop_range"):
                print(f'    ports: "{m["hop_range"].replace(":", "-")}"')
        elif proto == "anytls":
            print(f'  - name: "{name}"')
            print("    type: anytls")
            print(f'    server: "{server}"')
            print(f"    port: {port}")
            print(f'    password: "{m["password"]}"')
            if m.get("domain"):
                print(f'    sni: "{m["domain"]}"')
            if m.get("tls_mode") == "self-signed":
                print("    skip-cert-verify: true")
            print("    udp: true")
        elif proto == "ss2022":
            print(f'  - name: "{name}"')
            print("    type: ss")
            print(f'    server: "{m["ip"]}"')
            print(f"    port: {port}")
            print(f'    cipher: "{m["method"]}"')
            print(f'    password: "{m["password"]}"')
            print("    udp: true")
        elif proto == "socks":
            print(f'  - name: "{name}"')
            print("    type: socks5")
            print(f'    server: "{m["ip"]}"')
            print(f"    port: {port}")
            print(f'    username: "{m["username"]}"')
            print(f'    password: "{m["password"]}"')
            print("    udp: true")
        elif proto == "naive":
            print(f'  # "{name}" (naive 建议使用 sing-box / Shadowrocket / v2rayN 直接导入 naive+https:// 链接)')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="sb-kit sing-box config generator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_base = sub.add_parser("base-config")
    p_base.add_argument("--out", required=True)
    p_base.add_argument("--log-file", default="/var/log/sing-box/error.log")
    p_base.add_argument("--log-level", default="error")
    p_base.add_argument("--cn-srs", default="")

    p_add = sub.add_parser("add")
    p_add.add_argument("--proto", required=True, choices=list(PROTO_LABELS.keys()))
    p_add.add_argument("--port", required=True, type=int)
    p_add.add_argument("--ip", required=True)
    p_add.add_argument("--country", default="VPS")
    p_add.add_argument("--conf-dir", required=True)
    p_add.add_argument("--meta-dir", required=True)
    p_add.add_argument("--state-dir", required=True)
    p_add.add_argument("--sb-ver", default="1.14.4")
    p_add.add_argument("--sb-bin", default="")
    p_add.add_argument("--sni", default="")
    p_add.add_argument("--domain", default="")
    p_add.add_argument("--cert", default="")
    p_add.add_argument("--key", default="")
    p_add.add_argument("--email", default="")
    p_add.add_argument("--cf-token", default="")
    p_add.add_argument("--self-signed", action="store_true")
    p_add.add_argument("--hop-range", default="")
    p_add.add_argument("--whitelist", default="")
    p_add.add_argument("--remark", default="")

    p_mod = sub.add_parser("modify")
    p_mod.add_argument("--tag", required=True)
    p_mod.add_argument("--conf-dir", required=True)
    p_mod.add_argument("--meta-dir", required=True)
    p_mod.add_argument("--state-dir", required=True)
    p_mod.add_argument("--sb-ver", default="")
    p_mod.add_argument("--sb-bin", default="")
    p_mod.add_argument("--port", type=int, default=0)
    p_mod.add_argument("--sni", default="")
    p_mod.add_argument("--domain", default="")
    p_mod.add_argument("--cf-token", default="")
    p_mod.add_argument("--remark", default="")
    p_mod.add_argument("--whitelist", default=None)
    p_mod.add_argument("--clear-whitelist", action="store_true")
    p_mod.add_argument("--rotate-creds", action="store_true")

    p_links = sub.add_parser("links")
    p_links.add_argument("--meta-dir", required=True)

    p_yaml = sub.add_parser("yaml")
    p_yaml.add_argument("--meta-dir", required=True)

    args = parser.parse_args()
    if args.cmd == "base-config":
        return cmd_base_config(args)
    if args.cmd == "add":
        return cmd_add(args)
    if args.cmd == "modify":
        return cmd_modify(args)
    if args.cmd == "links":
        return cmd_links(args)
    if args.cmd == "yaml":
        return cmd_yaml(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
