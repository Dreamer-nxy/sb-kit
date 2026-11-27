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
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import string
import subprocess
import sys
import tempfile
import urllib.parse
import uuid
from contextlib import ExitStack
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

CN_MODES = ("off", "on")
GEOSITE_SRS_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geosite"

# Upstream v2fly / SagerNet fine-grained CN categories (mirrors the audited
# Dufu egress policy: blocks CN entertainment/media/netdisk/social/banks/PT
# while keeping fingerprint browsers, Feishu, 1688, Tencent Cloud & ordinary
# websites untouched).
CN_BLOCK_GEOSITE_TAGS: Tuple[str, ...] = (
    # Entertainment / Video / Streaming / Music / Netdisk
    "category-entertainment-cn",
    "bilibili",
    "iqiyi",
    "youku",
    "tencent-tme",
    "category-media-cn",
    "category-netdisk-cn",
    # Social / Search / Maps / P2P / Security telemetry
    "category-social-media-cn",
    "baidu",
    "xiaohongshu",
    "amap",
    "xunlei",
    "qihoo360",
    # Banking & Securities (high-risk anti-fraud audit targets)
    "category-bank-cn",
    "icbc",
    "ccb",
    "cmb",
    "boc",
    "category-securities-cn",
    # BT / PT trackers (datacenter DMCA anti-abuse)
    "category-pt",
    "category-public-tracker",
)

# Minimal explicit supplements for high-risk domestic endpoints not isolated in
# parent categories (deliberately avoids broad tencent/bytedance/alibaba/cn).
CN_BLOCK_EXTRA_DOMAINS: Tuple[str, ...] = (
    "gov.cn",
    "toutiao.com",
    "toutiaocdn.com",
    "toutiaoimg.com",
    "ixigua.com",
    "snssdk.com",
    "weixin.qq.com",
    "wechat.com",
    "servicewechat.com",
    "wx.qq.com",
    "qq.com",
    "qpic.cn",
    "qlogo.cn",
    "gtimg.cn",
    "weibo.com",
    "weibo.cn",
    "weibocdn.com",
    "umeng.com",
    "umengcloud.com",
    "getui.com",
    "jpush.cn",
    "jiguang.cn",
    "music.163.com",
    "yun.139.com",
)

# Built-in allowlist evaluated before built-in block rules so upstream category
# shifts cannot break fingerprint browsers, Feishu, 1688, TikTok, or OS checks.
CN_ALLOW_DOMAINS: Tuple[str, ...] = (
    "adspower.net",
    "adspower.com",
    "bitbrowser.cn",
    "bitbrowser.net",
    "hubstudio.com",
    "hubstudio.cn",
    "feishu.cn",
    "larksuite.com",
    "1688.com",
    "tiktok.com",
    "tiktokv.com",
    "tiktokcdn.com",
    "tiktokrow-cdn.com",
    "connectivitycheck.gstatic.com",
)

_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def route_plan_for_mode(mode: str, revision: str = "rule-set") -> List[Tuple[str, str, str]]:
    """Return (rule_set_tag, filename, download_url) tuples required for mode."""
    if mode == "off":
        return []
    if mode == "on":
        return [
            (f"geosite-{tag}", f"geosite-{tag}.srs", f"{GEOSITE_SRS_BASE}/{revision}/geosite-{tag}.srs")
            for tag in CN_BLOCK_GEOSITE_TAGS
        ]
    raise ValueError(f"unsupported CN route mode: {mode!r}")


# Include legacy geoip-cn.srs so uninstall cleans up older v0.2.x installs too.
ALL_MANAGED_RULE_FILES = frozenset(
    [fn for _, fn, _ in route_plan_for_mode("on")]
    + ["geoip-cn.srs", "route-state.json", "cn-allow.list", "cn-block.list"]
)


def normalize_domain(raw: str) -> str:
    """Validate and normalize a domain suffix (lowercase, no leading dot)."""
    domain = raw.strip().lower().lstrip(".")
    if not domain or len(domain) > 253 or not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"invalid domain suffix: {raw!r}")
    return domain


def load_domain_list(path: Optional[Path], ignore_invalid: bool = False) -> List[str]:
    if not path or not path.is_file():
        return []
    seen = set()
    result: List[str] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            dom = normalize_domain(line)
        except ValueError as exc:
            if ignore_invalid:
                continue
            raise ValueError(f"{path}:{lineno}: {exc}") from exc
        if dom not in seen:
            seen.add(dom)
            result.append(dom)
    return sorted(result)


def save_domain_list(path: Path, domains: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    body = "".join(f"{d}\n" for d in sorted(set(domains)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


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
    """Write JSON atomically; the temp file is created with the final mode (no umask window)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def publish_node_files(files: List[Tuple[Path, Dict[str, Any], int]]) -> None:
    """Stage the whole batch; retain the original inodes until every rename succeeds."""
    with ExitStack() as cleanup:
        staging: Dict[Path, Path] = {}
        pending = []
        for target, data, mode in files:
            parent = target.parent
            if parent not in staging:
                parent.mkdir(parents=True, exist_ok=True)
                work = cleanup.enter_context(tempfile.TemporaryDirectory(dir=parent))
                staging[parent] = Path(work)
            staged = staging[parent] / target.name
            atomic_write_json(staged, data, mode)
            original = None
            if target.exists():
                original = staged.with_suffix(".old")
                os.link(target, original)
            pending.append((target, staged, original))

        installed = []
        try:
            for target, staged, original in pending:
                os.replace(staged, target)
                installed.append((target, original))
        except BaseException:
            for target, original in reversed(installed):
                if original is None:
                    target.unlink()
                else:
                    os.replace(original, target)
            raise


_X25519_P = 2 ** 255 - 19
_X25519_A24 = 121665


def x25519(scalar: bytes, u_point: bytes) -> bytes:
    """RFC 7748 X25519 (pure Python, constant-structure Montgomery ladder)."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n = int.from_bytes(k, "little")
    p = _X25519_P
    x1 = int.from_bytes(u_point, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + _X25519_A24 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


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
    # No sing-box binary (dry-run / CI): derive a *real* X25519 keypair in pure Python,
    # so --generate-only links are actually usable.
    priv_raw = bytearray(secrets.token_bytes(32))
    priv_raw[0] &= 248
    priv_raw[31] &= 127
    priv_raw[31] |= 64
    pub_raw = x25519(bytes(priv_raw), (9).to_bytes(32, "little"))
    return _b64url(bytes(priv_raw)), _b64url(pub_raw)


def normalize_ip_list(raw: str) -> Tuple[List[str], List[str]]:
    """Validate a comma/space separated IP/CIDR list; return (v4_list, v6_list)."""
    import ipaddress

    v4: List[str] = []
    v6: List[str] = []
    for item in raw.replace(";", ",").replace(" ", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid IP/CIDR: {item!r}") from exc
        text = str(net.network_address) if net.num_addresses == 1 else str(net)
        target = v4 if net.version == 4 else v6
        if text not in target:
            target.append(text)
    return v4, v6


def generate_self_signed_cert(state_dir: Path) -> Tuple[str, str, str]:
    cert_dir = state_dir / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    # A published identity is immutable. Port reuse and failed rotations cannot
    # overwrite material still referenced by another node or by a rollback.
    identity = Path(tempfile.mkdtemp(prefix="identity-", dir=cert_dir))
    try:
        (identity / ".managed-by-sb-kit").touch(mode=0o600)
        return write_self_signed_cert(identity)
    except BaseException:
        shutil.rmtree(identity)
        raise


def write_self_signed_cert(identity: Path) -> Tuple[str, str, str]:
    cert_path = identity / "certificate.crt"
    key_path = identity / "private.key"
    # Randomized CN/O and non-fixed validity to avoid well-known script fingerprints.
    rand_cn = f"{secrets.token_hex(4)}.local"
    days = str(365 + secrets.randbelow(700))
    if shutil.which("openssl"):
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                # Force named-curve encoding: LibreSSL/old OpenSSL may emit explicit
                # EC params, which Go's crypto/x509 (sing-box) rejects.
                "-pkeyopt", "ec_param_enc:named_curve",
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
    domain: str = "",
    cert: str = "",
    key: str = "",
    email: str = "",
    cf_token: str = "",
    self_signed: bool = False,
    alpn: Optional[List[str]] = None,
    reuse_self_signed: Optional[Tuple[str, str, str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    tls: Dict[str, Any] = {"enabled": True}
    extra_meta: Dict[str, Any] = {"tls_mode": "acme", "pin_sha256": "", "cf_token": ""}
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
        if reuse_self_signed:
            cert_path, key_path, pin = reuse_self_signed
            if not Path(cert_path).is_file() or not Path(key_path).is_file():
                raise ValueError("self-signed certificate or key missing; restore the files or explicitly rotate credentials")
            pem = Path(cert_path).read_text(encoding="ascii")
            # Legacy previews on hosts without OpenSSL used a placeholder pair.
            if pem.strip() != "DRY_RUN_CERT" or pin != "00" * 32:
                digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
                if digest != pin.replace(":", "").lower():
                    raise ValueError("stored certificate fingerprint mismatch; restore the certificate or explicitly rotate credentials")
        else:
            cert_path, key_path, pin = generate_self_signed_cert(state_dir)
        tls["certificate_path"] = cert_path
        tls["key_path"] = key_path
        extra_meta["tls_mode"] = "self-signed"
        extra_meta["pin_sha256"] = pin
        extra_meta["self_cert"] = cert_path
        extra_meta["self_key"] = key_path
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
        # Persist in root-only (0600) meta so modify/regen never silently drops DNS-01.
        extra_meta["cf_token"] = cf_token

    if (major, minor) >= (1, 14):
        acme_cfg["type"] = "acme"
        tls["certificate_provider"] = acme_cfg
    else:
        tls["acme"] = acme_cfg

    return tls, extra_meta


# The tag is an ownership marker that survives both a lost route-state file and
# an operator changing adjacent rules. It is part of the sing-box schema.
CN_DOMAIN_GROUPS = (
    ("sbkit-cn-user-allow", "route"),
    ("sbkit-cn-user-block", "reject"),
    ("sbkit-cn-builtin-allow", "route"),
    ("sbkit-cn-extra-block", "reject"),
)
BASE_RULES = [
    {"action": "sniff", "timeout": "300ms"},
    {"ip_is_private": True, "action": "reject"},
    {"port": [25], "action": "reject"},
    {"protocol": "bittorrent", "action": "reject"},
]


def cn_action(condition: Dict[str, Any], action: str, direct_tag: Optional[str] = "direct") -> Dict[str, Any]:
    rule = dict(condition, action=action)
    if action == "route" and direct_tag:
        rule["outbound"] = direct_tag
    return rule


def cn_local_set(tag: str, path: Path) -> Dict[str, Any]:
    return {"tag": tag, "type": "local", "format": "binary", "path": str(path)}


def canonical_cn_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    # sing-box format emits scalars for one-item match lists.
    normalized = {
        k: [v] if k in ("domain_suffix", "rule_set", "port") and isinstance(v, (str, int)) else v
        for k, v in rule.items()
    }
    normalized.setdefault("action", "route")
    return normalized


def matches_cn_file(entry: Dict[str, Any], tag: str, path: Path) -> bool:
    expected = cn_local_set(tag, path)
    # sing-box format omits the binary format inferred from the .srs suffix.
    return entry == expected or entry == {k: v for k, v in expected.items() if k != "format"}


def cn_policy(args: argparse.Namespace, direct_tag: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    rules: Dict[str, Any] = {}
    sets: Dict[str, Any] = {}
    if args.cn_mode == "on":
        if not args.rules_dir:
            raise ValueError("--cn-mode on requires --rules-dir")
        allow = load_domain_list(Path(args.allow_file) if args.allow_file else None)
        block = load_domain_list(Path(args.block_file) if args.block_file else None)
        plan = route_plan_for_mode("on")
        for tag, filename, _ in plan:
            sets[tag] = cn_local_set(tag, Path(args.rules_dir) / filename)
        for (tag, action), domains in zip(CN_DOMAIN_GROUPS, (allow, block, CN_ALLOW_DOMAINS, CN_BLOCK_EXTRA_DOMAINS)):
            if tag == "sbkit-cn-extra-block":
                rules["categories"] = cn_action({"rule_set": [t for t, _, _ in plan]}, "reject")
            if domains:
                sets[tag] = {"type": "inline", "tag": tag, "rules": [{"domain_suffix": list(domains)}]}
                rules[tag] = cn_action({"rule_set": [tag]}, action, direct_tag)
    elif args.cn_srs:
        sets["geoip-cn"] = cn_local_set("geoip-cn", Path(args.cn_srs))
        rules["resolve"] = {"action": "resolve"}
        rules["geoip-cn"] = cn_action({"rule_set": ["geoip-cn"]}, "reject")
    return rules, sets


def read_base(path: Path) -> Dict[str, Any]:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict) or not isinstance(cfg.get("route", {}), dict):
        raise ValueError(f"{path}: expected an object with a route object")
    route = cfg.get("route", {})
    for field in ("rules", "rule_set"):
        entries = route.get(field, [])
        if not isinstance(entries, list) or not all(isinstance(r, dict) for r in entries):
            raise ValueError(f"{path}: route.{field} must be an array of objects")
    return cfg


def cn_owned_entries(route: Dict[str, Any], rules_dir: Path) -> Tuple[str, Dict[int, str], set]:
    """Identify the generated rules by both their source and their use."""
    rules = [canonical_cn_rule(r) for r in route.get("rules", [])]
    definitions = {r["tag"]: r for r in route.get("rule_set", []) if isinstance(r.get("tag"), str)}
    plan = route_plan_for_mode("on")
    categories = [tag for tag, _, _ in plan]
    bundle_rule = cn_action({"rule_set": categories}, "reject")
    all_local = all(matches_cn_file(definitions.get(t, {}), t, rules_dir / f) for t, f, _ in plan)
    owned: Dict[int, str] = {}
    if all_local and bundle_rule in rules:
        # Identify the complete builtin allow / category reject / extra reject
        # group. A user can independently reference the same local category
        # files, or add an identical reject outside that group.
        group_positions = {}
        for tag, action in CN_DOMAIN_GROUPS:
            group = definitions.get(tag, {})
            clauses = group.get("rules", [])
            if (group.get("type", "inline") == "inline" and isinstance(clauses, list) and len(clauses) == 1
                    and isinstance(clauses[0], dict) and set(clauses[0]) == {"domain_suffix"}):
                group_positions[tag] = [
                    i for i, r in enumerate(rules)
                    if r == cn_action({"rule_set": [tag]}, action, r.get("outbound"))
                ]
        builtin_tag = "sbkit-cn-builtin-allow"
        extra_tag = "sbkit-cn-extra-block"
        tagged = bool(group_positions.get(builtin_tag) and group_positions.get(extra_tag))
        if not tagged:
            # The first v0.3.0 generator used literal domain_suffix clauses.
            builtin = cn_action({"domain_suffix": list(CN_ALLOW_DOMAINS)}, "route")
            extra = cn_action({"domain_suffix": list(CN_BLOCK_EXTRA_DOMAINS)}, "reject")
            group_positions = {
                builtin_tag: [i for i, r in enumerate(rules) if r == builtin],
                extra_tag: [i for i, r in enumerate(rules) if r == extra],
            }

        candidates = []
        for i, r in enumerate(rules):
            if r != bundle_rule:
                continue
            before = [j for j in group_positions[builtin_tag] if j < i]
            after = [j for j in group_positions[extra_tag] if j > i]
            if before and after:
                candidates.append((after[0] - before[-1], before[-1], i, after[0]))
        if candidates:
            _, builtin_i, category_i, extra_i = min(candidates)
            owned.update({builtin_i: builtin_tag, category_i: "categories", extra_i: extra_tag})
            tags = set(categories)
            if tagged:
                tags.update((builtin_tag, extra_tag))
                for tag, _ in CN_DOMAIN_GROUPS[:2]:
                    preceding = [i for i in group_positions.get(tag, []) if i < builtin_i]
                    if preceding:
                        owned[preceding[-1]] = tag
                        tags.add(tag)
            return "on", owned, tags
    legacy = "geoip-cn"
    rule = cn_action({"rule_set": [legacy]}, "reject")
    if matches_cn_file(definitions.get(legacy, {}), legacy, rules_dir / "geoip-cn.srs") and rule in rules:
        i = rules.index(rule)
        owned[i] = legacy
        return "legacy", owned, {legacy}
    return "off", owned, set()


def rule_set_references(value: Any) -> set:
    """Find rule_set conditions including logical rules and DNS routing."""
    tags = set()
    if isinstance(value, list):
        for item in value:
            tags.update(rule_set_references(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if key == "rule_set":
                if isinstance(item, str):
                    tags.add(item)
                elif isinstance(item, list):
                    tags.update(tag for tag in item if isinstance(tag, str))
            else:
                tags.update(rule_set_references(item))
    return tags


def merge_cn_policy(cfg: Dict[str, Any], args: argparse.Namespace, source_dir: Path) -> None:
    route = cfg.setdefault("route", {})
    old_rules = route.get("rules", [])
    _, owned, owned_tags = cn_owned_entries(route, source_dir)
    # A customised installation can rename or remove the stock direct
    # outbound. Its configured default remains the destination for allowed
    # traffic if no explicitly tagged direct egress exists.
    outbounds = cfg.get("outbounds", [])
    if not isinstance(outbounds, list) or not all(isinstance(o, dict) for o in outbounds):
        raise ValueError("outbounds must be an array of objects")
    direct_tags = [o["tag"] for o in outbounds if o.get("type") == "direct" and o.get("tag")]
    default_tag = route.get("final") or (outbounds[0].get("tag") if outbounds else None)
    direct_tag = "direct" if "direct" in direct_tags else next(iter(direct_tags), default_tag)
    new_rules, new_sets = cn_policy(args, direct_tag)
    # The older unmarked user-list clauses are identified by the actual lists,
    # independently of adjacent operator-authored domain_suffix rules.
    builtin_pos = next((i for i, name in owned.items() if name == "sbkit-cn-builtin-allow"), None)
    if builtin_pos is not None and "domain_suffix" in old_rules[builtin_pos]:
        old_prefix = [canonical_cn_rule(r) for r in old_rules[:builtin_pos]]
        for (tag, action), file in zip(CN_DOMAIN_GROUPS[:2], (args.old_allow_file, args.old_block_file)):
            if not file:
                continue
            # Invalid lines in a manually edited list do not block off. Use
            # positive matches only: identical-looking operator rules have no
            # provenance marker in old v0.3.0 configurations.
            try:
                entries = load_domain_list(Path(file), ignore_invalid=True)
            except (OSError, UnicodeError):
                entries = []
            candidate = cn_action({"domain_suffix": entries}, action)
            if entries and candidate in old_prefix:
                pos = max(i for i, r in enumerate(old_prefix) if r == candidate)
                owned[pos] = tag

    # Replace each owned position so that interleaved operator rules retain
    # their precedence. Insert newly enabled groups before the next owned group.
    ordered = list(new_rules)
    result = []
    cursor = 0
    if owned:
        last_owned = max(owned)
        for i, rule in enumerate(old_rules):
            role = owned.get(i)
            if role is None:
                result.append(rule)
            elif role in new_rules:
                stop = ordered.index(role) + 1
                result.extend(new_rules[name] for name in ordered[cursor:stop])
                cursor = max(cursor, stop)
            if i == last_owned:
                result.extend(new_rules[name] for name in ordered[cursor:])
                cursor = len(ordered)
    else:
        pos = max((i + 1 for i, rule in enumerate(old_rules) if canonical_cn_rule(rule) in BASE_RULES), default=0)
        result = old_rules[:pos] + list(new_rules.values()) + old_rules[pos:]
    if result or "rules" in route:
        route["rules"] = result

    needed = rule_set_references(result) | rule_set_references(cfg.get("dns", {}))
    kept = []
    for entry in route.get("rule_set", []):
        tag = entry.get("tag")
        if tag in owned_tags:
            if tag in new_sets:
                kept.append(new_sets.pop(tag))
            elif tag in needed:
                kept.append(entry)
        elif tag in new_sets:
            # A shared set kept at 'off' can be adopted again only when the
            # definition matches the local file in the live managed directory.
            if not matches_cn_file(entry, tag, source_dir / (tag + ".srs")) and entry != new_sets[tag]:
                raise ValueError(f"route.rule_set tag conflicts with an existing operator rule set: {tag}")
            kept.append(new_sets.pop(tag))
        else:
            kept.append(entry)
    kept.extend(new_sets.values())
    if kept:
        route["rule_set"] = kept
    elif owned_tags:
        route.pop("rule_set", None)


def cmd_base_config(args: argparse.Namespace) -> int:
    try:
        if args.existing_config:
            source = Path(args.existing_config)
            cfg = read_base(source)
            live_dir = Path(args.existing_rules_dir) if args.existing_rules_dir else source.parent / "rules"
        else:
            cfg = {
                "log": {"output": args.log_file, "level": args.log_level, "timestamp": True},
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"rules": list(BASE_RULES), "final": "direct"},
            }
            live_dir = Path(args.rules_dir or ".")
        merge_cn_policy(cfg, args, live_dir)
        atomic_write_json(Path(args.out), cfg, mode=0o640)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_route_mode(args: argparse.Namespace) -> int:
    path = Path(args.config)
    try:
        if not path.exists():
            print("off")
        else:
            cfg = read_base(path)
            mode, _, _ = cn_owned_entries(cfg.get("route", {}), Path(args.rules_dir))
            print(mode)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_route_plan(args: argparse.Namespace) -> int:
    if args.commit is not None and not re.fullmatch("[0-9a-f]{40}", args.commit):
        print("ERROR: --commit must be a full lowercase Git SHA", file=sys.stderr)
        return 1
    for tag, filename, url in route_plan_for_mode(args.mode, args.commit or "rule-set"):
        print(f"{tag}|{filename}|{url}")
    return 0


def cmd_route_domains(args: argparse.Namespace) -> int:
    if args.action != "list":
        try:
            target = normalize_domain(args.domain)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        if args.action == "validate":
            return 0
    path = Path(args.file)
    try:
        current = load_domain_list(path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.action == "list":
        for dom in current:
            print(dom)
        return 0

    if args.action == "add":
        if target not in current:
            current.append(target)
        save_domain_list(path, current)
        print(f"ADDED={target}")
        return 0
    if args.action == "del":
        if target not in current:
            print(f"ERROR: domain not found in {path.name}: {target}", file=sys.stderr)
            return 1
        current = [d for d in current if d != target]
        save_domain_list(path, current)
        print(f"REMOVED={target}")
        return 0
    return 1


def cmd_route_state(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if args.action == "get":
        data: Dict[str, Any] = {}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("expected a JSON object")
            except (OSError, ValueError) as exc:
                print(f"ERROR: {path}: {exc}", file=sys.stderr)
                return 1
        mode = data.get("mode", "")
        if mode == "targeted":
            mode = "on"
        if mode not in CN_MODES:
            mode = ""
        print(f"MODE={mode}")
        print(f"GEOSITE_COMMIT={data.get('geosite_commit', '')}")
        print(f"UPDATED_AT={data.get('updated_at', '')}")
        return 0

    if args.action == "set":
        existing: Dict[str, Any] = {}
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except ValueError:
                existing = {}
        state = {
            "mode": args.mode,
            "geosite_commit": args.geosite_commit if args.geosite_commit is not None else existing.get("geosite_commit", ""),
            "updated_at": args.updated_at if args.updated_at is not None else existing.get("updated_at", ""),
        }
        atomic_write_json(path, state, mode=0o640)
        return 0
    return 1


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
        # SIP002: AEAD-2022 userinfo must be percent-encoded plain text, not base64.
        method = urllib.parse.quote(meta["method"], safe="")
        password = urllib.parse.quote(meta["password"], safe="")
        return f"ss://{method}:{password}@{host}:{port}#{remark}", extras

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
    masquerade: str = "",
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

    wl_v4, wl_v6 = normalize_ip_list(whitelist or "")
    norm_wl = ",".join(wl_v4 + wl_v6)

    reuse_ss: Optional[Tuple[str, str, str]] = None
    if existing_meta and not rotate_creds and existing_meta.get("tls_mode") == "self-signed":
        old_tag = existing_meta.get("tag", "")
        reuse_ss = (
            existing_meta.get("self_cert") or str(state_dir / "certs" / f"{old_tag}.crt"),
            existing_meta.get("self_key") or str(state_dir / "certs" / f"{old_tag}.key"),
            existing_meta.get("pin_sha256", ""),
        )

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
            domain=domain,
            cert=cert,
            key=key,
            email=email,
            cf_token=cf_token,
            reuse_self_signed=reuse_ss,
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
        if masquerade:
            inbound["masquerade"] = masquerade
        meta.update({
            "password": password,
            "domain": domain,
            "cert": cert,
            "key": key,
            "email": email,
            "hop_range": hop_range,
            "masquerade": masquerade,
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
            domain=domain,
            cert=cert,
            key=key,
            email=email,
            cf_token=cf_token,
            reuse_self_signed=reuse_ss,
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
            domain=domain,
            cert=cert,
            key=key,
            email=email,
            cf_token=cf_token,
            reuse_self_signed=reuse_ss,
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
            "whitelist": norm_wl,
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
            "whitelist": norm_wl,
        })

    else:
        raise ValueError(f"Unsupported protocol: {proto}")

    return tag, {"inbounds": [inbound]}, meta


def cmd_add(args: argparse.Namespace) -> int:
    name = f"{args.proto}-{args.port}.json"
    conf_path = Path(args.conf_dir) / name
    meta_path = Path(args.meta_dir) / name
    if not args.force and (conf_path.exists() or meta_path.exists()):
        print(f"ERROR: node {conf_path.stem} already exists (use modify, or del first)", file=sys.stderr)
        return 1
    try:
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
            masquerade=args.masquerade,
            whitelist=args.whitelist,
            remark=args.remark,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    publish_node_files([(conf_path, conf_obj, 0o640), (meta_path, meta, 0o600)])

    uri, extras = format_uri(meta)
    print(f"TAG={tag}")
    print(f"WHITELIST={meta.get('whitelist', '')}")
    print(f"URI={uri}")
    for line in extras:
        print(line)
    return 0


def read_conf_cf_token(conf_path: Path) -> str:
    """Recover a Cloudflare DNS-01 token from an existing inbound conf (legacy metas)."""
    try:
        data = json.loads(conf_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    for ib in data.get("inbounds", []):
        tls = ib.get("tls", {}) or {}
        for key in ("certificate_provider", "acme"):
            prov = tls.get(key)
            if isinstance(prov, dict):
                token = (prov.get("dns01_challenge") or {}).get("api_token", "")
                if token:
                    return token
    return ""


def rebuild_from_meta(
    old_meta: Dict[str, Any],
    conf_dir: Path,
    state_dir: Path,
    sb_ver: str,
    sb_bin: Optional[str],
    port: int = 0,
    sni: str = "",
    domain: str = "",
    cf_token: str = "",
    remark: str = "",
    hop_range: Optional[str] = None,
    clear_hop_range: bool = False,
    masquerade: Optional[str] = None,
    whitelist: Optional[str] = None,
    clear_whitelist: bool = False,
    rotate_creds: bool = False,
) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    old_tag = old_meta["tag"]
    token = (
        cf_token
        or old_meta.get("cf_token", "")
        or read_conf_cf_token(conf_dir / f"{old_tag}.json")
    )
    if old_meta.get("tls_mode") == "acme-dns01" and not token:
        raise ValueError("missing DNS-01 credentials in metadata and existing inbound")
    new_whitelist = (
        "" if clear_whitelist
        else (whitelist if whitelist is not None else old_meta.get("whitelist", ""))
    )
    new_hop_range = (
        "" if clear_hop_range
        else (hop_range if hop_range is not None else old_meta.get("hop_range", ""))
    )
    new_masquerade = (
        masquerade if masquerade is not None else old_meta.get("masquerade", "")
    )
    return build_inbound_and_meta(
        proto=old_meta["proto"],
        port=port or int(old_meta["port"]),
        ip=old_meta["ip"],
        country=old_meta.get("country", "VPS"),
        sb_ver=sb_ver or old_meta.get("sb_ver", "1.14.4"),
        state_dir=state_dir,
        sb_bin=sb_bin,
        sni=sni or old_meta.get("sni", ""),
        domain=domain or old_meta.get("domain", ""),
        cert=old_meta.get("cert", ""),
        key=old_meta.get("key", ""),
        email=old_meta.get("email", ""),
        cf_token=token,
        self_signed=(old_meta.get("tls_mode") == "self-signed"),
        hop_range=new_hop_range,
        masquerade=new_masquerade,
        whitelist=new_whitelist,
        remark=remark,
        existing_meta=old_meta,
        rotate_creds=rotate_creds,
    )


def read_node_meta(path: Path) -> Dict[str, Any]:
    meta = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict):
        raise ValueError("expected a metadata object")
    proto = meta.get("proto")
    port = meta.get("port")
    if proto not in PROTO_LABELS or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid node protocol or port")
    if path.stem != meta.get("tag") or path.stem != f"{proto}-{port}":
        raise ValueError("metadata filename, tag and protocol/port disagree")

    required = ["ip"]
    if proto == "vless-reality":
        required.extend(["uuid", "private_key", "public_key", "short_id", "sni"])
    else:
        required.append("password")
    if proto in ("naive", "socks"):
        required.append("username")
    if proto in ("hy2", "naive", "anytls"):
        tls_mode = meta.get("tls_mode")
        if tls_mode == "custom-cert":
            required.extend(["cert", "key"])
        elif tls_mode in ("acme", "acme-dns01"):
            required.append("domain")
        elif tls_mode == "self-signed":
            required.append("pin_sha256")
        else:
            raise ValueError("missing or unknown TLS mode")
    for key in required:
        if not isinstance(meta.get(key), str) or not meta[key]:
            raise ValueError(f"missing or invalid field {key}")
    return meta


def cmd_modify(args: argparse.Namespace) -> int:
    meta_path = Path(args.meta_dir) / f"{args.tag}.json"
    if not meta_path.is_file():
        print(f"ERROR: metadata not found: {meta_path}", file=sys.stderr)
        return 1

    conf_dir = Path(args.conf_dir)
    try:
        old_meta = read_node_meta(meta_path)
        target_tag = f"{old_meta['proto']}-{args.port or old_meta['port']}"
        new_conf = conf_dir / f"{target_tag}.json"
        new_meta_path = meta_path.parent / f"{target_tag}.json"
        if target_tag != args.tag and (new_conf.exists() or new_meta_path.exists()):
            raise ValueError(f"target node {target_tag} already exists")
        new_tag, conf_obj, new_meta = rebuild_from_meta(
            old_meta,
            conf_dir=conf_dir,
            state_dir=Path(args.state_dir),
            sb_ver=args.sb_ver,
            sb_bin=args.sb_bin,
            port=args.port,
            sni=args.sni,
            domain=args.domain,
            cf_token=args.cf_token or "",
            remark=args.remark or "",
            hop_range=args.hop_range,
            clear_hop_range=args.clear_hop_range,
            masquerade=args.masquerade,
            whitelist=args.whitelist,
            clear_whitelist=args.clear_whitelist,
            rotate_creds=args.rotate_creds,
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    old_conf = conf_dir / f"{args.tag}.json"
    publish_node_files([(new_conf, conf_obj, 0o640), (new_meta_path, new_meta, 0o600)])
    if new_tag != args.tag:
        old_conf.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)

    uri, extras = format_uri(new_meta)
    print(f"OLD_TAG={args.tag}")
    print(f"TAG={new_tag}")
    print(f"PROTO={new_meta['proto']}")
    print(f"PORT={new_meta['port']}")
    print(f"WHITELIST={new_meta.get('whitelist', '')}")
    print(f"HOP_RANGE={new_meta.get('hop_range', '')}")
    print(f"URI={uri}")
    for line in extras:
        print(line)
    return 0


def cmd_regen(args: argparse.Namespace) -> int:
    """Regenerate every inbound conf from meta (e.g. after a 1.13 -> 1.14 core upgrade)."""
    conf_dir = Path(args.conf_dir)
    meta_dir = Path(args.meta_dir)
    if not meta_dir.is_dir():
        print(f"ERROR: metadata directory not found: {meta_dir}", file=sys.stderr)
        return 1
    files = []
    tags = []
    for path in sorted(meta_dir.glob("*.json")):
        try:
            meta = read_node_meta(path)
            tag, conf_obj, new_meta = rebuild_from_meta(
                meta, conf_dir=conf_dir, state_dir=Path(args.state_dir),
                sb_ver=args.sb_ver, sb_bin=args.sb_bin,
            )
        except (KeyError, OSError, TypeError, ValueError) as exc:
            print(f"ERROR: regen {path.name}: {exc}", file=sys.stderr)
            return 1
        files.extend([(conf_dir / path.name, conf_obj, 0o640), (path, new_meta, 0o600)])
        tags.append(tag)
    try:
        publish_node_files(files)
    except OSError as exc:
        print(f"ERROR: publishing regenerated nodes: {exc}", file=sys.stderr)
        return 1
    for tag in tags:
        print(f"REGEN={tag}")
    print(f"COUNT={len(tags)}")
    return 0


def cmd_normalize_ips(args: argparse.Namespace) -> int:
    try:
        v4, v6 = normalize_ip_list(args.ips)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"ALL={','.join(v4 + v6)}")
    print(f"V4={', '.join(v4)}")
    print(f"V6={', '.join(v6)}")
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


_YAML_RESERVED = {"true", "false", "yes", "no", "on", "off", "null", "y", "n"}


def _yaml_scalar(value: Any) -> str:
    """JSON scalars are valid YAML; this safely quotes/escapes every string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", text) and text.lower() not in _YAML_RESERVED:
        return text
    return json.dumps(text, ensure_ascii=False)


def _yaml_proxy(m: Dict[str, Any]) -> Optional[List[Tuple[str, Any]]]:
    proto = m["proto"]
    name = m.get("remark", m["tag"])
    server = m.get("domain") or m["ip"]
    port = int(m["port"])
    if proto == "vless-reality":
        return [
            ("name", name), ("type", "vless"), ("server", m["ip"]), ("port", port),
            ("uuid", m["uuid"]), ("network", "tcp"), ("tls", True), ("udp", True),
            ("flow", "xtls-rprx-vision"), ("servername", m["sni"]),
            ("client-fingerprint", "chrome"),
            ("reality-opts", [("public-key", m["public_key"]), ("short-id", m["short_id"])]),
        ]
    if proto in ("hy2", "anytls"):
        items: List[Tuple[str, Any]] = [
            ("name", name), ("type", "hysteria2" if proto == "hy2" else "anytls"),
            ("server", server), ("port", port), ("password", m["password"]),
        ]
        if m.get("domain"):
            items.append(("sni", m["domain"]))
        if m.get("tls_mode") == "self-signed":
            items.append(("skip-cert-verify", True))
            if proto == "hy2" and m.get("pin_sha256"):
                items.append(("fingerprint", m["pin_sha256"].replace(":", "").lower()))
        if proto == "hy2" and m.get("hop_range"):
            items.append(("ports", m["hop_range"].replace(":", "-")))
        if proto == "anytls":
            items.append(("udp", True))
        return items
    if proto == "ss2022":
        return [
            ("name", name), ("type", "ss"), ("server", m["ip"]), ("port", port),
            ("cipher", m["method"]), ("password", m["password"]), ("udp", True),
        ]
    if proto == "socks":
        return [
            ("name", name), ("type", "socks5"), ("server", m["ip"]), ("port", port),
            ("username", m["username"]), ("password", m["password"]), ("udp", True),
        ]
    return None


def cmd_yaml(args: argparse.Namespace) -> int:
    items = load_all_meta(Path(args.meta_dir))
    if not items:
        print("# (当前没有已配置的节点)")
        return 0
    print("proxies:")
    for m in items:
        fields = _yaml_proxy(m)
        if fields is None:
            name = m.get("remark", m["tag"]).replace("\n", " ")
            print(f"  # {name} ({m['proto']} 请直接导入 sb i 输出的链接)")
            continue
        for i, (key, value) in enumerate(fields):
            prefix = "  - " if i == 0 else "    "
            if isinstance(value, list):
                print(f"{prefix}{key}:")
                for sub_key, sub_val in value:
                    print(f"      {sub_key}: {_yaml_scalar(sub_val)}")
            else:
                print(f"{prefix}{key}: {_yaml_scalar(value)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="sb-kit sing-box config generator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_base = sub.add_parser("base-config")
    p_base.add_argument("--out", required=True)
    p_base.add_argument("--log-file", default="/var/log/sing-box/error.log")
    p_base.add_argument("--log-level", default="error")
    p_base.add_argument("--cn-srs", default="")
    p_base.add_argument("--cn-mode", default="off", choices=list(CN_MODES))
    p_base.add_argument("--rules-dir", default="")
    p_base.add_argument("--allow-file", default="")
    p_base.add_argument("--block-file", default="")

    p_base.add_argument("--existing-config", default="")
    p_base.add_argument("--existing-rules-dir", default="")
    p_base.add_argument("--old-allow-file", default="")
    p_base.add_argument("--old-block-file", default="")

    p_mode = sub.add_parser("route-mode")
    p_mode.add_argument("--config", required=True)
    p_mode.add_argument("--rules-dir", required=True)

    p_rplan = sub.add_parser("route-plan")
    p_rplan.add_argument("--commit")
    p_rplan.add_argument("--mode", required=True, choices=list(CN_MODES))

    p_rdom = sub.add_parser("route-domains")
    p_rdom.add_argument("--file", required=True)
    p_rdom.add_argument("action", choices=["list", "add", "del", "validate"])
    p_rdom.add_argument("domain", nargs="?", default="")

    p_rstate = sub.add_parser("route-state")
    p_rstate.add_argument("--file", required=True)
    p_rstate.add_argument("action", choices=["get", "set"])
    p_rstate.add_argument("--mode", choices=list(CN_MODES), default="off")
    p_rstate.add_argument("--geosite-commit", default=None)
    p_rstate.add_argument("--updated-at", default=None)

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
    p_add.add_argument("--masquerade", default="")
    p_add.add_argument("--whitelist", default="")
    p_add.add_argument("--remark", default="")
    p_add.add_argument("--force", action="store_true")

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
    p_mod.add_argument("--hop-range", default=None)
    p_mod.add_argument("--clear-hop-range", action="store_true")
    p_mod.add_argument("--masquerade", default=None)
    p_mod.add_argument("--whitelist", default=None)
    p_mod.add_argument("--clear-whitelist", action="store_true")
    p_mod.add_argument("--rotate-creds", action="store_true")

    p_links = sub.add_parser("links")
    p_links.add_argument("--meta-dir", required=True)

    p_yaml = sub.add_parser("yaml")
    p_yaml.add_argument("--meta-dir", required=True)

    p_regen = sub.add_parser("regen")
    p_regen.add_argument("--conf-dir", required=True)
    p_regen.add_argument("--meta-dir", required=True)
    p_regen.add_argument("--state-dir", required=True)
    p_regen.add_argument("--sb-ver", default="")
    p_regen.add_argument("--sb-bin", default="")

    p_ips = sub.add_parser("normalize-ips")
    p_ips.add_argument("ips")

    args = parser.parse_args()
    # Secrets may be passed via environment to keep them out of `ps` / shell history.
    if hasattr(args, "cf_token") and not args.cf_token:
        args.cf_token = os.environ.get("SB_CF_TOKEN", "")
    if args.cmd == "base-config":
        return cmd_base_config(args)
    if args.cmd == "route-mode":
        return cmd_route_mode(args)
    if args.cmd == "route-plan":
        return cmd_route_plan(args)
    if args.cmd == "route-domains":
        return cmd_route_domains(args)
    if args.cmd == "route-state":
        return cmd_route_state(args)
    if args.cmd == "add":
        return cmd_add(args)
    if args.cmd == "modify":
        return cmd_modify(args)
    if args.cmd == "links":
        return cmd_links(args)
    if args.cmd == "yaml":
        return cmd_yaml(args)
    if args.cmd == "regen":
        return cmd_regen(args)
    if args.cmd == "normalize-ips":
        return cmd_normalize_ips(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
