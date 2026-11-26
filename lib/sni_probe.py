#!/usr/bin/env python3
"""Regional SNI latency benchmark, 4-point REALITY verifier, and RTT recommender.

Zero external dependencies (Python 3 stdlib only).
Checks:
  1. TLS 1.3 + ALPN h2 + handshake RTT
  2. Not fronted by Cloudflare CDN (cf-ray / server: cloudflare)
  3. Mainland China reachability via Globalping API (best-effort)
  4. No mainland China domestic CDN resolution via ipinfo.io (best-effort)
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

GLOBAL_POOL: List[Tuple[str, str]] = [
    ("www.gentoo.org", "Gentoo Linux"),
    ("www.debian.org", "Debian Linux"),
    ("www.kernel.org", "Linux Kernel"),
    ("www.openssl.org", "OpenSSL"),
    ("addons.mozilla.org", "Mozilla Add-ons"),
]

REGIONAL_POOLS: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {
    "US": ("US", [
        ("www.mozilla.org", "Mozilla"),
        ("www.harvard.edu", "Harvard Univ"),
        ("www.mit.edu", "MIT"),
        ("www.freebsd.org", "FreeBSD"),
        ("www.postgresql.org", "PostgreSQL"),
    ]),
    "CA": ("CA", [
        ("www.utoronto.ca", "Univ of Toronto"),
        ("www.ubc.ca", "UBC"),
        ("www.mcgill.ca", "McGill Univ"),
        ("www.freebsd.org", "FreeBSD"),
    ]),
    "JP": ("JP", [
        ("www.sony.jp", "Sony JP"),
        ("www.honda.co.jp", "Honda JP"),
        ("www.yamaha.com", "Yamaha"),
        ("www.u-tokyo.ac.jp", "Univ of Tokyo"),
        ("www.kyoto-u.ac.jp", "Kyoto Univ"),
    ]),
    "HK": ("HK", [
        ("www.hku.hk", "HKU"),
        ("www.cuhk.edu.hk", "CUHK"),
        ("www.cityu.edu.hk", "CityU HK"),
        ("www.ust.hk", "HKUST"),
    ]),
    "SG": ("SG", [
        ("nus.edu.sg", "NUS"),
        ("www.ntu.edu.sg", "NTU SG"),
        ("www.smu.edu.sg", "SMU SG"),
        ("www.changiairport.com", "Changi Airport"),
    ]),
    "TW": ("TW", [
        ("www.ntu.edu.tw", "NTU TW"),
        ("www.asus.com", "ASUS"),
        ("www.msi.com", "MSI"),
        ("www.evaair.com", "EVA Air"),
    ]),
    "KR": ("KR", [
        ("www.snu.ac.kr", "Seoul National Univ"),
        ("www.kaist.ac.kr", "KAIST"),
        ("www.koreanair.com", "Korean Air"),
        ("www.samsung.com", "Samsung"),
    ]),
    "GB": ("GB", [
        ("www.cam.ac.uk", "Cambridge Univ"),
        ("www.ox.ac.uk", "Oxford Univ"),
        ("www.arm.com", "Arm"),
        ("www.imperial.ac.uk", "Imperial College"),
    ]),
    "EU": ("EU", [
        ("www.tudelft.nl", "TU Delft"),
        ("www.ethz.ch", "ETH Zurich"),
        ("www.nokia.com", "Nokia"),
        ("www.mercedes-benz.com", "Mercedes-Benz"),
        ("www.postgresql.org", "PostgreSQL"),
    ]),
}

EU_COUNTRIES = {
    "DE", "NL", "FR", "CH", "AT", "SE", "FI", "PL", "IT",
    "ES", "LU", "IE", "NO", "DK", "BE", "CZ",
}

# Reference RTT (ms) from VPS region back to mainland China for tcpfit BDP sizing.
REGION_RTT_MS: Dict[str, int] = {
    "HK": 50,
    "MO": 50,
    "TW": 60,
    "JP": 75,
    "KR": 70,
    "SG": 85,
    "US": 160,
    "CA": 170,
    "AU": 180,
    "GB": 220,
    "EU": 220,
}


def detect_country() -> str:
    for url in ("https://ipinfo.io/country", "https://ifconfig.co/country-iso"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sb-kit/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                cc = resp.read().decode("utf-8", "ignore").strip().upper()
                if len(cc) == 2 and cc.isalpha():
                    return cc
        except Exception:
            continue
    return ""


def suggest_rtt_ms(cc: str) -> int:
    cc = (cc or "").upper()
    if cc in REGION_RTT_MS:
        return REGION_RTT_MS[cc]
    if cc in EU_COUNTRIES:
        return REGION_RTT_MS["EU"]
    return 160


def quick_tls_probe(item: Tuple[str, str, str]) -> Optional[Tuple[str, float, str, str]]:
    grp, host, desc = item
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, 443), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                rtt_ms = (time.monotonic() - t0) * 1000.0
                if ss.version() == "TLSv1.3" and ss.selected_alpn_protocol() == "h2":
                    return (grp, rtt_ms, host, desc)
    except Exception:
        return None
    return None


def verify_sni(host: str, skip_cn: bool = False) -> Tuple[bool, str]:
    host = host.strip()
    if not host:
        return False, "empty hostname"

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                rtt_ms = (time.monotonic() - t0) * 1000.0
                ver = ss.version()
                alpn = ss.selected_alpn_protocol()
    except Exception as exc:
        return False, f"TLS handshake failed: {exc}"

    if ver != "TLSv1.3" or alpn != "h2":
        return False, f"requires TLSv1.3 + h2, got {ver} / ALPN={alpn} ({rtt_ms:.1f} ms)"

    is_cf = False
    try:
        conn = http.client.HTTPSConnection(host, timeout=2.5, context=ssl.create_default_context())
        conn.request("HEAD", "/", headers={"User-Agent": "Mozilla/5.0"})
        hdrs = {k.lower(): v for k, v in conn.getresponse().getheaders()}
        is_cf = ("cf-ray" in hdrs) or ("cloudflare" in hdrs.get("server", "").lower())
        conn.close()
    except Exception:
        pass

    if is_cf:
        return False, f"behind Cloudflare CDN ({ver}+{alpn}, {rtt_ms:.1f} ms)"

    cn_note = "CN check skipped"
    if not skip_cn:
        cn_note = "CN probe unavailable"
        try:
            payload = json.dumps({
                "type": "http",
                "target": host,
                "locations": [{"country": "CN"}],
                "limit": 2,
                "measurementOptions": {
                    "protocol": "HTTPS",
                    "request": {"method": "HEAD", "path": "/"},
                },
            }).encode("utf-8")
            req = urllib.request.Request(
                "https://api.globalping.io/v1/measurements",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "sb-kit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                mid = json.loads(resp.read().decode("utf-8")).get("id")
            if mid:
                finished = None
                for _ in range(10):
                    time.sleep(1.0)
                    with urllib.request.urlopen(
                        f"https://api.globalping.io/v1/measurements/{mid}", timeout=5.0
                    ) as poll:
                        body = json.loads(poll.read().decode("utf-8"))
                    if body.get("status") == "finished":
                        finished = body.get("results", [])
                        break
                if finished is None:
                    return False, f"CN probe timeout ({ver}+{alpn}, {rtt_ms:.1f} ms)"
                if finished:
                    ok_cnt = 0
                    cn_cdn_ip = ""
                    for item in finished:
                        rr = item.get("result", {})
                        if rr.get("status") == "finished" and rr.get("statusCode"):
                            ok_cnt += 1
                        rip = rr.get("resolvedAddress", "")
                        if rip and not cn_cdn_ip:
                            try:
                                with urllib.request.urlopen(
                                    f"https://ipinfo.io/{rip}/country", timeout=2.5
                                ) as cc_resp:
                                    if cc_resp.read().decode("utf-8", "ignore").strip() == "CN":
                                        cn_cdn_ip = rip
                            except Exception:
                                pass
                    if cn_cdn_ip:
                        return False, f"resolves to CN domestic IP ({cn_cdn_ip}), avoid for REALITY"
                    if ok_cnt == 0:
                        return False, f"CN probes 0/{len(finished)} reachable (possibly blocked)"
                    cn_note = f"CN reachable {ok_cnt}/{len(finished)}, no CN CDN"
        except Exception:
            pass

    return True, f"{ver} + {alpn} | non-CF | {cn_note} ({rtt_ms:.1f} ms)"


def benchmark_candidates(cc: str) -> List[Tuple[str, float, str, str]]:
    rk = cc if cc in REGIONAL_POOLS else ("EU" if cc in EU_COUNTRIES else "")
    _, reg_pool = REGIONAL_POOLS.get(rk, ("", []))
    seen = set()
    items: List[Tuple[str, str, str]] = []
    for grp, pool in (("REG", reg_pool), ("GLB", GLOBAL_POOL)):
        for host, desc in pool:
            if host not in seen:
                seen.add(host)
                items.append((grp, host, desc))

    with ThreadPoolExecutor(max_workers=10) as ex:
        results = [r for r in ex.map(quick_tls_probe, items) if r is not None]

    reg_res = sorted([r for r in results if r[0] == "REG"], key=lambda x: x[1])
    glb_res = sorted([r for r in results if r[0] == "GLB"], key=lambda x: x[1])
    return reg_res[:5] + glb_res[:5]


def main() -> int:
    parser = argparse.ArgumentParser(description="REALITY SNI selector, verifier & region RTT helper")
    parser.add_argument("--verify", help="Verify a single SNI hostname")
    parser.add_argument("--auto", action="store_true", help="Pick best verified SNI non-interactively")
    parser.add_argument("--list", action="store_true", help="Benchmark and print pipe-delimited candidates")
    parser.add_argument("--country-info", action="store_true", help="Print CC|RTT_MS for current VPS")
    parser.add_argument("--country", default="", help="Override 2-letter VPS country code")
    parser.add_argument("--skip-cn", action="store_true", help="Skip Globalping CN probe")
    args = parser.parse_args()

    if args.country_info:
        cc = args.country.strip().upper() or detect_country()
        print(f"{cc or 'VPS'}|{suggest_rtt_ms(cc)}")
        return 0

    if args.verify:
        ok, detail = verify_sni(args.verify, skip_cn=args.skip_cn)
        prefix = "OK" if ok else "WARN"
        print(f"{prefix}|{args.verify}|{detail}")
        return 0 if ok else 2

    cc = args.country.strip().upper() or detect_country()
    candidates = benchmark_candidates(cc)

    if args.list:
        for grp, rtt, host, desc in candidates:
            print(f"{grp}|{host}|{rtt:.1f}|{desc}")
        return 0 if candidates else 1

    if args.auto:
        for _, _, host, _ in candidates:
            ok, detail = verify_sni(host, skip_cn=args.skip_cn)
            if ok:
                print(f"OK|{host}|{detail}")
                return 0
        fallback = candidates[0][2] if candidates else "www.gentoo.org"
        print(f"WARN|{fallback}|fallback without full verification")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
