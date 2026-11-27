"""Track the exact rule and timer files that sb-kit published."""
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
from config_gen import (
    ALL_MANAGED_RULE_FILES, BASE_RULES, canonical_cn_rule, cn_owned_entries,
    read_base, route_plan_for_mode,
)


MANIFEST = ".sb-kit-route-files.json"
FORMAT = "sb-kit-route-files-v1"
STATE = "route-state.json"
LISTS = ("cn-allow.list", "cn-block.list")
SERVICE = "sbkit-rules-update.service"
TIMER = "sbkit-rules-update.timer"
PLAN = [(tag, name) for tag, name, _ in route_plan_for_mode("on")]
RULE_NAMES = set(ALL_MANAGED_RULE_FILES)
UNIT_NAMES = {SERVICE, TIMER}


def unit_files(cli):
    return {
        SERVICE: f"""[Unit]
Description=sb-kit CN route rules auto-updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={cli} cn update --quiet
""".encode(),
        TIMER: b"""[Unit]
Description=sb-kit weekly CN route rules update timer

[Timer]
OnCalendar=Sun *-*-* 06:30:00 UTC
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
""",
    }


def digest(path):
    if path.is_symlink() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_object(path):
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (ValueError, UnicodeError):
        return {}
    return data if isinstance(data, dict) else {}


def snapshot_list(path):
    with path.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        return {
            "data": base64.b64encode(stream.read()).decode("ascii"),
            "mode": stat.st_mode & 0o7777, "uid": stat.st_uid, "gid": stat.st_gid,
            "mtime_ns": stat.st_mtime_ns,
        }


def restore_list(path, original, preserve_current=False):
    data = base64.b64decode(original["data"], validate=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".sb-kit-original-{path.name}.", delete=False) as stream:
        tmp = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), original["uid"], original["gid"])
            os.fchmod(stream.fileno(), original["mode"])
            os.utime(tmp, ns=(original["mtime_ns"], original["mtime_ns"]))
            if preserve_current:
                print(f"保留人工修改的 {path}；旧名单原件在 {tmp}", file=sys.stderr)
            else:
                os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise


def legacy_receipts(config, rules, units, cli, backups):
    """Pre-manifest releases can be identified by their generated routing configuration."""
    marker = config.parent / ".managed-by-sb-kit"
    if marker.is_symlink() or not marker.is_file():
        return {}, {}
    original = None
    lines = marker.read_text().splitlines()
    if lines and lines != ["sb-kit-v1", "fresh"]:
        if len(lines) != 2 or lines[0] != "sb-kit-v1" or not re.fullmatch(r"pre-install-[\w.-]+", lines[1]):
            return {}, {}
        original = backups / lines[1] / "etc-sing-box"
        if not (original.parent / "complete").is_file():
            return {}, {}

    if config.is_symlink() or not config.is_file():
        return {}, {}
    try:
        route = read_base(config).get("route", {})
    except (ValueError, UnicodeError):
        return {}, {}
    mode, _, _ = cn_owned_entries(route, rules)
    selected = {"on": [name for _, name in PLAN], "legacy": ["geoip-cn.srs"], "off": []}[mode]
    names = list(selected)
    state = read_object(rules / STATE)
    normalized_rules = [canonical_cn_rule(rule) for rule in route.get("rules", [])]
    generated = mode == "on" or (mode == "off" and all(r in normalized_rules for r in BASE_RULES))
    if (generated and state.keys() == {"mode", "geosite_commit", "updated_at"} and state.get("mode") == mode
            and all(isinstance(v, str) for v in state.values())):
        names.append(STATE)
    receipts = {}
    for name in names:
        if original and os.path.lexists(original / "rules" / name):
            continue
        checksum = digest(rules / name)
        if checksum:
            receipts[name] = checksum
    if STATE in receipts and mode == "on":
        for name, data in unit_files(cli).items():
            checksum = hashlib.sha256(data).hexdigest()
            if digest(units / name) == checksum:
                receipts[name] = checksum
    originals = {}
    if STATE in receipts:
        # Old list files contained plain domains with no ownership marker.
        # Preserve even operator-created lists when adopting an old deployment.
        for name in LISTS:
            path = rules / name
            if path.is_file() and not path.is_symlink():
                originals[name] = snapshot_list(path)
                receipts[name] = hashlib.sha256(base64.b64decode(originals[name]["data"])).hexdigest()
    return receipts, originals


def load_receipts(config, rules, units, cli, backups):
    path = rules / MANIFEST
    if not os.path.lexists(path):
        return legacy_receipts(config, rules, units, cli, backups)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o022:
        raise ValueError(f"规则归属清单的所有者或权限不安全: {path}")
    data = read_object(path)
    entries = data.get("files")
    if (data.get("format") != FORMAT or not isinstance(entries, dict)
            or not entries.keys() <= RULE_NAMES | UNIT_NAMES
            or not all(isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) for v in entries.values())):
        raise ValueError(f"无法确认规则归属清单，请检查并保留原件: {path}")
    originals = data.get("original_lists", {})
    if not isinstance(originals, dict) or not originals.keys() <= set(LISTS) & entries.keys():
        raise ValueError(f"旧名单备份记录无效: {path}")
    for original in originals.values():
        if (not isinstance(original, dict) or not isinstance(original.get("data"), str)
                or not all(isinstance(original.get(key), int) for key in ("mode", "uid", "gid", "mtime_ns"))
                or not 0 <= original["mode"] <= 0o7777 or min(original["uid"], original["gid"]) < 0):
            raise ValueError(f"旧名单的原始权限或数据无效: {path}")
        base64.b64decode(original["data"], validate=True)
    return entries, originals


def write_receipts(candidate, entries, originals):
    # The candidate may share inodes with the live generation. Always replace.
    with tempfile.NamedTemporaryFile(mode="w", dir=candidate, delete=False) as stream:
        tmp = Path(stream.name)
        try:
            json.dump({"format": FORMAT, "files": entries, "original_lists": originals}, stream, sort_keys=True)
            stream.write("\n")
        except BaseException:
            tmp.unlink()
            raise
    try:
        os.replace(tmp, candidate / MANIFEST)
    finally:
        tmp.unlink(missing_ok=True)


def apply(action, config, rules, units, cli, backups, args):
    if rules.is_symlink():
        raise ValueError(f"规则目录是符号链接: {rules}")
    if action == "write-units":
        for name, body in unit_files(cli).items():
            (Path(args[0]) / name).write_bytes(body)
        return
    try:
        entries, originals = load_receipts(config, rules, units, cli, backups)
    except ValueError as exc:
        if action == "unit-owned":
            return False
        if action != "cleanup":
            raise
        print(f"保留规则目录中的文件: {exc}", file=sys.stderr)
        return
    if action == "unit-owned":
        name, = args
        return name in UNIT_NAMES and name in entries and digest(units / name) == entries[name]
    if action == "cleanup":
        original = Path(args[0]) / "etc-sing-box/rules" if args[0] else None
        for name in sorted(entries.keys() & RULE_NAMES):
            target = rules / name
            actual = digest(target)
            if name in originals:
                saved = originals[name]
                expected = hashlib.sha256(base64.b64decode(saved["data"])).hexdigest()
                if actual == expected:
                    st = target.stat()
                    attrs = (st.st_mode & 0o7777, st.st_uid, st.st_gid, st.st_mtime_ns)
                    if actual != entries[name] or attrs == tuple(saved[k] for k in ("mode", "uid", "gid", "mtime_ns")):
                        continue
                restore_list(target, saved, os.path.lexists(target) and actual != entries[name])
            elif actual == entries[name]:
                target.unlink()
                if original and os.path.lexists(original / name):
                    shutil.copy2(original / name, target, follow_symlinks=False)
            elif os.path.lexists(target):
                print(f"保留已修改的规则文件: {target}", file=sys.stderr)
        (rules / MANIFEST).unlink(missing_ok=True)
        return
    mode, candidate, custom = args
    if mode not in ("on", "off") or (custom and custom not in LISTS):
        raise ValueError("无效规则归属参数")
    names = [STATE] + ([custom] if custom else [])
    if mode == "on":
        names.extend(name for _, name in PLAN)
    if action == "check":
        for name in names + (sorted(UNIT_NAMES) if mode == "on" else []):
            target = (units if name in UNIT_NAMES else rules) / name
            if os.path.lexists(target) and (name not in entries or digest(target) != entries[name]):
                raise ValueError(f"文件未由 sb-kit 创建或内容已被修改，请先将其移走: {target}")
    elif action == "record":
        for name in names:
            checksum = digest(Path(candidate) / name)
            if not checksum:
                raise ValueError(f"缺少待发布规则文件: {name}")
            entries[name] = checksum
        for name, data in unit_files(cli).items():
            if mode == "on":
                entries[name] = hashlib.sha256(data).hexdigest()
            else:
                entries.pop(name, None)
        write_receipts(Path(candidate), entries, originals)
    else:
        raise ValueError(f"未知归属操作: {action}")


if __name__ == "__main__":
    op, cfg, root, systemd, command, backup_root, *params = sys.argv[1:]
    try:
        if apply(op, Path(cfg), Path(root), Path(systemd), command, Path(backup_root), params) is False:
            sys.exit(1)
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))
