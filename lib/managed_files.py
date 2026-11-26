"""Remove sb-kit node files and restore pre-takeover copies when available."""
import json
import os
import re
import shutil
import sys
from pathlib import Path


NODE = re.compile(r"(vless-reality|hy2|naive|anytls|ss2022|socks)-([1-9][0-9]{0,4})")


def check_acme_storage(root):
    """Only follow CertMagic storage locations which the new service may write."""
    def raise_error(error):
        raise error

    if not root.exists():
        return
    tree = root.resolve(strict=True)
    for directory, subdirs, files in os.walk(root, onerror=raise_error):
        if Path(directory) == root:
            subdirs[:] = [d for d in subdirs if d in ("acme", "certificates", "locks", "ocsp")]
            files = [f for f in files if f in ("acme", "certificates", "locks", "ocsp", "last_clean.json", "instance.uuid")]
        for name in subdirs + files:
            path = Path(directory, name)
            if path.is_symlink():
                try:
                    target = path.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise ValueError(f"无法解析链接: {path}") from exc
                if target != tree and tree not in target.parents:
                    raise ValueError(f"链接指向备份树外: {path} -> {target}")


def discard(path, original=None):
    if path.is_dir() and not path.is_symlink():
        return
    path.unlink(missing_ok=True)
    if original and (original.is_file() or original.is_symlink()):
        shutil.copy2(original, path, follow_symlinks=False)


def empty_dir(path):
    if path.is_dir() and not path.is_symlink() and not any(path.iterdir()):
        path.rmdir()


def restore_permissions(path, original):
    if not original.exists() or original.is_symlink() or path.is_symlink():
        return
    if original.is_dir():
        if path.exists() and not path.is_dir():
            return
        path.mkdir(exist_ok=True)
        for child in original.iterdir():
            if child.is_dir() or (path / child.name).exists():
                restore_permissions(path / child.name, child)
    if path.exists():
        stat = original.stat()
        if os.geteuid() == 0:
            os.chown(path, stat.st_uid, stat.st_gid)
        path.chmod(stat.st_mode & 0o7777)


def remove_nodes(config, state, logs, backup, legacy):
    conf, meta, certs = config / "conf", config / "meta", state / "certs"
    for item in sorted(meta.glob("*.json")):
        tag = item.stem
        match = NODE.fullmatch(tag)
        if not match or item.is_symlink() or not item.is_file():
            continue
        try:
            record = json.loads(item.read_text())
            if (record["tag"], record["proto"], record["port"]) != (tag, match[1], int(match[2])):
                continue
        except (ValueError, TypeError, KeyError):
            continue
        target = conf / item.name
        if target.is_symlink():
            continue
        if target.exists():
            try:
                inbounds = json.loads(target.read_text()).get("inbounds", [])
                if len(inbounds) != 1 or inbounds[0].get("tag") != tag:
                    continue
            except (ValueError, AttributeError, TypeError, IndexError):
                continue
        discard(target, backup / "etc-sing-box/conf" / item.name if backup else None)
        discard(item, backup / "etc-sing-box/meta" / item.name if backup else None)
        if record.get("tls_mode") == "self-signed":
            for field, extension in (("self_cert", ".crt"), ("self_key", ".key")):
                path = Path(record.get(field) or certs / (tag + extension))
                if path.parent == certs and NODE.fullmatch(path.stem) and path.suffix == extension:
                    discard(path, backup / "state/certs" / path.name if backup else None)

    for identity in certs.glob("identity-*"):
        marker = identity / ".managed-by-sb-kit"
        if identity.is_dir() and not identity.is_symlink() and marker.is_file() and not marker.is_symlink():
            for name in ("certificate.crt", "private.key", ".managed-by-sb-kit"):
                discard(identity / name)
            empty_dir(identity)

    # Runtime-generated logs and ACME accounts can predate a legacy installation.
    acme = state / "acme"
    if not legacy and not (backup and (backup / "state/acme").exists()) and acme.is_dir() and not acme.is_symlink():
        for pattern in ("certificates/*/*/*", "acme/*/users/*/*", "locks/*.lock", "ocsp/*"):
            for path in acme.glob(pattern):
                if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if acme in parent.parents):
                    continue
                if path.parent.name in ("locks", "ocsp") or (
                    path.suffix in (".crt", ".key", ".json") and path.stem == path.parent.name
                ):
                    discard(path)
        for directory in sorted(acme.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if directory.relative_to(acme).parts[0] in ("acme", "certificates", "locks", "ocsp"):
                empty_dir(directory)
        for part in ("last_clean.json", "instance.uuid"):
            discard(acme / part)
        empty_dir(acme)
    if not legacy:
        for path in logs.glob("error.log*"):
            if re.fullmatch(r"error\.log(?:\.\d+(?:\.gz)?)?", path.name):
                original = backup / "logs" / path.name if backup else None
                if not original or not original.exists():
                    discard(path)
    for directory in (meta, conf, certs, logs, state):
        empty_dir(directory)
    if backup:
        for live, source in ((config, "etc-sing-box"), (state, "state"), (logs, "logs")):
            original = backup / source
            if original.is_dir():
                restore_permissions(live, original)


if __name__ == "__main__":
    if sys.argv[1] == "check-takeover":
        try:
            check_acme_storage(Path(sys.argv[2]))
        except (ValueError, OSError) as error:
            sys.exit(str(error))
    else:
        cfg, state_dir, log_dir, snapshot, origin = sys.argv[1:]
        remove_nodes(Path(cfg), Path(state_dir), Path(log_dir), Path(snapshot) if snapshot else None, origin == "legacy")
