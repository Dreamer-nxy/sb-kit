#!/usr/bin/env python3
"""Publish a matched sbctl entry point and helpers with a single active-version pointer."""

import hashlib
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path


REQUIRED = {"audit.sh", "bundle.py", "config_gen.py", "managed_files.py", "sni_probe.py"}
VERSION_LINE = re.compile(rb'^SBKIT_VERSION="([0-9][0-9A-Za-z.+_-]*)"$', re.MULTILINE)
RELEASE_LINK = re.compile(r"releases/([a-f0-9]{64})/VERSION\Z")
COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\.(?:py|sh)\Z")
MANIFEST = ".sb-kit-manifest"


FILES = {"VERSION", "sbctl.sh", ".sb-kit-launcher", MANIFEST}
WORK_MAGIC = b"sb-kit publication workspace v1\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def flush_path(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def safe_member(rel):
    return rel in FILES or (rel.startswith("lib/") and COMPONENT.fullmatch(rel[4:]))


def remove_empty(path):
    if path.is_dir() and not path.is_symlink() and not any(path.iterdir()):
        path.rmdir()


def clean_work(work):
    """Recover only our named work files. An operator's other files are retained."""
    if not os.path.lexists(work):
        return
    owner = work / ".owner"
    if work.is_symlink() or not work.is_dir() or work.stat().st_uid != os.geteuid() or work.stat().st_mode & 0o077:
        raise ValueError(f"暂存目录不属于当前发布操作: {work}")
    # Bootstrapping a 0700 workspace can be interrupted while writing its first file.
    children = set(work.iterdir())
    if not children:
        work.rmdir()
        return
    if owner.is_symlink() or not owner.is_file() or owner.stat().st_uid != os.geteuid():
        raise ValueError(f"暂存目录标记不匹配: {work}")
    record = owner.read_bytes()
    if children == {owner} and WORK_MAGIC.startswith(record):
        owner.unlink()
        work.rmdir()
        return
    if record != WORK_MAGIC:
        raise ValueError(f"暂存目录标记不匹配: {work}")
    stage = work / "stage"
    plan = work / "inventory"
    if os.path.lexists(stage):
        if stage.is_symlink() or not stage.is_dir() or (stage / "lib").is_symlink() or plan.is_symlink():
            raise ValueError(f"暂存文件已改变: {stage}")
        for rel in plan.read_text().splitlines():
            if not safe_member(rel):
                raise ValueError(f"无效暂存文件名: {rel}")
            path = stage / rel
            if path.is_file() or path.is_symlink():
                path.unlink()
        remove_empty(stage / "lib")
        remove_empty(stage)
        if stage.exists():
            raise ValueError(f"暂存目录内有未托管文件，已保留: {stage}")
    for path in (plan, work / "file.next", work / "link.next"):
        if path.is_file() or path.is_symlink():
            path.unlink()
    if set(work.iterdir()) == {owner}:
        owner.unlink()
        work.rmdir()


def open_work(work):
    clean_work(work)
    if not work.exists():
        work.mkdir(mode=0o700)
        (work / ".owner").write_bytes(WORK_MAGIC)


def atomic_file(path, data, mode, work):
    tmp = work / "file.next"
    with tmp.open("xb") as out:
        out.write(data)
        os.fchmod(out.fileno(), mode)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)
    flush_path(path.parent)


def switch_link(path, target, work):
    link = work / "link.next"
    link.symlink_to(target)
    os.replace(link, path)
    flush_path(path.parent)


def launcher_bytes(marker, legacy):
    return ("""#!/usr/bin/env bash
# sb-kit immutable release launcher v1
set -eu
marker=%s
if [[ -L "$marker" ]]; then
  selected=$(readlink "$marker")
  [[ "$selected" =~ ^releases/[a-f0-9]{64}/VERSION$ ]] || { echo "Invalid sb-kit release" >&2; exit 1; }
  exec "${marker%%/*}/${selected%%/VERSION}/sbctl.sh" "$@"
fi
exec %s "$@"
""" % (shlex.quote(str(marker)), shlex.quote(str(legacy)))).encode()


def stage_bundle(source, work, launcher):
    main = source / "sbctl.sh"
    libs = source / "lib"
    if main.is_symlink() or not main.is_file() or libs.is_symlink() or not libs.is_dir():
        raise ValueError(f"请选择包含 sbctl.sh 与 lib 的 sb-kit 源码目录: {source}")
    helpers = sorted(p for p in libs.iterdir() if p.suffix in (".py", ".sh"))
    if REQUIRED - {p.name for p in helpers}:
        raise ValueError(f"源码组件不完整或版本布局不兼容: {source}")
    names = sorted(FILES | {"lib/" + p.name for p in helpers})
    if not all(safe_member(name) for name in names):
        raise ValueError("源码中含无效组件名")
    (work / "inventory").write_text("\n".join(names) + "\n")
    stage = work / "stage"
    stage.mkdir(mode=0o755)
    (stage / "lib").mkdir(mode=0o755)
    manifest = []
    for path in [main, *helpers]:
        if path.is_symlink() or not path.is_file() or not COMPONENT.fullmatch(path.name):
            raise ValueError(f"无效源码组件: {path}")
        relative = path.relative_to(source)
        target = stage / relative
        data = path.read_bytes()
        target.write_bytes(data)
        target.chmod(0o755)
        if path.suffix == ".py":
            compile(data, str(path), "exec")
        else:
            subprocess.run(["bash", "-n", str(target)], check=True)
        manifest.append(f"{sha(data)}  {relative}\n")
    matches = VERSION_LINE.findall((stage / "sbctl.sh").read_bytes())
    if len(matches) != 1:
        raise ValueError("无法唯一确定待同步版本")
    version = matches[0].decode()
    version_data = (version + "\n").encode()
    (stage / "VERSION").write_bytes(version_data)
    manifest.append(f"{sha(version_data)}  VERSION\n")
    (stage / ".sb-kit-launcher").write_bytes(launcher)
    (stage / ".sb-kit-launcher").chmod(0o755)
    manifest.append(f"{sha(launcher)}  .sb-kit-launcher\n")
    content = "".join(manifest).encode()
    (stage / MANIFEST).write_bytes(content)
    return sha(content), version


def commit_release(stage, release):
    # Make all payloads and directory entries durable before selecting this generation.
    for directory in (stage / "lib", stage):
        for path in directory.iterdir():
            if path.is_file():
                flush_path(path)
        flush_path(directory)
    os.replace(stage, release)
    flush_path(release.parent)


def manifest_files(release):
    manifest = release / MANIFEST
    if release.is_symlink() or not release.is_dir() or manifest.is_symlink() or not manifest.is_file():
        raise ValueError(f"缺少可信的版本清单: {release}")
    content = manifest.read_bytes()
    if sha(content) != release.name or (release / "lib").is_symlink():
        raise ValueError(f"版本目录或清单不一致: {release}")
    entries = []
    for line in content.decode().splitlines():
        digest, sep, rel = line.partition("  ")
        if not sep or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError(f"版本清单格式无效: {release}")
        if not safe_member(rel) or rel == MANIFEST:
            raise ValueError(f"无效组件路径: {rel}")
        entries.append((release / rel, digest))
    return entries


def legacy_name(cli):
    return cli.parent / f".{cli.name}.sb-kit-flat"


def work_dirs(root, cli):
    return root / ".sb-kit-publish-work", cli.parent / f".{cli.name}.sb-kit-publish-work"


def is_release_launcher(cli, root):
    if not cli.is_symlink():
        return False
    target = Path(os.readlink(cli))
    return (target.parent.parent == root / "releases" and target.name == ".sb-kit-launcher"
            and bool(re.fullmatch("[a-f0-9]{64}", target.parent.name)))


def is_flat_script(data):
    return bool(VERSION_LINE.search(data)) or b"# sbctl.sh " in data[:100] and b"sing-box" in data[:140]


def publish(source, root, cli):
    if (root.is_symlink() or (root / "releases").is_symlink() or
            (cli.is_symlink() and not is_release_launcher(cli, root))):
        raise ValueError("安装目录或入口为外部符号链接")
    releases = root / "releases"
    releases.mkdir(parents=True, exist_ok=True)
    flush_path(root)
    flush_path(root.parent)
    marker = root / "VERSION"
    if marker.is_symlink() and not RELEASE_LINK.fullmatch(os.readlink(marker)):
        raise ValueError(f"VERSION 指向外部文件: {marker}")
    cli.parent.mkdir(parents=True, exist_ok=True)
    legacy = legacy_name(cli)
    launcher = launcher_bytes(marker, legacy)
    work, bin_work = work_dirs(root, cli)
    open_work(work)
    try:
        open_work(bin_work)
        digest, version = stage_bundle(source, work, launcher)
        stage = work / "stage"
        release = releases / digest
        exists = os.path.lexists(release)
        if exists:
            for path, expected in manifest_files(release):
                if path.is_symlink() or not path.is_file() or sha(path.read_bytes()) != expected:
                    raise ValueError(f"已有版本内容已变动: {path}")
        relative = f"releases/{digest}/VERSION"
        previous = cli.read_bytes() if cli.exists() else None
        if previous is None:
            if marker.exists() and not marker.is_symlink():
                raise ValueError("已存在 VERSION，但缺少与之匹配的平铺入口")
            # Both stable paths remain dangling until the complete first release is renamed.
            # Retrying a killed bootstrap may select a different source digest.
            switch_link(marker, relative, work)
            switch_link(cli, release / ".sb-kit-launcher", bin_work)
            if not exists:
                commit_release(stage, release)
        else:
            if previous != launcher:
                if legacy.is_symlink() or (legacy.exists() and legacy.read_bytes() != previous):
                    raise ValueError(f"旧入口备份冲突: {legacy}")
                if marker.is_symlink() or not is_flat_script(previous):
                    raise ValueError(f"无法确认原入口属于平铺版 sb-kit: {cli}")
            if not exists:
                commit_release(stage, release)
            if previous != launcher:
                # During migration the stable launcher executes the old entry in its original
                # directory until the flat VERSION file becomes the release pointer.
                atomic_file(legacy, previous, cli.stat().st_mode & 0o777, bin_work)
                atomic_file(cli, launcher, 0o755, bin_work)
            if not marker.is_symlink() or os.readlink(marker) != relative:
                switch_link(marker, relative, work)
        return version
    finally:
        clean_work(work)
        clean_work(bin_work)


def uninstall(root, cli):
    for work in work_dirs(root, cli):
        clean_work(work)
    marker = root / "VERSION"
    if not marker.is_symlink() or not RELEASE_LINK.fullmatch(os.readlink(marker)):
        return
    legacy = legacy_name(cli)
    if ((cli.is_symlink() and not is_release_launcher(cli, root)) or
            (cli.exists() and cli.read_bytes() != launcher_bytes(marker, legacy))):
        raise ValueError(f"sbctl 入口已被替换: {cli}")
    if legacy.exists() and not legacy.is_symlink() and is_flat_script(legacy.read_bytes()):
        legacy.unlink()
    releases = root / "releases"
    if releases.is_symlink():
        raise ValueError("发布目录已被替换")
    for release in releases.iterdir():
        if not re.fullmatch("[a-f0-9]{64}", release.name):
            continue
        try:
            entries = manifest_files(release)
        except (ValueError, OSError, UnicodeError):
            continue  # A directory without our intact content-addressed manifest is not owned.
        for path, digest in entries:
            if not path.is_symlink() and path.is_file() and sha(path.read_bytes()) == digest:
                path.unlink()
        (release / MANIFEST).unlink()
        remove_empty(release / "lib")
        remove_empty(release)
    remove_empty(releases)


def main(argv):
    try:
        if len(argv) == 5 and argv[1] == "publish":
            print(publish(*(Path(value).absolute() for value in argv[2:])))
        elif len(argv) == 4 and argv[1] == "uninstall":
            uninstall(*(Path(value).absolute() for value in argv[2:]))
        else:
            raise ValueError("usage: bundle.py publish SOURCE LIB_ROOT CLI | uninstall LIB_ROOT CLI")
    except (OSError, ValueError, SyntaxError, subprocess.CalledProcessError) as exc:
        print(f"sb-kit: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
