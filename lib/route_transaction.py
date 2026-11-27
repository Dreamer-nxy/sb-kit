#!/usr/bin/env python3
"""Stage a rules tree without copying or following its unmanaged files."""
import ctypes
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path


def directory_id(path):
    st = path.stat()
    return [st.st_dev, st.st_ino]


def inventory(root, clone=None):
    directories = {}
    device = root.stat().st_dev

    def visit(src, dst):
        before = src.stat()
        if before.st_dev != device or os.path.ismount(src):
            raise ValueError(f"规则目录是独立挂载点，无法原子交换: {src}")
        if dst is not None:
            dst.mkdir(mode=0o700)
        for child in src.iterdir():
            target = dst / child.name if dst is not None else None
            if stat.S_ISDIR(child.lstat().st_mode):
                visit(child, target)
            elif target is not None:
                os.link(child, target, follow_symlinks=False)
        after = src.stat()
        if before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError(f"复制期间规则目录发生修改: {src}")
        directories[str(src.relative_to(root))] = [after.st_ino, after.st_mtime_ns]
        if dst is not None:
            if (before.st_uid, before.st_gid) != (dst.stat().st_uid, dst.stat().st_gid):
                os.chown(dst, before.st_uid, before.st_gid)
            shutil.copystat(src, dst)

    visit(root, clone)
    return directories


def exchange(a, b):
    lib = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rc = lib.renamex_np(os.fsencode(a), os.fsencode(b), 2)  # RENAME_SWAP
    else:
        rc = lib.renameat2(-100, os.fsencode(a), -100, os.fsencode(b), 2)  # RENAME_EXCHANGE
    if rc:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), str(a))


def install_file(src, dst):
    # Keep the backup intact so a recovery interrupted at any step is retryable.
    if not os.path.lexists(src):
        if os.path.lexists(dst):
            dst.unlink()
        return
    with tempfile.TemporaryDirectory(prefix=".sbkit-file-", dir=dst.parent) as tmp:
        candidate = Path(tmp) / "next"
        shutil.copy2(src, candidate, follow_symlinks=False)
        st = src.lstat()
        got = candidate.lstat()
        if (st.st_uid, st.st_gid) != (got.st_uid, got.st_gid):
            os.chown(candidate, st.st_uid, st.st_gid, follow_symlinks=False)
        os.replace(candidate, dst)


def main():
    action, first, second = sys.argv[1:]
    a, b = Path(first), Path(second)
    if action == "install":
        install_file(a, b)
        return
    old = b / "rules.original"
    candidate = b / "rules"
    if action == "prepare":
        before = directory_id(a)
        old.write_text(json.dumps([before, inventory(a, candidate)]))
    elif action == "publish":
        before, tree = json.loads(old.read_text())
        if directory_id(a) != before or inventory(a) != tree:
            raise ValueError("暂存期间原规则目录已变动，请重试")
        (b / "rules.published").write_text(json.dumps([directory_id(candidate), inventory(candidate)]))
        exchange(a, candidate)
    elif action == "restore":
        before, tree = json.loads(old.read_text())
        if directory_id(a) == before:
            return
        published, new_tree = json.loads((b / "rules.published").read_text())
        if directory_id(candidate) != before or directory_id(a) != published or inventory(a) != new_tree or inventory(candidate) != tree:
            raise ValueError("规则目录被其他操作修改，已保留事务目录以供恢复")
        exchange(a, candidate)
    else:
        raise ValueError(f"unknown action: {action}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, AttributeError) as exc:
        sys.exit(str(exc))
