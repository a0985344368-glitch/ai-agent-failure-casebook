"""Scan and safely add UTF-8 BOMs to UTF-8 PowerShell scripts."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Iterable


EXIT_OK = 0
EXIT_ERROR = 1
UTF8_BOM = b"\xef\xbb\xbf"

BOM_SIGNATURES = (
    ("UTF-32 BE", b"\x00\x00\xfe\xff"),
    ("UTF-32 LE", b"\xff\xfe\x00\x00"),
    ("UTF-8", UTF8_BOM),
    ("UTF-16 BE", b"\xfe\xff"),
    ("UTF-16 LE", b"\xff\xfe"),
)

VERDICTS = ("RISK", "SAFE_BOM", "PURE_ASCII", "UNSAFE_ENCODING")


class BomfixError(Exception):
    """An operational or safety failure that must make the command fail closed."""


def get_bom_type(data: bytes) -> str | None:
    """Return the recognized BOM name, with longer signatures checked first."""
    for name, signature in BOM_SIGNATURES:
        if data.startswith(signature):
            return name
    return None


def _is_link_or_reparse(path: str | os.PathLike[str]) -> bool:
    """Detect POSIX symlinks and Windows reparse points, including junctions."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
    )


def _is_within(root: str, candidate: str) -> bool:
    try:
        common = os.path.commonpath(
            (os.path.normcase(root), os.path.normcase(candidate))
        )
    except ValueError:
        return False
    return common == os.path.normcase(root)


def resolve_root(root_dir: str | os.PathLike[str]) -> str:
    """Resolve and validate the write boundary."""
    lexical = os.path.abspath(os.fspath(root_dir))
    if not os.path.isdir(lexical):
        raise BomfixError(f"target is not a directory: {root_dir}")
    if _is_link_or_reparse(lexical):
        raise BomfixError(f"root may not be a symlink or reparse point: {root_dir}")
    resolved = os.path.realpath(lexical)
    if not os.path.isdir(resolved):
        raise BomfixError(f"resolved target is not a directory: {resolved}")
    return resolved


def assert_contained(
    root: str,
    candidate: str | os.PathLike[str],
    *,
    must_exist: bool,
) -> str:
    """Resolve a path, reject links/reparse points, and enforce root containment."""
    lexical = os.path.abspath(os.fspath(candidate))
    if not _is_within(root, lexical):
        raise BomfixError(f"path escapes root boundary: {lexical}")

    check_target = lexical if must_exist else os.path.dirname(lexical)
    if must_exist and not os.path.lexists(check_target):
        raise BomfixError(f"path does not exist: {lexical}")
    if not must_exist and not os.path.isdir(check_target):
        raise BomfixError(f"parent directory does not exist: {check_target}")

    relative = os.path.relpath(check_target, root)
    current = root
    if relative != os.curdir:
        for part in Path(relative).parts:
            current = os.path.join(current, part)
            if _is_link_or_reparse(current):
                raise BomfixError(
                    f"symlink or reparse point is outside the write policy: {current}"
                )

    resolved_target = os.path.realpath(check_target)
    if not _is_within(root, resolved_target):
        raise BomfixError(f"resolved path escapes root boundary: {lexical}")
    return lexical


def find_ps1_files(
    root: str, excludes: Iterable[str]
) -> tuple[list[str], list[str]]:
    """Find .ps1 files without traversing symlink or reparse-point directories."""
    files: list[str] = []
    errors: list[str] = []
    patterns = tuple(excludes)

    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        kept_dirs: list[str] = []
        for name in sorted(dirs):
            if any(fnmatch.fnmatch(name, pattern) for pattern in patterns):
                continue
            path = os.path.join(current, name)
            try:
                assert_contained(root, path, must_exist=True)
            except (BomfixError, OSError) as exc:
                errors.append(f"{path}: {exc}")
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs

        for name in sorted(names):
            if not name.lower().endswith(".ps1"):
                continue
            path = os.path.join(current, name)
            try:
                assert_contained(root, path, must_exist=True)
            except (BomfixError, OSError) as exc:
                errors.append(f"{path}: {exc}")
                continue
            files.append(path)

    return sorted(files), errors


def _read_file_secure(root: str, filepath: str) -> tuple[bytes, os.stat_result]:
    path = assert_contained(root, filepath, must_exist=True)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise BomfixError(f"not a regular file: {path}")
    if _is_link_or_reparse(path):
        raise BomfixError(f"refusing symlink or reparse point: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise BomfixError(f"file changed while it was opened: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)

    after = os.lstat(path)
    if _identity(after) != _identity(before) or _is_link_or_reparse(path):
        raise BomfixError(f"file changed while it was read: {path}")
    return b"".join(chunks), before


def _classify(filepath: str, data: bytes) -> dict[str, object]:
    bom_type = get_bom_type(data)
    non_ascii_count = sum(byte >= 128 for byte in data)

    if bom_type is not None:
        verdict = "SAFE_BOM"
        reason = None
    else:
        try:
            decoded = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            verdict = "UNSAFE_ENCODING"
            reason = f"strict UTF-8 decode failed at byte {exc.start}"
        else:
            if "\x00" in decoded:
                verdict = "UNSAFE_ENCODING"
                reason = "NUL bytes indicate binary data or BOM-less UTF-16/UTF-32"
            elif non_ascii_count:
                verdict = "RISK"
                reason = None
            else:
                verdict = "PURE_ASCII"
                reason = None

    return {
        "path": os.path.normpath(filepath),
        "size": len(data),
        "non_ascii_count": non_ascii_count,
        "utf8_bom_present": bom_type == "UTF-8",
        "bom_type": bom_type,
        "verdict": verdict,
        "reason": reason,
    }


def analyze_file(filepath: str, root: str | None = None) -> dict[str, object]:
    """Analyze one file. A supplied root enables full boundary enforcement."""
    boundary = resolve_root(root or os.path.dirname(os.path.abspath(filepath)))
    data, _ = _read_file_secure(boundary, os.path.abspath(filepath))
    return _classify(filepath, data)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _owned_temp_identity(path: str, expected: tuple[int, int]) -> bool:
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return False
    return (current.st_dev, current.st_ino) == expected


def _cleanup_owned_temp(path: str, expected: tuple[int, int]) -> None:
    if _owned_temp_identity(path, expected):
        os.unlink(path)


def _fsync_directory(directory: str) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_backup_atomically(
    root: str,
    filepath: str,
    data: bytes,
    source_info: os.stat_result,
) -> str:
    """Publish a complete backup atomically without ever replacing an existing one."""
    backup_path = filepath + ".bak"
    assert_contained(root, backup_path, must_exist=False)
    if os.path.lexists(backup_path):
        raise BomfixError(f"backup already exists; refusing overwrite: {backup_path}")

    directory = os.path.dirname(filepath)
    descriptor, temp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(filepath)}.bak.",
        suffix=".tmp",
        dir=directory,
    )
    temp_info = os.fstat(descriptor)
    owned = (temp_info.st_dev, temp_info.st_ino)
    published = False
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.chmod(temp_path, stat.S_IMODE(source_info.st_mode))

        assert_contained(root, backup_path, must_exist=False)
        if os.path.lexists(backup_path):
            raise BomfixError(
                f"backup appeared concurrently; refusing overwrite: {backup_path}"
            )

        if os.name == "nt":
            os.rename(temp_path, backup_path)
        else:
            os.link(temp_path, backup_path, follow_symlinks=False)
        published = True
        _fsync_directory(directory)
        return backup_path
    except FileExistsError as exc:
        raise BomfixError(
            f"backup appeared concurrently; refusing overwrite: {backup_path}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not (published and os.name == "nt"):
            _cleanup_owned_temp(temp_path, owned)


def _replace_target_atomically(
    root: str,
    filepath: str,
    data: bytes,
    source_info: os.stat_result,
) -> None:
    """Write a complete same-directory temp file and atomically replace the target."""
    directory = os.path.dirname(filepath)
    descriptor, temp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(filepath)}.",
        suffix=".tmp",
        dir=directory,
    )
    temp_info = os.fstat(descriptor)
    owned = (temp_info.st_dev, temp_info.st_ino)
    replaced = False
    try:
        _write_all(descriptor, UTF8_BOM + data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.chmod(temp_path, stat.S_IMODE(source_info.st_mode))

        assert_contained(root, filepath, must_exist=True)
        current = os.lstat(filepath)
        if _identity(current) != _identity(source_info):
            raise BomfixError(f"source changed before atomic replace: {filepath}")
        if _is_link_or_reparse(filepath):
            raise BomfixError(f"source became a link before replace: {filepath}")

        os.replace(temp_path, filepath)
        replaced = True
        _fsync_directory(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            _cleanup_owned_temp(temp_path, owned)


def fix_file(root: str, filepath: str) -> tuple[bool, str | None]:
    """Fix one eligible file, returning (changed, backup_path)."""
    data, source_info = _read_file_secure(root, filepath)
    result = _classify(filepath, data)
    verdict = result["verdict"]
    if verdict == "UNSAFE_ENCODING":
        raise BomfixError(f"unsafe encoding: {result['reason']}")
    if verdict != "RISK":
        return False, None

    if stat.S_IMODE(source_info.st_mode) & 0o222 == 0:
        raise BomfixError(f"read-only file cannot be replaced safely: {filepath}")

    assert_contained(root, filepath, must_exist=True)
    backup_path = _create_backup_atomically(root, filepath, data, source_info)
    _replace_target_atomically(root, filepath, data, source_info)
    return True, backup_path


def _print_result(result: dict[str, object]) -> None:
    line = f"{result['verdict']}: {result['path']}"
    if result["reason"]:
        line += f" ({result['reason']})"
    print(line)


def _prepare(args: argparse.Namespace) -> tuple[str, list[str], list[str]]:
    root = resolve_root(args.dir)
    files, discovery_errors = find_ps1_files(root, args.exclude)
    return root, files, discovery_errors


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        root, files, errors = _prepare(args)
    except (BomfixError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    results: list[dict[str, object]] = []
    for filepath in files:
        try:
            data, _ = _read_file_secure(root, filepath)
            result = _classify(filepath, data)
            results.append(result)
            if result["verdict"] == "UNSAFE_ENCODING":
                errors.append(f"{filepath}: {result['reason']}")
        except (BomfixError, OSError) as exc:
            errors.append(f"{filepath}: {exc}")

    summary = {name: 0 for name in VERDICTS}
    for result in results:
        summary[str(result["verdict"])] += 1

    if args.json:
        print(json.dumps({"files": results, "summary": summary, "errors": errors}, indent=2))
    else:
        for result in results:
            _print_result(result)
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            "Summary: "
            + ", ".join(f"{name}={summary[name]}" for name in VERDICTS)
            + f", ERRORS={len(errors)}"
        )
    return EXIT_ERROR if errors else EXIT_OK


def cmd_fix(args: argparse.Namespace) -> int:
    try:
        root, files, errors = _prepare(args)
    except (BomfixError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    candidates = 0
    changes = 0
    for filepath in files:
        try:
            data, _ = _read_file_secure(root, filepath)
            result = _classify(filepath, data)
        except (BomfixError, OSError) as exc:
            errors.append(f"{filepath}: {exc}")
            continue

        if result["verdict"] == "UNSAFE_ENCODING":
            errors.append(f"{filepath}: SKIP unsafe encoding: {result['reason']}")
            continue
        if result["verdict"] != "RISK":
            continue

        candidates += 1
        if not args.apply:
            print(f"DRY-RUN: would fix {filepath} and create {filepath}.bak")
            continue

        try:
            changed, backup_path = fix_file(root, filepath)
        except (BomfixError, OSError) as exc:
            errors.append(f"{filepath}: {exc}")
            continue
        if changed:
            changes += 1
            print(f"FIXED: {filepath} (backup: {backup_path})")

    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if args.apply:
        print(f"Summary: candidates={candidates}, changed={changes}, errors={len(errors)}")
    else:
        print(
            f"Dry-run summary: candidates={candidates}, changed=0, errors={len(errors)}"
        )
    return EXIT_ERROR if errors else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Find and safely add UTF-8 BOMs to UTF-8 PowerShell scripts that "
            "contain non-ASCII characters."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("dir", help="root directory to scan")
        command.add_argument(
            "-e",
            "--exclude",
            action="append",
            default=[],
            help="directory-name pattern to exclude; repeatable",
        )

    scan = commands.add_parser("scan", help="report .ps1 encoding safety")
    add_common(scan)
    scan.add_argument("--json", action="store_true", help="emit JSON")
    scan.set_defaults(handler=cmd_scan)

    fix = commands.add_parser("fix", help="add a BOM to eligible files")
    add_common(fix)
    fix.add_argument(
        "--apply",
        action="store_true",
        help="write changes; without this flag the command is a dry-run",
    )
    fix.set_defaults(handler=cmd_fix)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    sys.exit(main())

