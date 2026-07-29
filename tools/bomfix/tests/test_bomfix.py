import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tools.bomfix import main as bomfix


UTF8_BOM = b"\xef\xbb\xbf"


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def run(*args: object) -> int:
    return bomfix.main([str(arg) for arg in args])


def test_pure_ascii_left_untouched_with_explicit_exit(tmp_path):
    script = tmp_path / "pure.ps1"
    original = b"Write-Output 'Hello World'\n"
    write(script, original)

    code = run("fix", tmp_path, "--apply")

    assert code == 0
    assert script.read_bytes() == original
    assert not Path(f"{script}.bak").exists()


def test_valid_utf8_is_fixed_and_backup_is_exact(tmp_path):
    script = tmp_path / "valid.ps1"
    original = "Write-Output 'Café — 東京'\n".encode()
    write(script, original)

    code = run("fix", tmp_path, "--apply")

    assert code == 0
    assert script.read_bytes() == UTF8_BOM + original
    assert Path(f"{script}.bak").read_bytes() == original


def test_existing_utf8_bom_is_untouched_with_explicit_exit(tmp_path):
    script = tmp_path / "safe.ps1"
    original = UTF8_BOM + "Write-Output 'Café'\n".encode()
    write(script, original)

    code = run("fix", tmp_path, "--apply")

    assert code == 0
    assert script.read_bytes() == original
    assert not Path(f"{script}.bak").exists()


def test_bom_marked_utf16_is_untouched_with_explicit_exit(tmp_path):
    little = tmp_path / "little.ps1"
    big = tmp_path / "big.ps1"
    little_bytes = b"\xff\xfe" + "Write-Output 'Café'".encode("utf-16-le")
    big_bytes = b"\xfe\xff" + "Write-Output 'Café'".encode("utf-16-be")
    write(little, little_bytes)
    write(big, big_bytes)

    code = run("fix", tmp_path, "--apply")

    assert code == 0
    assert little.read_bytes() == little_bytes
    assert big.read_bytes() == big_bytes
    assert not Path(f"{little}.bak").exists()
    assert not Path(f"{big}.bak").exists()


def test_cp1252_cafe_is_skipped_and_nonzero(tmp_path, capsys):
    script = tmp_path / "cp1252.ps1"
    original = b"Write-Output 'Caf\xe9'\n"
    write(script, original)

    code = run("fix", tmp_path, "--apply")
    captured = capsys.readouterr()

    assert code == 1
    assert "SKIP unsafe encoding" in captured.err
    assert script.read_bytes() == original
    assert not Path(f"{script}.bak").exists()


def test_bomless_utf16_is_skipped_even_when_ascii_bytes_are_valid_utf8(
    tmp_path, capsys
):
    script = tmp_path / "bomless-utf16.ps1"
    original = "Write-Output 'Cafe'\n".encode("utf-16-le")
    write(script, original)

    code = run("fix", tmp_path, "--apply")
    captured = capsys.readouterr()

    assert code == 1
    assert "BOM-less UTF-16/UTF-32" in captured.err
    assert script.read_bytes() == original
    assert not Path(f"{script}.bak").exists()


def test_dry_run_writes_nothing_and_returns_zero(tmp_path):
    script = tmp_path / "dry.ps1"
    original = "Write-Output 'Café'\n".encode()
    write(script, original)

    code = run("fix", tmp_path)

    assert code == 0
    assert script.read_bytes() == original
    assert not Path(f"{script}.bak").exists()


def test_simulated_backup_failure_is_nonzero(tmp_path, monkeypatch):
    script = tmp_path / "backup-failure.ps1"
    original = "Write-Output 'Café'\n".encode()
    write(script, original)

    def fail_backup(*_args, **_kwargs):
        raise OSError("simulated backup failure")

    monkeypatch.setattr(bomfix, "_create_backup_atomically", fail_backup)
    code = run("fix", tmp_path, "--apply")

    assert code == 1
    assert script.read_bytes() == original
    assert not Path(f"{script}.bak").exists()


def test_simulated_write_failure_is_nonzero_and_original_survives(
    tmp_path, monkeypatch
):
    script = tmp_path / "write-failure.ps1"
    original = "Write-Output 'Café'\n".encode()
    write(script, original)

    def fail_replace(*_args, **_kwargs):
        raise OSError("simulated target write failure")

    monkeypatch.setattr(bomfix, "_replace_target_atomically", fail_replace)
    code = run("fix", tmp_path, "--apply")

    assert code == 1
    assert script.read_bytes() == original
    assert Path(f"{script}.bak").read_bytes() == original


def test_preexisting_backup_is_never_overwritten_and_returns_nonzero(tmp_path):
    script = tmp_path / "existing-backup.ps1"
    backup = Path(f"{script}.bak")
    original = "Write-Output 'Café'\n".encode()
    sentinel = b"do not overwrite"
    write(script, original)
    write(backup, sentinel)

    code = run("fix", tmp_path, "--apply")

    assert code == 1
    assert script.read_bytes() == original
    assert backup.read_bytes() == sentinel


def test_read_only_file_is_fail_closed_with_explicit_exit(tmp_path):
    script = tmp_path / "read-only.ps1"
    original = "Write-Output 'Café'\n".encode()
    write(script, original)
    script.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    try:
        code = run("fix", tmp_path, "--apply")
        assert code == 1
        assert script.read_bytes() == original
        assert not Path(f"{script}.bak").exists()
    finally:
        script.chmod(stat.S_IRUSR | stat.S_IWUSR)


@pytest.mark.parametrize(
    "command",
    [
        ("scan",),
        ("fix", "--apply"),
    ],
)
def test_unreadable_file_is_fail_closed_with_explicit_exit(
    tmp_path, monkeypatch, command
):
    good = tmp_path / "good.ps1"
    unreadable = tmp_path / "unreadable.ps1"
    write(good, "Write-Output 'Café'\n".encode())
    write(unreadable, "Write-Output 'Café'\n".encode())
    original_read = bomfix._read_file_secure

    def fail_one(root, filepath):
        if os.path.basename(filepath) == unreadable.name:
            raise PermissionError("simulated unreadable file")
        return original_read(root, filepath)

    monkeypatch.setattr(bomfix, "_read_file_secure", fail_one)
    code = run(command[0], tmp_path, *command[1:])

    assert code == 1


def test_symlink_or_junction_cannot_escape_root_and_returns_nonzero(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    target = outside / "escape.ps1"
    original = "Write-Output 'Café'\n".encode()
    write(target, original)
    link = root / "escape.ps1"
    junction = None

    try:
        link.symlink_to(target)
    except OSError:
        if os.name != "nt":
            pytest.fail("could not create required symlink boundary fixture")
        junction = root / "escape-junction"
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            check=True,
            capture_output=True,
            text=True,
        )

    try:
        code = run("fix", root, "--apply")
        assert code == 1
        assert target.read_bytes() == original
        assert not Path(f"{target}.bak").exists()
    finally:
        if junction is not None and junction.exists():
            os.rmdir(junction)


def test_idempotency_second_run_is_noop_with_explicit_exit_codes(tmp_path):
    script = tmp_path / "idempotent.ps1"
    original = "Write-Output 'Café'\n".encode()
    write(script, original)

    first_code = run("fix", tmp_path, "--apply")
    first_bytes = script.read_bytes()
    backup = Path(f"{script}.bak")
    first_backup_bytes = backup.read_bytes()
    first_backup_stat = backup.stat()

    second_code = run("fix", tmp_path, "--apply")

    assert first_code == 0
    assert second_code == 0
    assert first_bytes == UTF8_BOM + original
    assert script.read_bytes() == first_bytes
    assert backup.read_bytes() == first_backup_bytes == original
    assert backup.stat().st_mtime_ns == first_backup_stat.st_mtime_ns


def test_exclude_and_json_scan_preserve_existing_behavior(tmp_path, capsys):
    skipped = tmp_path / "exclude_me" / "skipped.ps1"
    kept = tmp_path / "keep_me" / "kept.ps1"
    write(skipped, "Write-Output 'Café'\n".encode())
    write(kept, "Write-Output 'Café'\n".encode())

    code = run("scan", tmp_path, "--exclude", "exclude_me", "--json")
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert [Path(item["path"]).name for item in output["files"]] == ["kept.ps1"]
    assert output["summary"]["RISK"] == 1
    assert output["errors"] == []

