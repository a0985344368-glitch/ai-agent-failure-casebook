import os
import shutil
import tempfile
import pytest
from tools.bomfix.main import analyze_file, find_ps1_files, get_bom_type, main
import sys
from unittest.mock import patch
import json

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)

def test_pure_ascii_left_untouched(temp_dir):
    """(a) Pure-ASCII file left untouched."""
    filepath = os.path.join(temp_dir, "pure.ps1")
    content = b"Write-Output 'Hello World'\n"
    with open(filepath, "wb") as f:
        f.write(content)

    stats = analyze_file(filepath)
    assert stats["verdict"] == "PURE_ASCII"
    assert stats["non_ascii_count"] == 0
    assert stats["utf8_bom_present"] is False

    # Try applying fix
    test_args = ["bomfix", "fix", temp_dir, "--apply"]
    with patch("sys.argv", test_args):
        main()

    # Verify no modification and no backup file created
    with open(filepath, "rb") as f:
        new_content = f.read()
    assert new_content == content
    assert not os.path.exists(filepath + ".bak")

def test_non_ascii_without_bom_risk_and_fixed(temp_dir):
    """(b) Non-ASCII file without BOM detected as RISK and correctly fixed."""
    filepath = os.path.join(temp_dir, "risk.ps1")
    # Content with non-ascii character (e.g. smart quotes or emoji)
    content = "Write-Output 'Hello World — Café'".encode('utf-8')
    with open(filepath, "wb") as f:
        f.write(content)

    stats = analyze_file(filepath)
    assert stats["verdict"] == "RISK"
    assert stats["non_ascii_count"] > 0
    assert stats["utf8_bom_present"] is False

    # Apply fix
    test_args = ["bomfix", "fix", temp_dir, "--apply"]
    with patch("sys.argv", test_args):
        main()

    # Verify backup exists
    backup_path = filepath + ".bak"
    assert os.path.exists(backup_path)
    with open(backup_path, "rb") as f:
        assert f.read() == content

    # Verify fixed file has UTF-8 BOM + exact same content
    with open(filepath, "rb") as f:
        fixed_content = f.read()
    assert fixed_content.startswith(b"\xef\xbb\xbf")
    assert fixed_content[3:] == content

def test_file_with_utf8_bom_untouched(temp_dir):
    """(c) File that already has a UTF-8 BOM left untouched."""
    filepath = os.path.join(temp_dir, "safe_utf8.ps1")
    content = b"\xef\xbb\xbfWrite-Output 'Caf\xc3\xa9'\n"
    with open(filepath, "wb") as f:
        f.write(content)

    stats = analyze_file(filepath)
    assert stats["verdict"] == "SAFE_BOM"
    assert stats["utf8_bom_present"] is True

    # Try applying fix
    test_args = ["bomfix", "fix", temp_dir, "--apply"]
    with patch("sys.argv", test_args):
        main()

    # Verify untouched and no backup
    with open(filepath, "rb") as f:
        assert f.read() == content
    assert not os.path.exists(filepath + ".bak")

def test_utf16_not_corrupted(temp_dir):
    """(d) UTF-16 encoded file is not corrupted."""
    # UTF-16 LE BOM: \xff\xfe
    filepath_le = os.path.join(temp_dir, "utf16le.ps1")
    content_le = "Write-Output 'Café'".encode('utf-16-le')
    # Prepend LE BOM
    full_le = b"\xff\xfe" + content_le
    with open(filepath_le, "wb") as f:
        f.write(full_le)

    # UTF-16 BE BOM: \xfe\xff
    filepath_be = os.path.join(temp_dir, "utf16be.ps1")
    content_be = "Write-Output 'Café'".encode('utf-16-be')
    # Prepend BE BOM
    full_be = b"\xfe\xff" + content_be
    with open(filepath_be, "wb") as f:
        f.write(full_be)

    # Both should be classified as SAFE_BOM
    stats_le = analyze_file(filepath_le)
    assert stats_le["verdict"] == "SAFE_BOM"
    assert stats_le["bom_type"] == "UTF-16 LE"

    stats_be = analyze_file(filepath_be)
    assert stats_be["verdict"] == "SAFE_BOM"
    assert stats_be["bom_type"] == "UTF-16 BE"

    # Try applying fix
    test_args = ["bomfix", "fix", temp_dir, "--apply"]
    with patch("sys.argv", test_args):
        main()

    # Verify they were not changed and no backup exists
    with open(filepath_le, "rb") as f:
        assert f.read() == full_le
    assert not os.path.exists(filepath_le + ".bak")

    with open(filepath_be, "rb") as f:
        assert f.read() == full_be
    assert not os.path.exists(filepath_be + ".bak")

def test_dry_run_writes_nothing(temp_dir):
    """(e) Dry-run writes nothing to disk."""
    filepath = os.path.join(temp_dir, "dry.ps1")
    content = "Write-Output 'Café'".encode('utf-8')
    with open(filepath, "wb") as f:
        f.write(content)

    # Fix command without --apply
    test_args = ["bomfix", "fix", temp_dir]
    with patch("sys.argv", test_args):
        main()

    # File should remain unmodified, and no .bak
    with open(filepath, "rb") as f:
        assert f.read() == content
    assert not os.path.exists(filepath + ".bak")

def test_backup_created_before_write(temp_dir):
    """(f) Backup file is created before any write."""
    filepath = os.path.join(temp_dir, "backup_test.ps1")
    content = "Write-Output 'Café'".encode('utf-8')
    with open(filepath, "wb") as f:
        f.write(content)

    # We will mock the write operation to raise an error during writing but after copy2.
    # We want to verify that the backup is indeed created.
    # To do this safely, we can patch 'open' specifically for writing, or mock the implementation.
    # Let's mock builtins.open when writing:
    orig_open = open
    def mock_open(file, mode='r', *args, **kwargs):
        if file == filepath and 'w' in mode:
            raise IOError("Simulated disk full / write error during write")
        return orig_open(file, mode, *args, **kwargs)

    test_args = ["bomfix", "fix", temp_dir, "--apply"]
    with patch("sys.argv", test_args), patch("builtins.open", side_effect=mock_open):
        main()

    # Backup file should still exist and match original content
    backup_path = filepath + ".bak"
    assert os.path.exists(backup_path)
    with orig_open(backup_path, "rb") as f:
        assert f.read() == content

def test_idempotency(temp_dir):
    """(g) Idempotency - second fix --apply run is a no-op."""
    filepath = os.path.join(temp_dir, "idempotent.ps1")
    content = "Write-Output 'Café'".encode('utf-8')
    with open(filepath, "wb") as f:
        f.write(content)

    # First run
    test_args = ["bomfix", "fix", temp_dir, "--apply"]
    with patch("sys.argv", test_args):
        main()

    # Capture state after first run
    with open(filepath, "rb") as f:
        state_1 = f.read()
    assert state_1.startswith(b"\xef\xbb\xbf")
    backup_mtime_1 = os.path.getmtime(filepath + ".bak")

    # Second run
    with patch("sys.argv", test_args):
        main()

    # File must be identical
    with open(filepath, "rb") as f:
        state_2 = f.read()
    assert state_2 == state_1

    # Backup shouldn't be touched or updated since no changes needed
    backup_mtime_2 = os.path.getmtime(filepath + ".bak")
    assert backup_mtime_1 == backup_mtime_2

def test_unread_file_no_crash(temp_dir):
    """(h) A file that cannot be read due to permissions does not crash the whole run."""
    filepath_ok = os.path.join(temp_dir, "good.ps1")
    with open(filepath_ok, "wb") as f:
        f.write("Write-Output 'Café'".encode('utf-8'))

    filepath_bad = os.path.join(temp_dir, "bad.ps1")
    with open(filepath_bad, "wb") as f:
        f.write("Write-Output 'Café'".encode('utf-8'))

    # We mock 'open' to raise PermissionError when opening 'bad.ps1' for reading
    orig_open = open
    def mock_open_perm(file, mode='r', *args, **kwargs):
        if "bad.ps1" in str(file) and 'r' in mode:
            raise PermissionError("Permission denied")
        return orig_open(file, mode, *args, **kwargs)

    test_args = ["bomfix", "scan", temp_dir]
    with patch("sys.argv", test_args), patch("builtins.open", side_effect=mock_open_perm):
        # Should complete with return code 0, and not crash
        res = main()
        assert res == 0

    # Also test fix command with permission errors
    test_args_fix = ["bomfix", "fix", temp_dir, "--apply"]
    with patch("sys.argv", test_args_fix), patch("builtins.open", side_effect=mock_open_perm):
        res = main()
        assert res == 0

    # The good file should be fixed successfully
    with open(filepath_ok, "rb") as f:
        assert f.read().startswith(b"\xef\xbb\xbf")

def test_exclude_skips_directory(temp_dir):
    """(i) --exclude actually skips the named directory."""
    # Create an excluded directory
    excluded_dir = os.path.join(temp_dir, "exclude_me")
    os.makedirs(excluded_dir)

    filepath_ex = os.path.join(excluded_dir, "nested.ps1")
    with open(filepath_ex, "wb") as f:
        f.write("Write-Output 'Café'".encode('utf-8'))

    # Create a normal directory
    normal_dir = os.path.join(temp_dir, "keep_me")
    os.makedirs(normal_dir)
    filepath_keep = os.path.join(normal_dir, "nested2.ps1")
    with open(filepath_keep, "wb") as f:
        f.write("Write-Output 'Café'".encode('utf-8'))

    test_args = ["bomfix", "scan", temp_dir, "--exclude", "exclude_me", "--json"]

    # We can capture stdout to parse JSON results
    import io
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        with patch("sys.argv", test_args):
            main()
        output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout

    data = json.loads(output)
    files_found = [os.path.basename(f["path"]) for f in data["files"]]

    assert "nested2.ps1" in files_found
    assert "nested.ps1" not in files_found
