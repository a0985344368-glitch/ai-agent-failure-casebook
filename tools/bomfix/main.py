import os
import sys
import fnmatch
import json
import argparse
import shutil

# BOM definitions
BOM_SIGNATURES = {
    "UTF-32 BE": b'\x00\x00\xfe\xff',
    "UTF-32 LE": b'\xff\xfe\x00\x00',
    "UTF-8": b'\xef\xbb\xbf',
    "UTF-16 BE": b'\xfe\xff',
    "UTF-16 LE": b'\xff\xfe',
}

def get_bom_type(data: bytes):
    """Detect the BOM type of the given bytes data."""
    if data.startswith(b'\x00\x00\xfe\xff'):
        return "UTF-32 BE"
    if data.startswith(b'\xff\xfe\x00\x00'):
        return "UTF-32 LE"
    if data.startswith(b'\xef\xbb\xbf'):
        return "UTF-8"
    if data.startswith(b'\xfe\xff'):
        return "UTF-16 BE"
    if data.startswith(b'\xff\xfe'):
        return "UTF-16 LE"
    return None

def find_ps1_files(root_dir, excludes):
    """Recursively find all *.ps1 files under root_dir, skipping directories matching excludes."""
    ps1_files = []
    # Normalize root_dir
    if not os.path.isdir(root_dir):
        raise ValueError(f"Target path '{root_dir}' is not a directory.")

    for root, dirs, files in os.walk(root_dir):
        # Modify dirs in-place to exclude directories matching name patterns
        dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pat) for pat in excludes)]
        for file in files:
            if file.lower().endswith('.ps1'):
                ps1_files.append(os.path.join(root, file))
    return sorted(ps1_files)

def analyze_file(filepath):
    """Analyze a single file and return its stats and verdict."""
    with open(filepath, 'rb') as f:
        data = f.read()

    size = len(data)
    bom_type = get_bom_type(data)
    utf8_bom_present = (bom_type == "UTF-8")
    any_bom_present = (bom_type is not None)

    # Count non-ASCII bytes (bytes >= 128)
    non_ascii_count = sum(1 for b in data if b >= 128)

    # Verdict rules:
    # RISK: non-ASCII present AND no BOM
    # SAFE_BOM: non-ASCII present WITH BOM
    # PURE_ASCII: no non-ASCII bytes
    if non_ascii_count > 0:
        if any_bom_present:
            verdict = "SAFE_BOM"
        else:
            verdict = "RISK"
    else:
        verdict = "PURE_ASCII"

    return {
        "path": os.path.normpath(filepath),
        "size": size,
        "non_ascii_count": non_ascii_count,
        "utf8_bom_present": utf8_bom_present,
        "verdict": verdict,
        "bom_type": bom_type
    }

def cmd_scan(args):
    """Scan command implementation."""
    try:
        ps1_files = find_ps1_files(args.dir, args.exclude)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    results = []
    verdict_totals = {"RISK": 0, "SAFE_BOM": 0, "PURE_ASCII": 0}

    for filepath in ps1_files:
        try:
            stats = analyze_file(filepath)
            results.append(stats)
            verdict_totals[stats["verdict"]] += 1
        except Exception as e:
            # Requirements: "(h) a file that cannot be read due to permissions does not crash the whole run"
            # "scan: recursively find *.ps1 files. For each report..." -> if error, report to stderr but don't crash.
            print(f"Warning: Failed to read/analyze '{filepath}': {e}", file=sys.stderr)

    if args.json:
        # JSON output
        output_data = {
            "files": results,
            "summary": verdict_totals
        }
        print(json.dumps(output_data, indent=2))
    else:
        # Human-readable output
        for stat in results:
            print(f"File: {stat['path']}")
            print(f"  Size (bytes): {stat['size']}")
            print(f"  Non-ASCII bytes: {stat['non_ascii_count']}")
            print(f"  UTF-8 BOM present: {stat['utf8_bom_present']}")
            print(f"  Verdict: {stat['verdict']}")
            print("-" * 40)

        print(f"Summary: RISK={verdict_totals['RISK']}, SAFE_BOM={verdict_totals['SAFE_BOM']}, PURE_ASCII={verdict_totals['PURE_ASCII']}")

    return 0

def cmd_fix(args):
    """Fix command implementation."""
    try:
        ps1_files = find_ps1_files(args.dir, args.exclude)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Analyze all files first to identify those in RISK
    risk_files = []
    for filepath in ps1_files:
        try:
            stats = analyze_file(filepath)
            if stats["verdict"] == "RISK":
                risk_files.append(filepath)
        except Exception as e:
            # Tolerable reading error for single files
            print(f"Warning: Skipping file '{filepath}' because it cannot be read: {e}", file=sys.stderr)

    if not risk_files:
        if not args.apply:
            print("Dry-run: No files at RISK found to modify.")
        else:
            print("No files at RISK found to modify.")
        return 0

    for filepath in risk_files:
        if not args.apply:
            print(f"Dry-run: Would fix '{filepath}' (and create '{filepath}.bak')")
        else:
            # Real execution
            backup_path = filepath + ".bak"
            try:
                # MUST create a .bak backup before modifying any file,
                # and MUST refuse to modify a file if its backup cannot be created.
                shutil.copy2(filepath, backup_path)
            except Exception as e:
                print(f"Error: Refusing to modify '{filepath}' because backup creation failed: {e}", file=sys.stderr)
                continue

            # Perform modification
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()

                # Check again to ensure we don't double encode (idempotency, safety)
                # although it was checked in analysis, we can be extra careful.
                if get_bom_type(content) is not None:
                    # Already has a BOM somehow, skip
                    print(f"Warning: File '{filepath}' already has a BOM. Skipping write to avoid double-encoding.")
                    # Clean up backup if we didn't touch it?
                    # Or keep it? Let's leave backup if we are not sure, or delete it since we didn't write.
                    # It's safer to remove the backup if we did NOT modify the file,
                    # so that a backup doesn't clutter.
                    try:
                        os.remove(backup_path)
                    except Exception:
                        pass
                    continue

                # Prepend the UTF-8 BOM
                new_content = BOM_SIGNATURES["UTF-8"] + content

                with open(filepath, 'wb') as f:
                    f.write(new_content)

                print(f"Fixed: '{filepath}' (backup saved to '{backup_path}')")
            except Exception as e:
                print(f"Error: Failed to write fixed content to '{filepath}': {e}", file=sys.stderr)
                # Try to restore from backup or keep the backup so the user can restore manually?
                # Usually if we fail halfway, the file might be corrupted. Keeping backup is critical.

    if not args.apply:
        print("\nDry-run mode. No files were modified. Run with --apply to apply changes.")

    return 0

def main():
    parser = argparse.ArgumentParser(
        description="bomfix: Ensure UTF-8 BOM on PowerShell scripts with non-ASCII characters to prevent execution errors on legacy Windows PowerShell 5.1."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand to execute")

    # Common arguments
    def add_common_args(p):
        p.add_argument("dir", help="Directory to scan recursively for *.ps1 files")
        p.add_argument(
            "-e", "--exclude",
            action="append",
            default=[],
            help="Directory name patterns to exclude (can be repeated)"
        )

    # Scan subcommand
    parser_scan = subparsers.add_parser("scan", help="Scan *.ps1 files and report safety status")
    add_common_args(parser_scan)
    parser_scan.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Fix subcommand
    parser_fix = subparsers.add_parser("fix", help="Fix files by prepending a UTF-8 BOM")
    add_common_args(parser_fix)
    parser_fix.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply changes and write backups (default is dry-run)"
    )

    args = parser.parse_args()

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "fix":
        return cmd_fix(args)

    return 0
