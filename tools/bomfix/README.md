# bomfix

A self-contained, standard-library-only Python CLI tool to find and fix PowerShell scripts (`*.ps1`) that contain non-ASCII characters but lack a UTF-8 BOM.

## The Failure Mode
Windows PowerShell 5.1 decodes a `.ps1` file that has **no UTF-8 BOM** using the machine's active ANSI code page instead of UTF-8.
Consequently, any `.ps1` file that contains non-ASCII characters but lacks a UTF-8 BOM is mis-decoded at runtime, which can cause silent corruptions or runtime failures.
This issue is completely invisible on modern PowerShell (v7+) and on non-Windows systems (e.g., macOS/Linux), making it extremely treacherous when cross-platform code is run on legacy Windows environments.

`bomfix` prevents this by identifying at-risk files and safely prepending a UTF-8 BOM (`\xef\xbb\xbf`) without altering any other bytes in the file.

---

## Verdict Classifications

When scanning files, `bomfix` classifies each `.ps1` file into one of three safety verdicts:

1. **RISK**: The file contains non-ASCII characters (bytes $\ge$ 128) but **lacks** a BOM. This is dangerous and can fail on Windows PowerShell 5.1.
2. **SAFE_BOM**: The file contains non-ASCII characters and **already has** a BOM (e.g. UTF-8 BOM, UTF-16 LE/BE BOM, or UTF-32 LE/BE BOM), ensuring it is safely decoded.
3. **PURE_ASCII**: The file has no non-ASCII characters. It is safe without a BOM because ASCII decodes identically under both UTF-8 and legacy ANSI.

---

## Usage Examples

### 1. Scan a Directory
Recursively search for `.ps1` files in a folder and report their safety verdicts.

```bash
python -m tools.bomfix scan /path/to/scripts
```

#### JSON Output (Machine-readable)
Use the `--json` flag to retrieve structured results.

```bash
python -m tools.bomfix scan /path/to/scripts --json
```

### 2. Exclude Directories
Skip directories by name pattern (repeatable argument).

```bash
python -m tools.bomfix scan /path/to/scripts --exclude "node_modules" --exclude "temp*"
```

### 3. Dry-run Fix (Default)
By default, the `fix` command only displays what it *would* do without modifying any files.

```bash
python -m tools.bomfix fix /path/to/scripts
```

### 4. Apply Fixes
Actually fix the files with `RISK` status. This will:
1. Create a `.bak` backup copy of the target file.
2. Prepend a UTF-8 BOM (`\xef\xbb\xbf`) to the file.
3. Keep the file completely unchanged otherwise.

```bash
python -m tools.bomfix fix /path/to/scripts --apply
```

This operation is **idempotent**. Running `fix --apply` twice on the same directory will leave the files byte-identical after the first run.
Furthermore, `bomfix` detects and skips files with existing UTF-8, UTF-16, or UTF-32 BOM signatures to prevent double-encoding and to avoid corrupting non-UTF-8 files.
