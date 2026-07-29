# bomfix

`bomfix` is a Python 3.11+ standard-library CLI that scans PowerShell
`*.ps1` files and safely adds a UTF-8 BOM when all of these conditions hold:

1. the file has no recognized BOM;
2. its complete contents decode as strict UTF-8;
3. it contains at least one non-ASCII byte;
4. it is a regular writable file contained by the resolved scan root; and
5. no backup already exists.

CP1252/ANSI, binary data, and BOM-less UTF-16/UTF-32 are reported as
`UNSAFE_ENCODING`, skipped, and never written. NUL-containing BOM-less content
is rejected even when its byte sequence happens to be technically valid UTF-8.

## Usage

```bash
python -m tools.bomfix scan PATH
python -m tools.bomfix scan PATH --json
python -m tools.bomfix fix PATH
python -m tools.bomfix fix PATH --apply
python -m tools.bomfix fix PATH --exclude node_modules --apply
```

`fix` is a dry-run unless `--apply` is supplied.

## Write safety

- The root and every candidate are resolved and checked for containment.
- Symlinks, junctions, and other reparse points are rejected.
- A pre-existing `FILE.ps1.bak` is never overwritten.
- The complete backup is published with a no-clobber atomic operation.
- The replacement is written to a temporary file in the same directory,
  flushed, and installed with an atomic replace.
- If backup creation, reading, temporary writing, or replacement fails, the
  command reports the failure and exits non-zero.
- A second run after a successful fix is a no-op and leaves the original
  backup untouched.

## Verdicts and exit codes

- `RISK`: valid UTF-8, non-ASCII, and missing a BOM; eligible for fixing.
- `SAFE_BOM`: already has a recognized UTF-8/16/32 BOM; untouched.
- `PURE_ASCII`: valid ASCII; untouched.
- `UNSAFE_ENCODING`: not safe to treat as BOM-less UTF-8; skipped.

Exit code `0` means the requested scan/dry-run/apply completed with no
operational or safety failures. Exit code `1` means at least one file could not
be read, validated, backed up, or written, or was skipped for unsafe encoding
or a boundary violation. A `scan` that merely finds `RISK` files still exits
`0`; the scan itself succeeded.

