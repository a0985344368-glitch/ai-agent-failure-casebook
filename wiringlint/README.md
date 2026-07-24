# wiringlint

`wiringlint` is a self-contained, pure Python CLI tool that audits event-driven shell command wirings and reports which ones are **incapable of returning a blocking decision** to their host process.

## Background

Many systems let you wire shell commands to lifecycle events. A wired command can tell the host "reject this action" through one of two channels:
- **Channel A — exit code**: the command exits non-zero.
- **Channel B — structured stdout**: the command prints a JSON object to stdout containing a decision field (e.g. `{"decision": "block"}`).

A wiring is **effective** if at least one channel actually works end to end. Otherwise it is a **no-op**.

`wiringlint` statically analyzes the shell wiring and the invoked script to find any flaws.

---

## The Classification Table

| Classification | Meaning | Severity / Outcome |
|---|---|---|
| **`EFFECTIVE`** | The script successfully exits non-zero or prints a valid decision JSON on a reachable execution path, and the wiring command does not swallow the exit status. | **PASS** (Normal exit 0) |
| **`NOOP_SWALLOWED_EXIT`** | The script exits non-zero, but the wiring command neutralizes Channel A (e.g. by appending `|| true` or `; exit 0`). | **FAIL** (Exit code 1) |
| **`NOOP_NO_BLOCK_PATH`** | The script contains no logic path that can exit non-zero or print a decision JSON. | **FAIL** (Exit code 1) |
| **`DECLARED_UNREACHABLE`** | The script contains a blocking path, but it is gated behind a CLI flag or environment variable that the wiring does not provide. | **FAIL** (Exit code 1) |
| **`UNKNOWN`** | The script is unparseable (e.g., SyntaxError) or written in an unsupported language, so its safety cannot be guaranteed. | **UNKNOWN** (Fail-closed) |

---

## Features

1. **Schema-Free Config Parsing**: Walks JSON configurations recursively without requiring a fixed schema to discover candidates invoking scripts.
2. **Comprehensive Static Analysis**:
   - Parses command-line inputs, arguments, environment variables, and redirects.
   - For Python: Uses AST parsing to trace `argparse` destinations and check conditions.
   - For Bash: Scans commands, control flow blocks (`if`/`elif`/`fi`), and logical operators.
3. **Naming Honesty check**: Detects scripts whose filename implies enforcement (e.g. `gate`, `guard`, `enforce`, `block`, `deny`, `shield`, `firewall`) but are classified as no-ops.
4. **Zero Dependencies**: Built strictly using the Python Standard Library.

---

## Installation & Usage

### Running the Tool
`wiringlint` is fully self-contained. Invoke it using Python:

```bash
python -m wiringlint --config path/to/config.json [--root path/to/scripts]
```

### Options

* `--config <path>`: **Required**. Path to the configuration JSON.
* `--root <dir>`: Resolve relative script paths against this directory.
* `--json`: Output results in structured machine-readable JSON format instead of a terminal ASCII table.
* `--exit-zero`: Always return an exit status of `0` even if no-op wirings are found.
* `--name-check`: Perform the naming honesty warning check.
* `--enforce-words <words>`: Comma-separated list of enforcement terms to watch (default: `gate,guard,enforce,block,deny,shield,firewall`).

---

## Example

Given a `config.json` containing:
```json
{
  "pre-commit-hook": "python ./scripts/validate.py || true"
}
```

Running `wiringlint`:
```bash
python -m wiringlint --config config.json
```

Output:
```
+-----------------+----------------------------------------+---------------------+-------------------------------------------------------------------------+-------+
| JSON Path       | Wiring Command                         | Classification      | Reason                                                                  | Notes |
+-----------------+----------------------------------------+---------------------+-------------------------------------------------------------------------+-------+
| pre-commit-hook | python ./scripts/validate.py || true    | NOOP_SWALLOWED_EXIT | Script exits non-zero but the wiring swallows the exit status...        | -     |
+-----------------+----------------------------------------+---------------------+-------------------------------------------------------------------------+-------+
```
Exit code is `1`.

---

## Running Tests

`pytest` is used for unit testing. You can run all tests with:

```bash
PYTHONPATH=. pytest
```
