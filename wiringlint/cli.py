import os
import json
import argparse
import sys
from wiringlint.analyser import audit_wiring, parse_wiring_command

def walk_config(obj, current_path=""):
    """
    Recursively walk the config JSON object to find candidate wiring command strings.
    We identify candidate command strings by looking for any string value that
    looks like it invokes a local script or shell command.
    Specifically:
    - Must be a string.
    - Not just empty or short non-command strings.
    - Contains common script extensions (.py, .sh, .bash, .zsh) OR is a candidate script name.
    Since we don't have a fixed schema, we return a list of tuples: (json_path, command_str)
    """
    candidates = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            path_part = f".{k}" if current_path else k
            candidates.extend(walk_config(v, current_path + path_part))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            path_part = f"[{i}]"
            candidates.extend(walk_config(item, current_path + path_part))
    elif isinstance(obj, str):
        # Determine if it's a candidate command
        # We check if it references a script or can be parsed into a candidate script path.
        val = obj.strip()
        if val:
            # Try to parse to see if it has a script-like name
            script_path, _, _ = parse_wiring_command(val)
            if script_path:
                _, ext = os.path.splitext(script_path)
                # If it has a known extension or contains keywords like gate, guard, enforce, block, etc.
                is_candidate = False
                if ext in ('.py', '.sh', '.bash', '.zsh'):
                    is_candidate = True
                elif any(word in script_path.lower() for word in ['gate', 'guard', 'enforce', 'block', 'deny', 'shield', 'firewall']):
                    is_candidate = True
                elif '/' in script_path or '\\' in script_path:
                    # Likely a local relative/absolute path
                    is_candidate = True
                elif script_path.startswith('./') or script_path.startswith('../'):
                    is_candidate = True

                if is_candidate:
                    candidates.append((current_path, val))

    return candidates

def format_table(headers, rows):
    """
    Generates a beautiful text table from headers and rows.
    """
    if not rows:
        return ""

    widths = [len(h) for h in headers]
    for r in rows:
        for i, val in enumerate(r):
            widths[i] = max(widths[i], len(str(val)))

    separator = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    header_row = "|" + "|".join(f" {str(h).ljust(widths[i])} " for i, h in enumerate(headers)) + "|"

    out_lines = [separator, header_row, separator]
    for r in rows:
        out_row = "|" + "|".join(f" {str(val).ljust(widths[i])} " for i, val in enumerate(r)) + "|"
        out_lines.append(out_row)
    out_lines.append(separator)

    return "\n".join(out_lines)

def run_cli(args=None):
    parser = argparse.ArgumentParser(
        prog="wiringlint",
        description="Audit event-driven shell command wirings for decision blocking capabilities."
    )
    parser.add_argument("--config", required=True, help="Path to config JSON file")
    parser.add_argument("--root", help="Root directory to resolve relative script paths")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--exit-zero", action="store_true", help="Always exit zero, overriding no-op failures")
    parser.add_argument("--name-check", action="store_true", help="Perform enforcement naming honesty check")
    parser.add_argument(
        "--enforce-words",
        default="gate,guard,enforce,block,deny,shield,firewall",
        help="Comma-separated enforcement words for --name-check"
    )

    parsed = parser.parse_args(args)

    if not os.path.exists(parsed.config):
        print(f"Error: Config file not found at {parsed.config}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(parsed.config, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
    except Exception as e:
        print(f"Error parsing config JSON: {e}", file=sys.stderr)
        sys.exit(1)

    candidates = walk_config(config_data)

    results = []
    has_noop = False

    enforce_words = [w.strip().lower() for w in parsed.enforce_words.split(',') if w.strip()]

    for path, cmd in candidates:
        classification, reason, notes, script_path = audit_wiring(cmd, parsed.root)

        # Check if classification is a no-op
        is_noop = classification in ('NOOP_SWALLOWED_EXIT', 'NOOP_NO_BLOCK_PATH', 'DECLARED_UNREACHABLE')
        if is_noop:
            has_noop = True

        # Name check logic: filename contains an enforce-word, but it's classified as no-op
        name_check_fail = False
        if parsed.name_check and is_noop and script_path:
            filename = os.path.basename(script_path).lower()
            if any(word in filename for word in enforce_words):
                name_check_fail = True

        results.append({
            "json_path": path,
            "wiring": cmd,
            "script_path": script_path or "N/A",
            "classification": classification,
            "reason": reason,
            "notes": notes,
            "name_check_fail": name_check_fail
        })

    if parsed.json:
        # Output as JSON
        out_data = {
            "wirings": results,
            "summary": {
                "total": len(results),
                "has_noop": has_noop
            }
        }
        print(json.dumps(out_data, indent=2))
    else:
        # Human-readable table
        headers = ["JSON Path", "Wiring Command", "Classification", "Reason", "Notes"]
        rows = []
        for r in results:
            notes_str = "; ".join(r["notes"]) if r["notes"] else "-"
            rows.append([
                r["json_path"],
                r["wiring"],
                r["classification"],
                r["reason"],
                notes_str
            ])

        if rows:
            print(format_table(headers, rows))
        else:
            print("No candidate wirings found in the configuration.")

        if parsed.name_check:
            fail_names = [r for r in results if r["name_check_fail"]]
            if fail_names:
                print("\n⚠️  NAMING HONESTY REPORT WARNING:")
                print("The following scripts imply enforcement by name but are classified as a NO-OP:")
                for r in fail_names:
                    print(f"  - {r['script_path']} (JSON Path: {r['json_path']})")

    if has_noop and not parsed.exit_zero:
        sys.exit(1)
    else:
        sys.exit(0)
