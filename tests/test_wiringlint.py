import os
import json
import pytest
from wiringlint.analyser import audit_wiring, parse_wiring_command, is_swallowed_exit, detect_redirections, detect_language
from wiringlint.cli import walk_config

# Helper to write temp files
def write_temp_script(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding='utf-8')
    return str(p)

def test_parse_wiring_command():
    # Test complex split with environment variables
    cmd = "ENV_VAR=1 python scripts/test.py --flag val"
    script, args, envs = parse_wiring_command(cmd)
    assert script == "scripts/test.py"
    assert args == ["--flag", "val"]
    assert envs == {"ENV_VAR": "1"}

    cmd2 = "./my_script.sh arg1"
    script2, args2, envs2 = parse_wiring_command(cmd2)
    assert script2 == "./my_script.sh"
    assert args2 == ["arg1"]
    assert envs2 == {}

def test_is_swallowed_exit():
    assert is_swallowed_exit("python script.py || true") is True
    assert is_swallowed_exit("python script.py ; exit 0") is True
    assert is_swallowed_exit("python script.py || exit") is True
    assert is_swallowed_exit("python script.py ; true") is True
    assert is_swallowed_exit("python script.py ; :") is True
    assert is_swallowed_exit("python script.py && echo 1") is False
    assert is_swallowed_exit("python script.py") is False

def test_detect_redirections():
    assert "2>/dev/null" in detect_redirections("python script.py 2>/dev/null")
    assert ">/dev/null" in detect_redirections("python script.py >/dev/null")
    assert "2>&1" in detect_redirections("python script.py 2>&1")
    assert len(detect_redirections("python script.py")) == 0

def test_detect_language(tmp_path):
    p = write_temp_script(tmp_path, "test.py", "print('hello')")
    assert detect_language(p) == "python"

    p2 = write_temp_script(tmp_path, "test.sh", "echo hello")
    assert detect_language(p2) == "shell"

    # Testing shebang detection
    p3 = write_temp_script(tmp_path, "no_ext", "#!/usr/bin/env python3\nprint('hello')")
    with open(p3, 'r') as f:
        first = f.readline()
    assert detect_language(p3, first) == "python"

    p4 = write_temp_script(tmp_path, "no_ext_sh", "#!/bin/bash\necho hello")
    with open(p4, 'r') as f:
        first = f.readline()
    assert detect_language(p4, first) == "shell"

# Required Fixtures & Failure Modes

# 1. Swallowed exit code via `; exit 0` or `|| true`
def test_swallowed_exit_modes(tmp_path):
    # A script that exits non-zero
    script_content = """import sys
sys.exit(1)
"""
    sp = write_temp_script(tmp_path, "err.py", script_content)

    # Wiring with `; exit 0` over the script
    cmd1 = f"python {sp} ; exit 0"
    classification1, reason1, _, _ = audit_wiring(cmd1)
    assert classification1 == "NOOP_SWALLOWED_EXIT"
    assert "swallows the exit" in reason1.lower()

    # Wiring with `|| true` over the script
    cmd2 = f"python {sp} || true"
    classification2, reason2, _, _ = audit_wiring(cmd2)
    assert classification2 == "NOOP_SWALLOWED_EXIT"

# 2. Script whose only "enforcement" is print() with no exit and no JSON
def test_no_block_path(tmp_path):
    script_content = """print("WARNING: this is bad!")
"""
    sp = write_temp_script(tmp_path, "warn.py", script_content)
    cmd = f"python {sp}"
    classification, reason, _, _ = audit_wiring(cmd)
    assert classification == "NOOP_NO_BLOCK_PATH"
    assert "no block paths" in reason.lower()

# 3. Script that prints correct decision JSON (EFFECTIVE even though exits 0)
def test_decision_json_effective(tmp_path):
    # Python script
    script_content = """import json
print(json.dumps({"decision": "block", "reason": "unsafe"}))
"""
    sp = write_temp_script(tmp_path, "json_block.py", script_content)
    cmd = f"python {sp}"
    classification, reason, _, _ = audit_wiring(cmd)
    assert classification == "EFFECTIVE"
    assert "channel b active" in reason.lower()

    # Shell script printing JSON
    sh_content = """#!/bin/bash
echo '{"decision": "block", "reason": "unsafe"}'
"""
    sp2 = write_temp_script(tmp_path, "json_block.sh", sh_content)
    cmd2 = f"bash {sp2}"
    classification2, reason2, _, _ = audit_wiring(cmd2)
    assert classification2 == "EFFECTIVE"

# 4. Script with sys.exit(2) on a real branch (EFFECTIVE)
def test_sys_exit_effective(tmp_path):
    script_content = """import sys
if True:
    sys.exit(2)
"""
    sp = write_temp_script(tmp_path, "exit_branch.py", script_content)
    cmd = f"python {sp}"
    classification, reason, _, _ = audit_wiring(cmd)
    assert classification == "EFFECTIVE"
    assert "channel a active" in reason.lower()

# 5. Script with an `--emit-json` style flag gating its block path, wired without that flag (DECLARED_UNREACHABLE)
def test_flag_gated_block_path(tmp_path):
    # Gated Python script via flag/argparse
    script_content = """import argparse
import sys
parser = argparse.ArgumentParser()
parser.add_argument('--emit-json', action='store_true')
args = parser.parse_args()

if args.emit_json:
    print('{"decision": "block"}')
"""
    sp = write_temp_script(tmp_path, "gate.py", script_content)

    # Wired WITHOUT the flag -> DECLARED_UNREACHABLE
    cmd_without = f"python {sp}"
    classification, reason, _, _ = audit_wiring(cmd_without)
    assert classification == "DECLARED_UNREACHABLE"
    assert "missing configuration" in reason.lower()
    assert "flag --emit-json" in reason

    # Wired WITH the flag -> EFFECTIVE
    cmd_with = f"python {sp} --emit-json"
    classification2, reason2, _, _ = audit_wiring(cmd_with)
    assert classification2 == "EFFECTIVE"

# 6. Deeply nested / unusual config shape, to prove the recursive walk does not depend on a fixed schema
def test_unusual_config_shape():
    nested_config = {
        "services": {
            "web": {
                "hooks": [
                    {"name": "pre-commit", "command": "python scripts/gate.py"},
                    {"name": "post-commit", "command": "echo 'not candidate'"}
                ]
            }
        },
        "deep": [
            [[{"action": "bash ./scripts/guard.sh"}]]
        ]
    }
    candidates = walk_config(nested_config)
    paths = [p for p, _ in candidates]
    commands = [c for _, c in candidates]

    assert "services.web.hooks[0].command" in paths
    assert "python scripts/gate.py" in commands
    assert "deep[0][0][0].action" in paths
    assert "bash ./scripts/guard.sh" in commands

# 7. Unparseable script (UNKNOWN with a reason, never silently EFFECTIVE)
def test_unparseable_script(tmp_path):
    # Syntax error in python
    script_content = """import sys
if:
    sys.exit(1)
"""
    sp = write_temp_script(tmp_path, "invalid.py", script_content)
    cmd = f"python {sp}"
    classification, reason, _, _ = audit_wiring(cmd)
    assert classification == "UNKNOWN"
    assert "syntaxerror" in reason.lower()

# 8. Env var gating block path test
def test_env_var_gating(tmp_path):
    script_content = """import os
import sys
if os.environ.get('STRICT_MODE') == '1':
    sys.exit(1)
"""
    sp = write_temp_script(tmp_path, "env_gate.py", script_content)

    # Wired WITHOUT the env var -> DECLARED_UNREACHABLE
    cmd_without = f"python {sp}"
    classification, reason, _, _ = audit_wiring(cmd_without)
    assert classification == "DECLARED_UNREACHABLE"
    assert "env var STRICT_MODE" in reason

    # Wired WITH the env var -> EFFECTIVE
    cmd_with = f"STRICT_MODE=1 python {sp}"
    classification2, reason2, _, _ = audit_wiring(cmd_with)
    assert classification2 == "EFFECTIVE"

# 9. Shell script gating flag/env var test
def test_shell_gating(tmp_path):
    script_content = """#!/bin/bash
if [ "$1" = "--block" ]; then
    exit 3
fi
"""
    sp = write_temp_script(tmp_path, "shell_gate.sh", script_content)

    # Wired WITHOUT flag -> DECLARED_UNREACHABLE
    cmd_without = f"bash {sp}"
    classification, reason, _, _ = audit_wiring(cmd_without)
    assert classification == "DECLARED_UNREACHABLE"
    assert "flag -b" in reason or "flag --block" in reason

    # Wired WITH flag -> EFFECTIVE
    cmd_with = f"bash {sp} --block"
    classification2, reason2, _, _ = audit_wiring(cmd_with)
    assert classification2 == "EFFECTIVE"

# 10. CLI-level integration tests
from wiringlint.cli import run_cli

def test_cli_help(capsys):
    with pytest.raises(SystemExit) as excinfo:
        run_cli(["--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "wiringlint" in captured.out
    assert "--config" in captured.out

def test_cli_run_effective_and_noop(tmp_path, capsys):
    # Prepare script files
    sp_effective = write_temp_script(tmp_path, "guard.py", "import sys\nsys.exit(2)")
    sp_noop = write_temp_script(tmp_path, "warn_only.py", "print('warning')")

    config = {
        "pre-commit": f"python {sp_effective}",
        "post-commit": f"python {sp_noop}"
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    # Run CLI with noop present -> should exit 1
    with pytest.raises(SystemExit) as excinfo:
        run_cli(["--config", str(config_path)])
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "EFFECTIVE" in captured.out
    assert "NOOP_NO_BLOCK_PATH" in captured.out

    # Run CLI with noop present but --exit-zero -> should exit 0
    with pytest.raises(SystemExit) as excinfo2:
        run_cli(["--config", str(config_path), "--exit-zero"])
    assert excinfo2.value.code == 0

    # Run CLI with JSON output -> should be valid json with total/has_noop
    capsys.readouterr()  # clear buffer
    with pytest.raises(SystemExit) as excinfo3:
        run_cli(["--config", str(config_path), "--json", "--exit-zero"])
    assert excinfo3.value.code == 0
    captured_json = capsys.readouterr()
    parsed_out = json.loads(captured_json.out)
    assert parsed_out["summary"]["total"] == 2
    assert parsed_out["summary"]["has_noop"] is True

    wirings = parsed_out["wirings"]
    assert wirings[0]["classification"] == "EFFECTIVE"
    assert wirings[1]["classification"] == "NOOP_NO_BLOCK_PATH"

def test_cli_name_check(tmp_path, capsys):
    # Script file that implies enforcement but has no-op classification
    sp_gate = write_temp_script(tmp_path, "gate_file.py", "print('hello')")
    config = {
        "hook": f"python {sp_gate}"
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    # Run with --name-check
    with pytest.raises(SystemExit) as excinfo:
        run_cli(["--config", str(config_path), "--name-check", "--exit-zero"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "NAMING HONESTY REPORT WARNING" in captured.out
    assert "gate_file.py" in captured.out
