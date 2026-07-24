import os
import re
import ast
import shlex

def parse_wiring_command(command_str):
    """
    Parses a shell command string to extract:
    - script_path: the path to the script being invoked.
    - args: list of arguments/flags passed to the script.
    - env_vars: dictionary of environment variables set on the command line before the command.
    """
    try:
        tokens = shlex.split(command_str)
    except Exception:
        tokens = command_str.split()

    env_vars = {}
    tokens_clean = []

    state = "env"
    for token in tokens:
        if state == "env" and "=" in token and not token.startswith("-"):
            parts = token.split("=", 1)
            env_vars[parts[0]] = parts[1]
        else:
            state = "cmd"
            tokens_clean.append(token)

    interpreters = {"python", "python3", "bash", "sh", "zsh"}

    script_path = None
    args = []

    if tokens_clean:
        first = tokens_clean[0]
        base_first = os.path.basename(first)
        if base_first in interpreters:
            if len(tokens_clean) > 1:
                script_path = tokens_clean[1]
                args = tokens_clean[2:]
            else:
                script_path = first
                args = []
        else:
            script_path = first
            args = tokens_clean[1:]

    return script_path, args, env_vars

def is_swallowed_exit(command_str):
    """
    Checks if the wiring command neutralises Channel A (exit code).
    """
    normalized = " ".join(command_str.split())
    norm_lower = normalized.lower()

    # Match || true, || exit 0, || exit, || :, ; exit 0, ; exit, ; true, ; :
    # Handled with a trailing non-word char check or line end
    pattern = r'(\|\||;)\s*(true|exit\s*0|exit|:)(?:\s|$|;)'
    if re.search(pattern, norm_lower):
        return True
    return False

def detect_redirections(command_str):
    """
    Finds all stdout/stderr redirections (e.g. 2>/dev/null, >/dev/null, 2>&1).
    """
    normalized = " ".join(command_str.split())
    pattern = r'(\b2>\s*&1|[0-2]?\s*>\s*/dev/null|&\s*>\s*/dev/null|[0-2]?\s*>\s*\S+)'
    matches = re.findall(pattern, normalized)
    return [m.strip() for m in matches]

def detect_language(file_path, first_line=None):
    """
    Detects script language based on file extension or shebang.
    """
    _, ext = os.path.splitext(file_path)
    if ext == '.py':
        return 'python'
    elif ext in ('.sh', '.bash', '.zsh'):
        return 'shell'

    if first_line and first_line.startswith('#!'):
        first_line_lower = first_line.lower()
        if 'python' in first_line_lower:
            return 'python'
        elif any(sh in first_line_lower for sh in ['bash', 'sh', 'zsh']):
            return 'shell'

    return None

def extract_argparse_definitions(root_node):
    """
    Statically analyzes the Python AST to find dest names mapped to flags.
    """
    attr_to_flags = {}
    for node in ast.walk(root_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument':
                flags = []
                dest = None
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        flags.append(arg.value)
                    elif isinstance(arg, ast.Str):
                        flags.append(arg.s)

                for kw in node.keywords:
                    if kw.arg == 'dest':
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            dest = kw.value.value
                        elif isinstance(kw.value, ast.Str):
                            dest = kw.value.s

                if not dest and flags:
                    long_flags = [f for f in flags if f.startswith('--')]
                    if long_flags:
                        dest = long_flags[0].lstrip('-').replace('-', '_')
                    else:
                        dest = flags[0].lstrip('-').replace('-', '_')

                if dest:
                    attr_to_flags[dest] = flags
    return attr_to_flags

def extract_gated_vars_and_flags(test_node, attr_to_flags):
    """
    Extracts flags and env vars guarding a specific condition block.
    """
    gated_flags = []
    gated_envs = []

    for node in ast.walk(test_node):
        if isinstance(node, ast.Call):
            is_getenv = False
            is_environ_get = False
            if isinstance(node.func, ast.Name) and node.func.id == 'getenv':
                is_getenv = True
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr == 'getenv' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                    is_getenv = True
                elif node.func.attr == 'get' and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == 'environ':
                    is_environ_get = True

            if (is_getenv or is_environ_get) and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    gated_envs.append(first_arg.value)
                elif isinstance(first_arg, ast.Str):
                    gated_envs.append(first_arg.s)

        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and node.value.attr == 'environ':
                if hasattr(node, 'slice'):
                    if isinstance(node.slice, ast.Index):
                        sl = node.slice.value
                    else:
                        sl = node.slice
                    if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                        gated_envs.append(sl.value)
                    elif isinstance(sl, ast.Str):
                        gated_envs.append(sl.s)

        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value
            if val.startswith('-'):
                gated_flags.append(val)
        elif isinstance(node, ast.Str):
            val = node.s
            if val.startswith('-'):
                gated_flags.append(val)

        elif isinstance(node, ast.Attribute):
            attr_name = node.attr
            if attr_name in attr_to_flags:
                gated_flags.extend(attr_to_flags[attr_name])

    return list(set(gated_flags)), list(set(gated_envs))

def is_decision_print(node):
    """
    Checks if a Python AST Call prints structured decision JSON.
    """
    is_print_func = False
    if isinstance(node.func, ast.Name) and node.func.id == 'print':
        is_print_func = True
    elif isinstance(node.func, ast.Attribute) and node.func.attr == 'write':
        is_print_func = True

    if not is_print_func:
        return False

    has_key = False
    has_val = False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            val = sub.value.lower()
            if any(k in val for k in ['decision', 'status', 'action']):
                has_key = True
            if any(v in val for v in ['block', 'deny', 'reject']):
                has_val = True
        elif isinstance(sub, ast.Str):
            val = sub.s.lower()
            if any(k in val for k in ['decision', 'status', 'action']):
                has_key = True
            if any(v in val for v in ['block', 'deny', 'reject']):
                has_val = True

    return has_key and has_val

def find_python_block_paths(root_node, attr_to_flags):
    """
    Walks Python AST to collect block paths with their gating conditions.
    """
    block_paths = []

    def dfs(node, current_flags, current_envs):
        is_block = False
        is_json = False

        if isinstance(node, ast.Call):
            is_exit_call = False
            if isinstance(node.func, ast.Name) and node.func.id in ('exit', 'quit'):
                is_exit_call = True
            elif isinstance(node.func, ast.Attribute) and node.func.attr == 'exit':
                if isinstance(node.func.value, ast.Name) and node.func.value.id == 'sys':
                    is_exit_call = True

            if is_exit_call:
                if not node.args:
                    is_block = False
                else:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant):
                        if first_arg.value == 0 or first_arg.value is None:
                            is_block = False
                        else:
                            is_block = True
                    elif isinstance(first_arg, ast.Str):
                        if first_arg.s == '0':
                            is_block = False
                        else:
                            is_block = True
                    elif isinstance(first_arg, ast.Num):
                        if first_arg.n == 0:
                            is_block = False
                        else:
                            is_block = True
                    else:
                        is_block = True

            if not is_block and is_decision_print(node):
                is_block = True
                is_json = True

        elif isinstance(node, ast.Raise):
            is_block = True

        if is_block:
            block_paths.append({
                'node': node,
                'gated_flags': list(set(current_flags)),
                'gated_envs': list(set(current_envs)),
                'prints_json': is_json
            })

        if isinstance(node, ast.If):
            flags, envs = extract_gated_vars_and_flags(node.test, attr_to_flags)
            next_flags = current_flags + flags
            next_envs = current_envs + envs

            for child in node.body:
                dfs(child, next_flags, next_envs)
            for child in node.orelse:
                dfs(child, next_flags, next_envs)
        else:
            for child in ast.iter_child_nodes(node):
                dfs(child, current_flags, current_envs)

    dfs(root_node, [], [])
    return block_paths

def analyze_shell_script(content):
    """
    Parses Shell scripts to collect block paths with their gating conditions.
    """
    lines = content.splitlines()
    block_paths = []
    condition_stack = []

    def parse_shell_condition(cond_str):
        # Match flags possibly enclosed in quotes
        flags = re.findall(r'(?:^|\s|["\'])(--[a-zA-Z0-9_-]+|-[a-zA-Z0-9_-]+)(?:$|\s|["\'])', cond_str)
        envs = re.findall(r'\$([A-Z_][A-Z0-9_]*)|\$\{([A-Z_][A-Z0-9_]1*)\}', cond_str)
        flat_envs = []
        for g1, g2 in envs:
            if g1:
                flat_envs.append(g1)
            elif g2:
                flat_envs.append(g2)
        return list(set(flags)), list(set(flat_envs))

    def is_shell_decision_print(line):
        line_lower = line.lower()
        if not any(cmd in line_lower for cmd in ['echo', 'printf', 'cat']):
            return False
        has_key = any(k in line_lower for k in ['decision', 'status', 'action'])
        has_val = any(v in line_lower for v in ['block', 'deny', 'reject'])
        return has_key and has_val

    def is_shell_exit(line):
        line_clean = line.split('#')[0].strip()
        match = re.search(r'\bexit\s+(\S+)', line_clean)
        if match:
            exit_code = match.group(1).strip(';"\'')
            if exit_code in ('0', '"0"', "'0'"):
                return False
            return True
        return False

    for i, line in enumerate(lines):
        line_clean = line.split('#')[0].strip()
        if not line_clean:
            continue

        if line_clean.startswith('if ') or line_clean.startswith('elif '):
            cond_part = line_clean
            if '; then' in cond_part:
                cond_part = cond_part.split('; then')[0]
            if cond_part.startswith('if '):
                cond_part = cond_part[3:]
            elif cond_part.startswith('elif '):
                cond_part = cond_part[5:]
                if condition_stack:
                    condition_stack.pop()

            c_flags, c_envs = parse_shell_condition(cond_part)
            condition_stack.append({'flags': c_flags, 'envs': c_envs})

        elif line_clean == 'fi':
            if condition_stack:
                condition_stack.pop()

        is_block = False
        is_json = False
        inline_flags = []
        inline_envs = []

        if '&&' in line_clean:
            parts = line_clean.split('&&')
            action_part = parts[-1].strip()
            cond_parts = " ".join(parts[:-1])
            if is_shell_exit(action_part) or is_shell_decision_print(action_part):
                is_block = True
                is_json = is_shell_decision_print(action_part)
                inline_flags, inline_envs = parse_shell_condition(cond_parts)
        else:
            if is_shell_exit(line_clean) or is_shell_decision_print(line_clean):
                is_block = True
                is_json = is_shell_decision_print(line_clean)

        if is_block:
            all_flags = []
            all_envs = []
            for cond in condition_stack:
                all_flags.extend(cond['flags'])
                all_envs.extend(cond['envs'])
            all_flags.extend(inline_flags)
            all_envs.extend(inline_envs)

            block_paths.append({
                'line_num': i + 1,
                'gated_flags': list(set(all_flags)),
                'gated_envs': list(set(all_envs)),
                'prints_json': is_json
            })

    return block_paths

def audit_wiring(command_str, root_dir=None):
    """
    Audits a wiring and returns a classification:
    - classification: EFFECTIVE, NOOP_SWALLOWED_EXIT, NOOP_NO_BLOCK_PATH, DECLARED_UNREACHABLE, or UNKNOWN
    - reason: explaining the classification
    - notes: list of lower-severity notes (e.g. redirections)
    - script_path: resolved script path
    """
    notes = []

    # 1. Parse wiring
    script_rel_path, wiring_args, wiring_envs = parse_wiring_command(command_str)
    if not script_rel_path:
        return 'UNKNOWN', 'Could not parse script path from wiring', notes, None

    # Check for redirections
    redirs = detect_redirections(command_str)
    if redirs:
        notes.append(f"Redirection detected in wiring: {', '.join(redirs)}")

    # Check if wiring has swallowed exit code
    swallowed = is_swallowed_exit(command_str)

    # Resolve script path
    if root_dir:
        script_path = os.path.join(root_dir, script_rel_path)
    else:
        script_path = script_rel_path

    if not os.path.exists(script_path):
        return 'UNKNOWN', f"Script file not found: {script_rel_path}", notes, script_path

    # 2. Detect language
    try:
        with open(script_path, 'r', encoding='utf-8', errors='replace') as f:
            first_line = f.readline()
    except Exception as e:
        return 'UNKNOWN', f"Failed to read script file: {e}", notes, script_path

    lang = detect_language(script_path, first_line)
    if not lang:
        return 'UNKNOWN', "Unsupported script language / extension", notes, script_path

    # Read entire content
    try:
        with open(script_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except Exception as e:
        return 'UNKNOWN', f"Failed to read script file: {e}", notes, script_path

    block_paths = []

    if lang == 'python':
        try:
            root_node = ast.parse(content)
        except SyntaxError as se:
            return 'UNKNOWN', f"Python SyntaxError: {se}", notes, script_path
        except Exception as e:
            return 'UNKNOWN', f"Failed to parse Python AST: {e}", notes, script_path

        attr_to_flags = extract_argparse_definitions(root_node)
        block_paths = find_python_block_paths(root_node, attr_to_flags)

    elif lang == 'shell':
        try:
            block_paths = analyze_shell_script(content)
        except Exception as e:
            return 'UNKNOWN', f"Failed to parse Shell script: {e}", notes, script_path

    # 3. Apply classification logic
    # Find which block paths are reachable
    reachable_paths = []
    for bp in block_paths:
        # Check if all gated flags are present in wiring args
        flags_satisfied = True
        for f in bp['gated_flags']:
            if f not in wiring_args:
                flags_satisfied = False
                break

        # Check if all gated envs are present in wiring envs
        envs_satisfied = True
        for env in bp['gated_envs']:
            if env not in wiring_envs:
                envs_satisfied = False
                break

        if flags_satisfied and envs_satisfied:
            reachable_paths.append(bp)

    if not reachable_paths:
        if block_paths:
            # We have block paths but none are reachable
            # Report the gating flags or envs of the first block path as explanation
            missing_details = []
            for bp in block_paths:
                missing = []
                for f in bp['gated_flags']:
                    if f not in wiring_args:
                        missing.append(f"flag {f}")
                for e in bp['gated_envs']:
                    if e not in wiring_envs:
                        missing.append(f"env var {e}")
                if missing:
                    missing_details.append(f"({', '.join(missing)})")
            reason = f"Block paths exist but are unreachable due to missing configuration: {', '.join(missing_details)}"
            return 'DECLARED_UNREACHABLE', reason, notes, script_path
        else:
            return 'NOOP_NO_BLOCK_PATH', "No block paths (non-zero exit or decision JSON) found in the script", notes, script_path

    # We have reachable paths!
    # Does any reachable path print decision JSON?
    reachable_prints_json = any(bp['prints_json'] for bp in reachable_paths)

    if reachable_prints_json:
        # Channel B works end to end. It's effective!
        return 'EFFECTIVE', "Script prints structured decision JSON on a reachable path (Channel B active)", notes, script_path
    else:
        # Reaches block path, but it only exits non-zero (Channel A).
        # Check if Channel A is swallowed by the wiring command.
        if swallowed:
            return 'NOOP_SWALLOWED_EXIT', "Script exits non-zero but the wiring swallows the exit status (Channel A neutralized)", notes, script_path
        else:
            return 'EFFECTIVE', "Script exits non-zero on a reachable path and wiring does not swallow exit status (Channel A active)", notes, script_path
