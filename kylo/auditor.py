import os
import ast
import json
import time
import re
from .utils import load_json, save_json

STATE_DIR_NAME = '.kylo'
STATE_FILE = 'state.json'

STOPWORDS = set(["the","and","or","to","a","of","in","for","is","with","on","that","this"])


def init_project(cwd):
    cwd = os.path.abspath(cwd)
    readme_path = os.path.join(cwd, 'README.md')
    state_dir = os.path.join(cwd, STATE_DIR_NAME)
    deps_dir = os.path.join(state_dir, 'deps')
    os.makedirs(deps_dir, exist_ok=True)

    if not os.path.exists(readme_path):
        template = "# Project README\n\nPlease describe your project goals here. Kylo will use this to align auditing results with project intent.\n"
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(template)
        print(f"Created {readme_path}. Please update it with your project goals and re-run `kylo init`.")
    else:
        print(f"Found README.md at {readme_path}")

    # copy requirements if present
    req_in = os.path.join(cwd, 'requirements.txt')
    if os.path.exists(req_in):
        with open(req_in, 'r', encoding='utf-8') as src, open(os.path.join(deps_dir, 'requirements.txt'), 'w', encoding='utf-8') as dst:
            dst.write(src.read())
        print("Copied requirements.txt into .kylo/deps/")

    # create initial state
    state = {"files": {}, "generated": time.time()}
    save_json(os.path.join(state_dir, STATE_FILE), state)
    print(f"Initialized kylo state at {state_dir}")


def _extract_readme_keywords(readme_path):
    if not os.path.exists(readme_path):
        return []
    text = open(readme_path, 'r', encoding='utf-8').read()
    words = re.findall(r"[A-Za-z]+", text.lower())
    keywords = [w for w in words if w not in STOPWORDS]
    # take top unique keywords
    seen = set()
    out = []
    for w in keywords:
        if w in seen:
            continue
        seen.add(w)
        out.append(w)
        if len(out) >= 20:
            break
    return out


def audit_file(path, readme_keywords=None):
    issues = []
    try:
        src = open(path, 'r', encoding='utf-8').read()
        tree = ast.parse(src, filename=path)
    except Exception as e:
        issues.append({"severity": "error", "message": f"Failed to parse: {e}", "file": path})
        return issues

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node):
            # detect use of eval/exec
            if isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec'):
                issues.append({"file": path, "line": node.lineno, "severity": "high", "message": f"Use of {node.func.id}() can be dangerous.", "suggestion": "Avoid eval/exec; use safe parsers or restricted execution."})

            # detect potential SQL execute with f-strings or concatenation
            func_name = None
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name and func_name.lower() in ('execute', 'executemany'):
                if node.args:
                    first = node.args[0]
                    # f-string
                    if isinstance(first, ast.JoinedStr):
                        issues.append({"file": path, "line": first.lineno, "severity": "critical", "message": "SQL query constructed with f-string — possible SQL injection.", "suggestion": "Use parameterized queries (e.g., placeholders + parameters) instead of f-strings."})
                    # concatenation or formatting
                    if isinstance(first, ast.BinOp) and (isinstance(first.left, ast.Str) or isinstance(first.right, ast.Str)):
                        issues.append({"file": path, "line": first.lineno, "severity": "high", "message": "SQL query built via string concatenation — possible SQL injection.", "suggestion": "Use parameterized queries instead."})
            self.generic_visit(node)

        def visit_JoinedStr(self, node):
            # f-string usage detection (standalone)
            # Could be benign; flag when used in suspicious contexts in visit_Call above.
            self.generic_visit(node)

    Visitor().visit(tree)

    # simple alignment check: ensure README keywords appear in source
    alignment_issues = []
    if readme_keywords:
        text_lower = src.lower()
        missing = [k for k in readme_keywords if k not in text_lower]
        if missing:
            alignment_issues.append({"file": path, "severity": "medium", "message": "Potential misalignment with README goals.", "details": {"missing_keywords_sample": missing[:5]}})

    merged = issues + alignment_issues

    # Optionally call Gemini for deeper analysis if configured
    try:
        from .gemini_analyzer import analyze_code_security
        from dotenv import load_dotenv
        load_dotenv()
        force = False
        if os.getenv('KYLO_FORCE_GEMINI', '0') == '1':
            force = True
        if force:
            context = {
                'goals': readme_keywords or [],
                'file': path
            }
            gemini_issues = analyze_code_security(src, context, force=force)
            # Tag Gemini issues and append
            for gi in gemini_issues:
                gi['source'] = 'gemini'
                gi.setdefault('file', path)
                merged.append(gi)
    except Exception:
        pass

    return merged


def audit_path(path):
    path = os.path.abspath(path)
    cwd = os.getcwd()
    readme = os.path.join(cwd, 'README.md')
    keywords = _extract_readme_keywords(readme)

    state_dir = os.path.join(cwd, STATE_DIR_NAME)
    os.makedirs(state_dir, exist_ok=True)
    state_path = os.path.join(state_dir, STATE_FILE)
    state = load_json(state_path) or {"files": {}, "generated": time.time()}

    report = {"scanned": [], "summary": {"files": 0, "issues": 0}}

    targets = []
    if os.path.isfile(path) and path.endswith('.py'):
        targets = [path]
    else:
        for root, dirs, files in os.walk(path):
            for f in files:
                if f.endswith('.py'):
                    targets.append(os.path.join(root, f))

    for t in targets:
        issues = audit_file(t, readme_keywords=keywords)
        state['files'][t] = {"last_scanned": time.time(), "issues": issues}
        report['scanned'].append({"file": t, "issues_count": len(issues)})
        report['summary']['files'] += 1
        report['summary']['issues'] += len(issues)

    state['generated'] = time.time()
    save_json(state_path, state)
    return report


def secure_target(target):
    print(f"Running security checks on {target} (prototype)")
    report = audit_path(target)
    print(f"Scanned {report['summary']['files']} files, found {report['summary']['issues']} issues")
    print("Review .kylo/state.json for details and line-level suggestions.")
