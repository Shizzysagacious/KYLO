import os
import ast
import json
import time
import re
from pathlib import Path
from .utils import load_json, save_json

STATE_DIR_NAME = '.kylo'
STATE_FILE = 'state.json'
CONTEXT_FILE = 'context.json'

STOPWORDS = set(["the","and","or","to","a","of","in","for","is","with","on","that","this"])


class AuditError(Exception):
    """Custom exception for audit errors"""
    pass


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
    
    # create initial context
    context = {
        "project_initialized": time.time(),
        "total_audits": 0,
        "last_audit": None,
        "files_tracked": {},
        "vulnerability_history": []
    }
    save_json(os.path.join(state_dir, CONTEXT_FILE), context)
    
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


def validate_audit_target(path):
    """Validate the audit target and return list of Python files to audit"""
    if not os.path.exists(path):
        raise AuditError(f"❌ Path does not exist: {path}")
    
    python_files = []
    
    if os.path.isfile(path):
        if not path.endswith('.py'):
            raise AuditError(f"❌ Invalid file type: {path}\n   Only .py files are supported. Got: {os.path.splitext(path)[1]}")
        python_files.append(path)
    elif os.path.isdir(path):
        # Walk directory to find Python files
        for root, dirs, files in os.walk(path):
            # Skip hidden directories and common non-code directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules', 'venv', '.venv', 'env']]
            
            for f in files:
                if f.endswith('.py'):
                    python_files.append(os.path.join(root, f))
        
        if not python_files:
            raise AuditError(f"❌ No Python files found in: {path}\n   Make sure the directory contains .py files")
    else:
        raise AuditError(f"❌ Invalid target: {path}\n   Must be a .py file or directory")
    
    return python_files


def update_context(cwd, files_audited, total_issues):
    """Update the context file with audit information"""
    state_dir = os.path.join(cwd, STATE_DIR_NAME)
    context_path = os.path.join(state_dir, CONTEXT_FILE)
    
    context = load_json(context_path) or {
        "project_initialized": time.time(),
        "total_audits": 0,
        "last_audit": None,
        "files_tracked": {},
        "vulnerability_history": []
    }
    
    # Update audit count
    context["total_audits"] += 1
    context["last_audit"] = time.time()
    
    # Update files tracked
    for file_path in files_audited:
        if file_path not in context["files_tracked"]:
            context["files_tracked"][file_path] = {
                "first_seen": time.time(),
                "audit_count": 0,
                "last_issues": 0
            }
        
        context["files_tracked"][file_path]["audit_count"] += 1
        context["files_tracked"][file_path]["last_audited"] = time.time()
        context["files_tracked"][file_path]["last_issues"] = files_audited[file_path]
    
    # Add to vulnerability history
    context["vulnerability_history"].append({
        "timestamp": time.time(),
        "total_issues": total_issues,
        "files_audited": len(files_audited)
    })
    
    # Keep only last 50 history entries
    if len(context["vulnerability_history"]) > 50:
        context["vulnerability_history"] = context["vulnerability_history"][-50:]
    
    save_json(context_path, context)
    return context


def get_context_summary(cwd):
    """Get a summary of past audits from context"""
    state_dir = os.path.join(cwd, STATE_DIR_NAME)
    context_path = os.path.join(state_dir, CONTEXT_FILE)
    
    context = load_json(context_path)
    if not context or context.get("total_audits", 0) == 0:
        return None
    
    last_audit = context.get("last_audit")
    if last_audit:
        days_ago = (time.time() - last_audit) / 86400
        if days_ago < 1:
            time_str = "today"
        elif days_ago < 2:
            time_str = "yesterday"
        else:
            time_str = f"{int(days_ago)} days ago"
    else:
        time_str = "never"
    
    return {
        "total_audits": context.get("total_audits", 0),
        "last_audit_str": time_str,
        "files_tracked": len(context.get("files_tracked", {}))
    }


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
            try:
                gemini_issues = analyze_code_security(src, context, force=force)
                # Tag Gemini issues and append
                for gi in gemini_issues:
                    gi['source'] = 'gemini'
                    gi.setdefault('file', path)
                    merged.append(gi)
            except Exception as gemini_error:
                # AI service unavailable - continue with local analysis
                print(f"⚠️  AI analysis unavailable: {gemini_error}")
                print("   Continuing with local security scanning...")
    except ImportError:
        # gemini_analyzer not available
        pass
    except Exception:
        pass

    return merged


def audit_path(path):
    path = os.path.abspath(path)
    cwd = os.getcwd()
    
    # Validate target first
    try:
        targets = validate_audit_target(path)
    except AuditError as e:
        print(str(e))
        return {"error": str(e), "scanned": [], "summary": {"files": 0, "issues": 0}}
    
    readme = os.path.join(cwd, 'README.md')
    keywords = _extract_readme_keywords(readme)

    state_dir = os.path.join(cwd, STATE_DIR_NAME)
    os.makedirs(state_dir, exist_ok=True)
    state_path = os.path.join(state_dir, STATE_FILE)
    state = load_json(state_path) or {"files": {}, "generated": time.time()}

    # Show context summary if available
    context_summary = get_context_summary(cwd)
    if context_summary:
        print(f"\n📊 Audit History:")
        print(f"   Total audits: {context_summary['total_audits']}")
        print(f"   Last audit: {context_summary['last_audit_str']}")
        print(f"   Files tracked: {context_summary['files_tracked']}\n")

    report = {"scanned": [], "summary": {"files": 0, "issues": 0}}
    files_audited = {}

    print(f"🔍 Scanning {len(targets)} Python file(s)...\n")

    for t in targets:
        try:
            issues = audit_file(t, readme_keywords=keywords)
            state['files'][t] = {"last_scanned": time.time(), "issues": issues}
            report['scanned'].append({"file": t, "issues_count": len(issues)})
            report['summary']['files'] += 1
            report['summary']['issues'] += len(issues)
            files_audited[t] = len(issues)
            
            # Print per-file summary
            if len(issues) > 0:
                print(f"❌ {t}: {len(issues)} issue(s) found")
            else:
                print(f"✅ {t}: No issues detected")
        except Exception as e:
            print(f"⚠️  Error scanning {t}: {e}")
            continue

    state['generated'] = time.time()
    save_json(state_path, state)
    
    # Update context with this audit
    update_context(cwd, files_audited, report['summary']['issues'])
    
    print(f"\n{'='*50}")
    print(f"📊 Audit Complete")
    print(f"{'='*50}")
    print(f"Files scanned: {report['summary']['files']}")
    print(f"Total issues: {report['summary']['issues']}")
    print(f"\n💾 Report saved to: {state_path}")
    
    return report


def secure_target(target):
    print(f"Running security checks on {target} (prototype)")
    try:
        report = audit_path(target)
        if "error" in report:
            return
        print(f"\nReview .kylo/state.json for detailed findings and fix suggestions.")
    except Exception as e:
        print(f"❌ Error during security scan: {e}")