"""Enhanced security scanner with test-net and aggressive modes"""
import ast
import os
import re
from typing import Dict, List, Optional
from pathlib import Path
from .secure_storage import SecureStorage
from .usage_tracker import UsageTracker
from rich.console import Console

console = Console()

class SecurityScanner:
    def __init__(self, kylo_root: Path, mode: str = 'aggressive'):
        """Security scanner: default to aggressive/advanced checks only.

        The project owner requested only advanced checks; basic checks have
        been removed to keep behavior strict and focused on deeper issues.
        """
        self.kylo_root = kylo_root
        self.mode = mode or 'aggressive'
        self.secure = SecureStorage(kylo_root)
        self.tracker = UsageTracker(kylo_root)
        
        # Always load aggressive/advanced rules by default
        self.rules = self._load_rules()
        
    def _load_rules(self) -> Dict:
        """Load security rules based on mode"""
        # Aggressive rule set (advanced-only checks)
        aggressive_rules = {
            'dangerous_functions': {
                'eval', 'exec', 'os.system', 'subprocess.call',
                'pickle.loads', 'yaml.load', 'marshal.loads'
            },
            'sql_risks': {
                'execute', 'executemany', 'raw', 'cursor.execute'
            },
            'file_risks': {
                'open', 'write', 'read', 'load', 'loads'
            },
            'crypto_risks': {
                'random', 'secrets.random', 'random.random', 'random.randint',
                'md5', 'sha1', 'hash', 'digest', 'encrypt', 'decrypt'
            },
            'auth_risks': {
                'user', 'admin', 'role', 'permission', 'session', 'cookie',
                'token', 'key', 'password', 'credential', 'login', 'authenticate',
            },
            'data_risks': {
                'json.loads', 'parse', 'decode', 'deserialize', 'fromstring'
            },
            'network_risks': {
                'socket', 'connect', 'listen', 'bind', 'request', 'get', 'post', 'send'
            }
        }

        return aggressive_rules
    
    def scan_code(self, code: str, filename: str) -> List[Dict]:
        """Scan code for security issues"""
        self.tracker.track_secure_scan(filename, self.mode)
        
        issues = []
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            issues.append({
                'severity': 'critical',
                'message': f'Syntax error: {str(e)}',
                'line': e.lineno,
                'type': 'syntax'
            })
            return issues
            
        class Visitor(ast.NodeVisitor):
            def __init__(self, scanner):
                self.scanner = scanner
                self.issues = issues
                
            def visit_Call(self, node):
                # Check function calls
                func_name = ''
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = f"{self.get_attribute_name(node.func)}"
                
                # Check against rules
                for category, risky_funcs in self.scanner.rules.items():
                    if any(rf in func_name for rf in risky_funcs):
                        self.issues.append({
                            'severity': 'high',
                            'message': f'Potentially dangerous {category}: {func_name}',
                            'line': node.lineno,
                            'type': category,
                            'context': self.get_context(node)
                        })
                
                self.generic_visit(node)
            
            def get_attribute_name(self, node):
                parts = []
                while isinstance(node, ast.Attribute):
                    parts.append(node.attr)
                    node = node.value
                if isinstance(node, ast.Name):
                    parts.append(node.id)
                return '.'.join(reversed(parts))
            
            def get_context(self, node):
                return {
                    'code': ast.get_source_segment(code, node),
                    'lineno': node.lineno
                }
        
        visitor = Visitor(self)
        visitor.visit(tree)
        
        # Additional checks based on mode
        if self.mode in ('test-net', 'aggressive'):
            # Check for hardcoded secrets
            secret_pattern = re.compile(
                r'(password|secret|key|token|credential)\s*=\s*[\'"](.*?)[\'"]',
                re.IGNORECASE
            )
            for match in secret_pattern.finditer(code):
                issues.append({
                    'severity': 'critical',
                    'message': 'Possible hardcoded secret detected',
                    'line': code.count('\n', 0, match.start()) + 1,
                    'type': 'secret',
                    'context': {'code': match.group(0)}
                })
        
        if self.mode == 'aggressive':
            # Check for any TODO/FIXME comments
            comment_pattern = re.compile(r'#.*?(TODO|FIXME|XXX|HACK)', re.IGNORECASE)
            for match in comment_pattern.finditer(code):
                issues.append({
                    'severity': 'medium',
                    'message': 'Security-relevant comment found',
                    'line': code.count('\n', 0, match.start()) + 1,
                    'type': 'comment',
                    'context': {'code': match.group(0)}
                })
        
        return issues
    
    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a file for security issues"""
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        return self.scan_code(code, filepath)
    
    def scan_directory(self, dirpath: str) -> Dict[str, List[Dict]]:
        """Recursively scan a directory"""
        results = {}
        for root, _, files in os.walk(dirpath):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    results[filepath] = self.scan_file(filepath)
        return results