"""Secure usage tracking for Kylo"""
import os
import time
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from .secure_storage import SecureStorage

class UsageTracker:
    def __init__(self, kylo_root: Path):
        self.secure = SecureStorage(kylo_root)
        self.stats_file = kylo_root / '.kylo' / 'stats' / 'usage.json'
        self.stats_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize rate limiting, reading from env vars for creator control.
        # API limit (KYLO_RATE_LIMIT_API) specifies how many Gemini/LLM requests
        # or other outbound API calls Kylo will make per hour. Default is 1000.
        import os
        self.rate_limits = {
            'audit': int(os.getenv('KYLO_RATE_LIMIT_AUDITS', '100')),
            'secure': int(os.getenv('KYLO_RATE_LIMIT_SECURE', '50')),
            'api': int(os.getenv('KYLO_RATE_LIMIT_API', '1000')),
        }
        
        self._load_stats()
    
    def _load_stats(self):
        """Load usage statistics"""
        if self.stats_file.exists():
            with open(self.stats_file, 'r') as f:
                self.stats = json.load(f)
        else:
            self.stats = {
                'first_seen': time.time(),
                'total_audits': 0,
                'total_secure_scans': 0,
                'total_api_calls': 0,
                'hourly': {},
                'daily': {}
            }
    
    def _save_stats(self):
        """Save usage statistics"""
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f)
    
    def _update_hourly(self, event_type: str):
        """Update hourly statistics"""
        hour = datetime.now().strftime('%Y-%m-%d-%H')
        if hour not in self.stats['hourly']:
            self.stats['hourly'] = {hour: {}}  # Reset hourly stats
        
        if event_type not in self.stats['hourly'][hour]:
            self.stats['hourly'][hour][event_type] = 0
        self.stats['hourly'][hour][event_type] += 1
    
    def _check_rate_limit(self, event_type: str) -> bool:
        """Check if operation is within rate limits"""
        if event_type not in self.rate_limits:
            return True
            
        hour = datetime.now().strftime('%Y-%m-%d-%H')
        if hour in self.stats['hourly']:
            count = self.stats['hourly'][hour].get(event_type, 0)
            return count < self.rate_limits[event_type]
        return True
    
    def _hash_content(self, content: str) -> str:
        """Create privacy-preserving hash of content"""
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def track_audit(self, file_path: str, content: Optional[str] = None):
        """Track an audit operation"""
        if not self._check_rate_limit('audit'):
            raise Exception("Rate limit exceeded for audits")
            
        self.stats['total_audits'] += 1
        self._update_hourly('audit')
        
        # Store privacy-preserving file info
        if content:
            audit_data = {
                'file_hash': self._hash_content(content),
                'timestamp': time.time(),
                'size': len(content)
            }
            self.secure.store(f"audit_{time.time()}", audit_data)
        
        self._save_stats()
    
    def track_secure_scan(self, target: str, mode: str = 'standard'):
        """Track a secure scan operation"""
        if not self._check_rate_limit('secure'):
            raise Exception("Rate limit exceeded for secure scans")
            
        self.stats['total_secure_scans'] += 1
        self._update_hourly('secure')
        
        scan_data = {
            'target_hash': self._hash_content(target),
            'mode': mode,
            'timestamp': time.time()
        }
        self.secure.store(f"scan_{time.time()}", scan_data)
        
        self._save_stats()
    
    def track_api_call(self, api: str):
        """Track an API call"""
        if not self._check_rate_limit('api'):
            raise Exception("Rate limit exceeded for API calls")
            
        self.stats['total_api_calls'] += 1
        self._update_hourly('api')
        self._save_stats()
    
    def get_usage_report(self) -> Dict:
        """Get usage statistics report"""
        return {
            'summary': {
                'days_active': (time.time() - self.stats['first_seen']) / 86400,
                'total_audits': self.stats['total_audits'],
                'total_secure_scans': self.stats['total_secure_scans'],
                'total_api_calls': self.stats['total_api_calls']
            },
            'rate_limits': self.rate_limits,
            'hourly_stats': self.stats['hourly']
        }