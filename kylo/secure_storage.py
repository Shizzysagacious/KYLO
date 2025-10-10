"""Secure storage module for Kylo's sensitive data"""
import os
import json
import time
import base64
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console

console = Console()

class SecureStorage:
    """Handles encrypted storage of sensitive data"""
    
    def __init__(self, kylo_root: Path):
        self.kylo_root = kylo_root
        self.secure_dir = kylo_root / '.kylo' / 'secure'
        self.secure_dir.mkdir(parents=True, exist_ok=True)
        
        # Lock down permissions on .kylo/secure
        if os.name != 'nt':  # Unix-like systems
            os.chmod(self.secure_dir, 0o700)  # Owner read/write/execute only
            
        self._init_encryption()
    
    def _init_encryption(self):
        """Initialize encryption key with hardware-bound salt"""
        
        # Use machine-specific data to generate salt
        def get_hardware_id() -> bytes:
            """Get unique hardware identifier"""
            try:
                if os.name == 'nt':
                    # Windows: use WMIC to get motherboard serial
                    import subprocess
                    result = subprocess.run(['wmic', 'baseboard', 'get', 'serialnumber'], 
                                         capture_output=True, text=True)
                    serial = result.stdout.split('\n')[1].strip()
                else:
                    # Unix: use first MAC address
                    with open('/sys/class/net/eth0/address', 'r') as f:
                        serial = f.read().strip()
                return serial.encode()
            except Exception:
                # Fallback: use hostname
                return os.uname().nodename.encode()
        
        # Generate salt from hardware ID
        hw_id = get_hardware_id()
        salt = hashlib.sha256(hw_id).digest()
        
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        # Use current working directory as additional entropy
        cwd_bytes = os.getcwd().encode()
        key = base64.urlsafe_b64encode(kdf.derive(cwd_bytes))
        self.fernet = Fernet(key)
    
    def store(self, key: str, data: Any):
        """Store encrypted data"""
        json_data = json.dumps(data)
        encrypted = self.fernet.encrypt(json_data.encode())
        
        file_path = self.secure_dir / f"{key}.enc"
        with open(file_path, 'wb') as f:
            f.write(encrypted)
    
    def load(self, key: str) -> Optional[Any]:
        """Load and decrypt data"""
        try:
            file_path = self.secure_dir / f"{key}.enc"
            if not file_path.exists():
                return None
                
            with open(file_path, 'rb') as f:
                encrypted = f.read()
            
            decrypted = self.fernet.decrypt(encrypted)
            return json.loads(decrypted)
        except Exception as e:
            console.print(f"[red]Error loading secure data: {e}[/red]")
            return None
    
    def store_api_key(self, service: str, api_key: str):
        """Securely store an API key"""
        # New behavior: store all API keys in a single, fixed filename so
        # the encrypted file is always named `humanwhocodes.enc` as requested.
        # Keep backwards compatibility by still working with legacy files.
        payload = {
            "service": service,
            "key": api_key,
            "stored_at": time.time()
        }
        file_path = self.secure_dir / "humanwhocodes.enc"
        encrypted = self.fernet.encrypt(json.dumps(payload).encode())
        with open(file_path, 'wb') as f:
            f.write(encrypted)

    # --- Admin token management ---
    def set_admin_token(self, token: str):
        """Set an admin token (stored encrypted). Token is salted+derived before storage."""
        salt = os.urandom(16)
        # derive
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(token.encode()))
        # store as base64 strings
        payload = {
            'salt': base64.b64encode(salt).decode(),
            'hash': base64.b64encode(key).decode(),
            'created': time.time()
        }
        # use generic store for admin
        self.store('admin', payload)

    def verify_admin_token(self, token: str) -> bool:
        """Verify provided admin token against stored value."""
        data = self.load('admin')
        if not data:
            return False
        try:
            salt = base64.b64decode(data.get('salt'))
            stored = data.get('hash')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200000,
            )
            derived = base64.urlsafe_b64encode(kdf.derive(token.encode())).decode()
            return derived == stored
        except Exception:
            return False

    def admin_exists(self) -> bool:
        return (self.secure_dir / 'admin.enc').exists()

    # --- Migration helper ---
    def migrate_legacy_api_keys(self):
        """Migrate legacy api_key_<service>.enc files into single humanwhocodes.enc file.
        If multiple legacy keys exist, the first one is migrated and others are removed.
        """
        try:
            legacy = []
            for p in os.listdir(self.secure_dir):
                if p.startswith('api_key_') and p.endswith('.enc'):
                    svc = p[len('api_key_'):-len('.enc')]
                    legacy.append(svc)
            if not legacy:
                return False
            # pick first
            svc = legacy[0]
            data = self.load(f'api_key_{svc}')
            if not data:
                return False
            payload = {
                'service': svc,
                'key': data.get('key'),
                'migrated_at': time.time()
            }
            human_file = self.secure_dir / 'humanwhocodes.enc'
            encrypted = self.fernet.encrypt(json.dumps(payload).encode())
            with open(human_file, 'wb') as f:
                f.write(encrypted)
            # remove legacy files
            for s in legacy:
                try:
                    fp = self.secure_dir / f'api_key_{s}.enc'
                    if fp.exists():
                        fp.unlink()
                except Exception:
                    pass
            return True
        except Exception:
            return False
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Retrieve an API key"""
        # Check the new single-file location
        human_file = self.secure_dir / "humanwhocodes.enc"
        if human_file.exists():
            try:
                with open(human_file, 'rb') as f:
                    encrypted = f.read()
                decrypted = self.fernet.decrypt(encrypted)
                data = json.loads(decrypted)
                if data.get('service') == service:
                    return data.get('key')
            except Exception:
                pass

        # Fallback to legacy per-service files
        data = self.load(f"api_key_{service}")
        return data["key"] if data else None

    def list_keys(self) -> list:
        """List services with stored API keys (do not return secrets)."""
        keys = []
        try:
            # Check single-file name first
            human_file = self.secure_dir / "humanwhocodes.enc"
            if human_file.exists():
                try:
                    with open(human_file, 'rb') as f:
                        encrypted = f.read()
                    decrypted = self.fernet.decrypt(encrypted)
                    data = json.loads(decrypted)
                    svc = data.get('service')
                    if svc:
                        keys.append(svc)
                except Exception:
                    # If decrypt fails, still expose a generic name
                    keys.append('humanwhocodes')

            # Also include any legacy per-service files
            for p in os.listdir(self.secure_dir):
                if p.startswith('api_key_') and p.endswith('.enc'):
                    svc = p[len('api_key_'):-len('.enc')]
                    if svc not in keys:
                        keys.append(svc)
        except Exception:
            pass
        return keys

    def remove_api_key(self, service: str) -> bool:
        """Remove a stored API key for a service. Returns True if deleted."""
        try:
            # Check humanwhocodes.enc
            human_file = self.secure_dir / "humanwhocodes.enc"
            if human_file.exists():
                try:
                    with open(human_file, 'rb') as f:
                        encrypted = f.read()
                    decrypted = self.fernet.decrypt(encrypted)
                    data = json.loads(decrypted)
                    if data.get('service') == service:
                        human_file.unlink()
                        return True
                except Exception:
                    # If cannot decrypt, still attempt removal if requested
                    human_file.unlink()
                    return True

            # Fallback to legacy per-service files
            file_path = self.secure_dir / f"api_key_{service}.enc"
            if file_path.exists():
                file_path.unlink()
                return True
        except Exception:
            pass
        return False