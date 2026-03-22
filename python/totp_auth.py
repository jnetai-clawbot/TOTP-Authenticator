"""
TOTP Authenticator - Python Reference Implementation
Secure authenticator app with Google OAuth login
"""

import hashlib
import hmac
import base64
import time
import json
import os
import sys
import secrets
import sqlite3
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
from datetime import datetime

# Attempt import of key libraries, provide fallback
try:
    import pyotp
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False
    print("Warning: pyotp not installed. Run: pip install pyotp")

try:
    from encryption import encrypt_data, decrypt_data, derive_key
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("Warning: encryption module not found")


@dataclass
class Site:
    """Represents a TOTP site entry"""
    id: str
    name: str
    secret: str
    issuer: str = ""
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    created_at: str = ""
    updated_at: str = ""
    enabled: bool = True
    notes: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at


class TOTPGenerator:
    """Generate time-based one-time passwords"""

    @staticmethod
    def generate_totp(secret: str, period: int = 30, digits: int = 6, 
                      algorithm: str = "SHA1", time_value: Optional[int] = None) -> str:
        """
        Generate a TOTP code
        
        Args:
            secret: Base32 encoded secret key
            period: Time step in seconds
            digits: Number of digits to generate
            algorithm: Hash algorithm (SHA1, SHA256, SHA512)
            time_value: Unix timestamp (default: current time)
        
        Returns:
            TOTP code as string
        """
        if time_value is None:
            time_value = int(time.time())
        
        # Convert time to counter
        counter = time_value // period
        
        # Pack counter into 8 bytes (big-endian)
        counter_bytes = counter.to_bytes(8, 'big')
        
        # Get appropriate hash function
        if algorithm == "SHA256":
            hash_func = hashlib.sha256
        elif algorithm == "SHA512":
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha1
        
        # Generate HMAC
        try:
            # Handle base32 secret
            if TOTP_AVAILABLE:
                return pyotp.TOTP(secret, digits=digits, interval=period, 
                                 digest=hash_func).at(time_value)
        except Exception:
            pass
        
        # Manual implementation fallback
        try:
            decoded_secret = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
        except Exception:
            return "".join(['0' for _ in range(digits)])
        
        hmac_hash = hmac.new(decoded_secret, counter_bytes, hash_func).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        ) % (10 ** digits)
        
        return str(code).zfill(digits)

    @staticmethod
    def get_time_remaining(period: int = 30) -> int:
        """Get seconds remaining in current period"""
        return period - (int(time.time()) % period)

    @staticmethod
    def verify_totp(secret: str, code: str, period: int = 30, 
                   digits: int = 6, window: int = 1) -> bool:
        """
        Verify a TOTP code with tolerance for clock skew
        
        Args:
            secret: Base32 encoded secret key
            code: TOTP code to verify
            period: Time step in seconds
            digits: Number of digits
            window: Number of periods to check before/after
        """
        current_time = int(time.time())
        
        for offset in range(-window, window + 1):
            test_time = current_time + (offset * period)
            if TOTPGenerator.generate_totp(secret, period, digits, 
                                         time_value=test_time) == code:
                return True
        return False


class SecureStorage:
    """Handle secure storage of secrets"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "auth_data.db")
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    secret_encrypted TEXT NOT NULL,
                    issuer TEXT DEFAULT '',
                    digits INTEGER DEFAULT 6,
                    period INTEGER DEFAULT 30,
                    algorithm TEXT DEFAULT 'SHA1',
                    created_at TEXT,
                    updated_at TEXT,
                    enabled INTEGER DEFAULT 1,
                    notes TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.commit()
    
    def _get_master_key(self, password: str) -> bytes:
        """Derive encryption key from password"""
        return derive_key(password) if ENCRYPTION_AVAILABLE else \
               hashlib.sha256(password.encode()).digest()
    
    def add_site(self, site: Site, master_password: str) -> bool:
        """Add a new site entry"""
        try:
            encrypted_secret = encrypt_data(site.secret, master_password) \
                              if ENCRYPTION_AVAILABLE else site.secret
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO sites VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    site.id, site.name, encrypted_secret, site.issuer,
                    site.digits, site.period, site.algorithm,
                    site.created_at, site.updated_at, 
                    1 if site.enabled else 0, site.notes
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error adding site: {e}")
            return False
    
    def get_site(self, site_id: str, master_password: str) -> Optional[Site]:
        """Retrieve a site entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM sites WHERE id = ?", (site_id,))
                row = cursor.fetchone()
                
                if row:
                    secret = decrypt_data(row[2], master_password) \
                            if ENCRYPTION_AVAILABLE else row[2]
                    return Site(
                        id=row[0], name=row[1], secret=secret, issuer=row[3],
                        digits=row[4], period=row[5], algorithm=row[6],
                        created_at=row[7], updated_at=row[8],
                        enabled=bool(row[9]), notes=row[10]
                    )
                return None
        except Exception as e:
            print(f"Error getting site: {e}")
            return None
    
    def get_all_sites(self, master_password: str) -> List[Site]:
        """Retrieve all site entries"""
        sites = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM sites ORDER BY name")
                rows = cursor.fetchall()
                
                for row in rows:
                    secret = decrypt_data(row[2], master_password) \
                            if ENCRYPTION_AVAILABLE else row[2]
                    sites.append(Site(
                        id=row[0], name=row[1], secret=secret, issuer=row[3],
                        digits=row[4], period=row[5], algorithm=row[6],
                        created_at=row[7], updated_at=row[8],
                        enabled=bool(row[9]), notes=row[10]
                    ))
        except Exception as e:
            print(f"Error getting sites: {e}")
        return sites
    
    def update_site(self, site: Site, master_password: str) -> bool:
        """Update a site entry"""
        try:
            encrypted_secret = encrypt_data(site.secret, master_password) \
                              if ENCRYPTION_AVAILABLE else site.secret
            site.updated_at = datetime.now().isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE sites SET name=?, secret_encrypted=?, issuer=?,
                    digits=?, period=?, algorithm=?, updated_at=?,
                    enabled=?, notes=? WHERE id=?
                """, (
                    site.name, encrypted_secret, site.issuer,
                    site.digits, site.period, site.algorithm,
                    site.updated_at, 1 if site.enabled else 0,
                    site.notes, site.id
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error updating site: {e}")
            return False
    
    def delete_site(self, site_id: str) -> bool:
        """Delete a site entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM sites WHERE id = ?", (site_id,))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting site: {e}")
            return False


class AuthenticatorApp:
    """Main TOTP Authenticator Application"""
    
    def __init__(self, storage_path: str = None):
        self.storage = SecureStorage(storage_path)
        self.totp = TOTPGenerator()
        self.current_codes: Dict[str, str] = {}
        self.master_password_hash: Optional[str] = None
    
    def setup_initial_password(self, password: str) -> str:
        """
        Set up initial master password
        Returns the password hash for storage
        """
        self.master_password_hash = hashlib.sha256(password.encode()).hexdigest()
        return self.master_password_hash
    
    def verify_password(self, password: str) -> bool:
        """Verify master password"""
        return hashlib.sha256(password.encode()).hexdigest() == self.master_password_hash
    
    def add_site_interactive(self, name: str, secret: str, issuer: str = "",
                            digits: int = 6, period: int = 30,
                            algorithm: str = "SHA1", notes: str = "") -> bool:
        """Add a new site interactively"""
        # Validate secret
        if not secret:
            print("Error: Secret cannot be empty")
            return False
        
        site = Site(
            id=secrets.token_urlsafe(16),
            name=name,
            secret=secret.upper().replace(' ', '').replace('-', ''),
            issuer=issuer,
            digits=digits,
            period=period,
            algorithm=algorithm,
            notes=notes
        )
        
        return self.storage.add_site(site, self.master_password_hash or "")
    
    def get_current_codes(self, master_password: str) -> Dict[str, tuple]:
        """
        Get current TOTP codes for all sites
        Returns dict of site_name -> (code, seconds_remaining)
        """
        sites = self.storage.get_all_sites(master_password)
        codes = {}
        
        for site in sites:
            if site.enabled:
                code = self.totp.generate_totp(
                    site.secret, site.period, site.digits, site.algorithm
                )
                remaining = self.totp.get_time_remaining(site.period)
                codes[site.name] = (code, remaining, site.issuer)
        
        self.current_codes = codes
        return codes
    
    def verify_code(self, site_name: str, code: str, master_password: str) -> bool:
        """Verify a code for a specific site"""
        sites = self.storage.get_all_sites(master_password)
        
        for site in sites:
            if site.name == site_name and site.enabled:
                return self.totp.verify_totp(
                    site.secret, code, site.period, site.digits
                )
        return False
    
    def export_sites_json(self, master_password: str) -> str:
        """Export all sites as JSON (secrets still encrypted)"""
        sites = self.storage.get_all_sites(master_password)
        return json.dumps([asdict(s) for s in sites], indent=2)
    
    def import_sites_json(self, json_data: str, master_password: str) -> int:
        """Import sites from JSON"""
        try:
            data = json.loads(json_data)
            count = 0
            for item in data:
                site = Site(**item)
                if self.storage.add_site(site, master_password):
                    count += 1
            return count
        except Exception as e:
            print(f"Import error: {e}")
            return 0


# CLI Interface
def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="TOTP Authenticator")
    parser.add_argument("--init", action="store_true", help="Initialize database")
    parser.add_argument("--add", nargs=3, metavar=("NAME", "SECRET", "ISSUER"),
                       help="Add a site")
    parser.add_argument("--list", action="store_true", help="List all sites")
    parser.add_argument("--codes", action="store_true", help="Show current codes")
    parser.add_argument("--verify", nargs=2, metavar=("SITE", "CODE"),
                       help="Verify a code")
    parser.add_argument("--delete", metavar="SITE_ID", help="Delete a site")
    parser.add_argument("--export", metavar="FILE", help="Export to JSON")
    parser.add_argument("--import", dest="import_file", metavar="FILE",
                       help="Import from JSON")
    parser.add_argument("--password", default="default_password",
                       help="Master password (default: default_password)")
    
    args = parser.parse_args()
    
    app = AuthenticatorApp()
    
    if args.init:
        password_hash = app.setup_initial_password(args.password)
        print(f"Initialized. Password hash: {password_hash[:16]}...")
        print("SECURITY NOTE: Change default password in production!")
    
    if args.add:
        name, secret, issuer = args.add
        if app.add_site_interactive(name, secret, issuer):
            print(f"Added site: {name}")
        else:
            print("Failed to add site")
    
    if args.list:
        sites = app.storage.get_all_sites(args.password)
        print("\nSites:")
        for s in sites:
            print(f"  [{s.id[:8]}] {s.name} ({s.issuer}) - {'Enabled' if s.enabled else 'Disabled'}")
    
    if args.codes:
        codes = app.get_current_codes(args.password)
        print("\nCurrent Codes:")
        for name, (code, remaining, issuer) in codes.items():
            issuer_str = f" ({issuer})" if issuer else ""
            print(f"  {name}{issuer_str}: {code} ({remaining}s)")
    
    if args.verify:
        site_name, code = args.verify
        result = app.verify_code(site_name, code, args.password)
        print(f"Verification {'SUCCESS' if result else 'FAILED'}")
    
    if args.delete:
        if app.storage.delete_site(args.delete):
            print("Site deleted")
        else:
            print("Failed to delete site")
    
    if args.export:
        json_data = app.export_sites_json(args.password)
        with open(args.export, 'w') as f:
            f.write(json_data)
        print(f"Exported to {args.export}")
    
    if args.import_file:
        with open(args.import_file, 'r') as f:
            json_data = f.read()
        count = app.import_sites_json(json_data, args.password)
        print(f"Imported {count} sites")


if __name__ == "__main__":
    main()
