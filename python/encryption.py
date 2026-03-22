"""
Encryption utilities for TOTP Authenticator
Provides AES-256-GCM encryption for secrets
"""

import hashlib
import os
import base64
import json
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not installed. Run: pip install cryptography")


def derive_key(password: str, salt: Optional[bytes] = None) -> bytes:
    """
    Derive a 256-bit key from password using PBKDF2
    
    Args:
        password: User password
        salt: Optional salt (generates random if not provided)
    
    Returns:
        32-byte derived key
    """
    if salt is None:
        salt = os.urandom(16)
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,  # iterations
        dklen=32
    )
    return key


def encrypt_data(plaintext: str, password: str) -> str:
    """
    Encrypt data using AES-256-GCM
    
    Args:
        plaintext: Data to encrypt
        password: Encryption password
    
    Returns:
        Base64 encoded string: salt(16) + nonce(12) + ciphertext
    """
    if not CRYPTO_AVAILABLE:
        # Fallback: simple base64 (NOT secure, for testing only)
        return base64.b64encode(plaintext.encode()).decode()
    
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    # Combine: salt + nonce + ciphertext
    encrypted = salt + nonce + ciphertext
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_data(encrypted_data: str, password: str) -> str:
    """
    Decrypt AES-256-GCM encrypted data
    
    Args:
        encrypted_data: Base64 encoded encrypted data
        password: Decryption password
    
    Returns:
        Decrypted plaintext
    """
    if not CRYPTO_AVAILABLE:
        # Fallback for simple base64
        return base64.b64decode(encrypted_data.encode()).decode()
    
    try:
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        
        salt = encrypted_bytes[:16]
        nonce = encrypted_bytes[16:28]
        ciphertext = encrypted_bytes[28:]
        
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return ""


def hash_password(password: str) -> str:
    """
    Create a secure hash of the password for verification
    Uses SHA-256 with salt (NOT for encryption, just verification)
    """
    salt = os.urandom(16)
    hash_value = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return base64.b64encode(salt + hash_value).decode('utf-8')


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against stored hash
    """
    try:
        decoded = base64.b64decode(stored_hash.encode('utf-8'))
        salt = decoded[:16]
        stored_hash_value = decoded[16:]
        
        hash_value = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        
        return hash_value == stored_hash_value
    except Exception:
        return False


# Test/demo
if __name__ == "__main__":
    # Demo encryption
    test_data = "JBSWY3DPEHPK3PXP"  # Example TOTP secret
    test_password = "MySecurePassword123"
    
    print("=== Encryption Demo ===")
    print(f"Original: {test_data}")
    
    encrypted = encrypt_data(test_data, test_password)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = decrypt_data(encrypted, test_password)
    print(f"Decrypted: {decrypted}")
    
    print(f"\nVerification: {test_data == decrypted}")
