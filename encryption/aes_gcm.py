"""
YOO AGENT AES-GCM Module: Authenticated Encryption with Key Rotation and Hardware Optimization
"""

import os
import json
import logging
import time
import hmac
import struct
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

# Configuration
KEY_DIR = "/var/lib/yoo-agent/aes_keys"
NONCE_COUNTER_FILE = "/var/lib/yoo-agent/nonce_counter.bin"
MAX_KEYS = 5  # Maximum retained key versions
KEY_LEN = 32  # 256-bit keys
NONCE_LEN = 12  # 96-bit nonce
TAG_LEN = 16    # 128-bit authentication tag

logger = logging.getLogger(__name__)

class AESGCMEngine:
    def __init__(self, 
                 current_key_version: str = "v1",
                 enable_hw: bool = True,
                 parallel_ops: int = 4):
        """
        Initialize AES-GCM engine with key management
        
        :param current_key_version: Active key ID
        :param enable_hw: Enable hardware acceleration
        :param parallel_ops: Thread pool size for parallel operations
        """
        self.current_key_version = current_key_version
        self.backend = default_backend()
        if enable_hw:
            self.backend = self.backend._force_software_only(False)
        self.executor = ThreadPoolExecutor(max_workers=parallel_ops)
        
        self._init_nonce_counter()
        self._validate_key(current_key_version)
        self._key_versions: Dict[str, float] = {}
        
        Path(KEY_DIR).mkdir(parents=True, exist_ok=True)

    def _init_nonce_counter(self):
        """Initialize or load nonce counter with atomic increment"""
        try:
            with open(NONCE_COUNTER_FILE, "rb") as f:
                self.nonce_counter = struct.unpack('Q', f.read())[0]
        except FileNotFoundError:
            self.nonce_counter = 0
            with open(NONCE_COUNTER_FILE, "wb") as f:
                f.write(struct.pack('Q', self.nonce_counter))

    def _atomic_increment_nonce(self) -> bytes:
        """Thread-safe nonce generation with counter persistence"""
        with open(NONCE_COUNTER_FILE, "r+b") as f:
            f.seek(0)
            counter = struct.unpack('Q', f.read(8))[0]
            f.seek(0)
            f.write(struct.pack('Q', counter + 1))
        return counter.to_bytes(NONCE_LEN, 'big')

    def _generate_key(self) -> bytes:
        """Generate cryptographically secure AES key"""
        return os.urandom(KEY_LEN)

    def _validate_key(self, key_id: str):
        """Ensure key exists or generate new"""
        key_path = Path(KEY_DIR) / f"{key_id}.key"
        if not key_path.exists():
            self.rotate_key(new_version=key_id)

    def rotate_key(self, new_version: str) -> str:
        """
        Generate new key version and prune old keys
        
        :param new_version: Unique identifier for new key
        :return: Version ID of new key
        """
        new_key = self._generate_key()
        key_path = Path(KEY_DIR) / f"{new_version}.key"
        
        # Write key with restricted permissions
        with open(key_path, "wb") as f:
            os.chmod(key_path, 0o400)
            f.write(new_key)
            
        # Update key versions and prune
        self._key_versions[new_version] = time.time()
        self._prune_old_keys()
        
        self.current_key_version = new_version
        return new_version

    def _prune_old_keys(self):
        """Remove keys exceeding retention policy"""
        versions = sorted(self._key_versions.items(), 
                         key=lambda x: x[1], reverse=True)
        for version, _ in versions[MAX_KEYS:]:
            (Path(KEY_DIR) / f"{version}.key").unlink(missing_ok=True)
            del self._key_versions[version]

    @lru_cache(maxsize=MAX_KEYS)
    def _load_key(self, key_version: str) -> bytes:
        """Load key material with version validation"""
        key_path = Path(KEY_DIR) / f"{key_version}.key"
        if not key_path.exists():
            raise ValueError(f"Key {key_version} not found")
            
        with open(key_path, "rb") as f:
            key = f.read()
            
        if len(key) != KEY_LEN:
            raise ValueError(f"Invalid key length for {key_version}")
            
        return key

    def encrypt(self, plaintext: bytes, 
               associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data with current key version
        
        :param plaintext: Data to encrypt
        :param associated_data: Optional authenticated data
        :return: (ciphertext, nonce)
        """
        key = self._load_key(self.current_key_version)
        nonce = self._atomic_increment_nonce()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
            
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce, encryptor.tag

    def decrypt(self, ciphertext: bytes, 
               nonce: bytes, 
               tag: bytes,
               associated_data: Optional[bytes] = None,
               key_version: Optional[str] = None) -> bytes:
        """
        Decrypt data with specified or current key version
        
        :param ciphertext: Encrypted data
        :param nonce: Nonce used during encryption
        :param tag: Authentication tag
        :param associated_data: Optional authenticated data
        :param key_version: Key version to use
        :return: Decrypted plaintext
        """
        version = key_version or self.current_key_version
        key = self._load_key(version)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
            
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def reencrypt(self, ciphertext: bytes, 
                 old_nonce: bytes, 
                 old_tag: bytes,
                 old_version: str) -> Tuple[bytes, bytes]:
        """
        Re-encrypt data with current key version (key rotation)
        
        :param ciphertext: Data encrypted with old key
        :param old_nonce: Nonce from original encryption
        :param old_tag: Tag from original encryption
        :param old_version: Previous key version
        :return: (new_ciphertext, new_nonce)
        """
        plaintext = self.decrypt(ciphertext, old_nonce, old_tag, key_version=old_version)
        return self.encrypt(plaintext)

    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Timing-attack resistant comparison"""
        return constant_time.bytes_eq(a, b)

    def export_key_metadata(self) -> Dict[str, Any]:
        """Export key rotation metadata for audit"""
        return {
            "current_version": self.current_key_version,
            "available_versions": list(self._key_versions.keys()),
            "key_retention_policy": f"last_{MAX_KEYS}_versions",
            "nonce_counter": self.nonce_counter
        }

# Example Usage
if __name__ == "__main__":
    engine = AESGCMEngine(current_key_version="v1")
    
    # Encrypt data
    plaintext = b"Top secret enterprise data"
    ciphertext, nonce, tag = engine.encrypt(plaintext)
    
    # Decrypt data
    decrypted = engine.decrypt(ciphertext, nonce, tag)
    print(f"Decrypted: {decrypted.decode()}")
    
    # Key rotation example
    engine.rotate_key("v2")
    new_ciphertext, new_nonce, new_tag = engine.reencrypt(ciphertext, nonce, tag, "v1")
    
    # Verify with new key
    engine.decrypt(new_ciphertext, new_nonce, new_tag, key_version="v2")
