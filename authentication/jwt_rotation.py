"""
YOO AGENT JWT Rotation Engine: Asymmetric Key Management with Graceful Rollover
"""

import os
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, AsyncGenerator
import json
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import jwt
import ntplib

# Constants
KEY_ROTATION_INTERVAL = 3600  # 1 hour in seconds
TOKEN_LIFETIME = 300  # 5 minutes
MAX_CLOCK_SKEW = 30  # Seconds
KEY_CACHE_SIZE = 3  # Keep previous 3 keys
BLACKLIST_CACHE_TTL = 86400  # 24h

class KeyRotationVault:
    def __init__(self):
        self._current_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._previous_keys: Dict[str, ed25519.Ed25519PublicKey] = {}
        self._key_expiration: Dict[str, float] = {}
        self._blacklisted_tokens = set()
        self._key_fingerprints = {}
        self._ntp_client = ntplib.NTPClient()
        
        # Initialize first key
        self._rotate_keys(force=True)

    def _generate_new_key(self) -> ed25519.Ed25519PrivateKey:
        """Create EdDSA private key with HKDF strengthening"""
        seed = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b"YOO_AGENT_JWT_KEY",
        )
        key_material = hkdf.derive(seed)
        return ed25519.Ed25519PrivateKey.from_private_bytes(key_material)

    def _rotate_keys(self, force: bool = False):
        """Automated key rotation with phase-out window"""
        now = self._get_ntp_time()
        
        if not force:
            if self._current_key and self._key_expiration["current"] > now:
                return
        
        # Phase out expired keys
        for kid in list(self._previous_keys.keys()):
            if self._key_expiration[kid] < now - KEY_ROTATION_INTERVAL * KEY_CACHE_SIZE:
                del self._previous_keys[kid]
                del self._key_expiration[kid]
                del self._key_fingerprints[kid]
        
        # Roll current key to previous
        if self._current_key:
            current_pub = self._current_key.public_key()
            current_kid = self._get_key_id(current_pub)
            self._previous_keys[current_kid] = current_pub
            self._key_expiration[current_kid] = now + KEY_ROTATION_INTERVAL * KEY_CACHE_SIZE
            self._key_fingerprints[current_kid] = self._get_key_fingerprint(current_pub)
        
        # Generate new key
        new_key = self._generate_new_key()
        new_pub = new_key.public_key()
        new_kid = self._get_key_id(new_pub)
        self._current_key = new_key
        self._key_expiration["current"] = now + KEY_ROTATION_INTERVAL
        self._key_fingerprints[new_kid] = self._get_key_fingerprint(new_pub)
        
    def _get_key_id(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """Compute KID from public key fingerprint"""
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.blake2b(pub_bytes, digest_size=16).hexdigest()

    def _get_key_fingerprint(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """Compute full key fingerprint for audit logs"""
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha3_256(pub_bytes).hexdigest()

    def _get_ntp_time(self) -> float:
        """NTP-synced timestamp to prevent time drift attacks"""
        try:
            response = self._ntp_client.request("pool.ntp.org")
            return response.tx_time
        except:
            logging.warning("NTP sync failed, using system time")
            return time.time()

    def get_signing_key(self) -> Tuple[ed25519.Ed25519PrivateKey, str]:
        """Retrieve current signing key with KID"""
        self._rotate_keys()
        public_key = self._current_key.public_key()
        return self._current_key, self._get_key_id(public_key)

    def get_verification_keys(self) -> Dict[str, ed25519.Ed25519PublicKey]:
        """Retrieve all valid public keys"""
        self._rotate_keys()
        return {**self._previous_keys, self._get_key_id(self._current_key.public_key()): self._current_key.public_key()}

    async def blacklist_token(self, token: str, ttl: int = BLACKLIST_CACHE_TTL):
        """Revoke token before expiration"""
        self._blacklisted_tokens.add(hashlib.sha256(token.encode()).digest())
        # Schedule TTL-based eviction
        async def evict():
            await asyncio.sleep(ttl)
            self._blacklisted_tokens.discard(hashlib.sha256(token.encode()).digest())
        asyncio.create_task(evict())

    def is_blacklisted(self, token: str) -> bool:
        """Check token revocation status"""
        return hashlib.sha256(token.encode()).digest() in self._blacklisted_tokens

class JWTManager:
    def __init__(self, vault: KeyRotationVault):
        self.vault = vault

    def generate_token(self, payload: Dict) -> str:
        """Create JWT with auto-rotating keys"""
        private_key, kid = self.vault.get_signing_key()
        now = self.vault._get_ntp_time()
        
        claims = {
            "iss": "YOO_AGENT",
            "iat": now,
            "exp": now + TOKEN_LIFETIME,
            "nbf": now - MAX_CLOCK_SKEW,
            "kid": kid,
            "fpt": self.vault._key_fingerprints[kid],
            **payload
        }
        
        return jwt.encode(
            claims,
            private_key,
            algorithm="EdDSA",
            headers={"typ": "JWT", "cty": "yoo-agent-v1"}
        )

    def validate_token(self, token: str) -> Dict:
        """Verify JWT signature and expiration with key rotation support"""
        if self.vault.is_blacklisted(token):
            raise jwt.InvalidTokenError("Revoked token")

        try:
            unverified = jwt.get_unverified_header(token)
            kid = unverified.get("kid")
            keys = self.vault.get_verification_keys()
            
            if kid not in keys:
                raise jwt.InvalidKeyError(f"Unknown key ID: {kid}")
                
            return jwt.decode(
                token,
                keys[kid],
                algorithms=["EdDSA"],
                options={
                    "verify_signature": True,
                    "require": ["exp", "iat", "nbf", "iss", "fpt"],
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "leeway": MAX_CLOCK_SKEW
                },
                issuer="YOO_AGENT"
            )
        except (jwt.ExpiredSignatureError, jwt.ImmatureSignatureError) as e:
            current_time = self.vault._get_ntp_time()
            logging.error(f"Token time validation failed: {e} (Server NTP: {current_time})")
            raise
        except InvalidSignature as e:
            logging.warning(f"Signature verification failed for KID {kid}: {str(e)}")
            raise jwt.InvalidSignatureError("Invalid cryptographic signature")
            
    async def refresh_token(self, token: str) -> AsyncGenerator[str, None]:
        """Async token refresh with seamless re-authentication"""
        try:
            payload = self.validate_token(token)
            del payload["iat"]
            del payload["exp"]
            del payload["nbf"]
            
            while True:
                new_token = self.generate_token(payload)
                yield new_token
                await asyncio.sleep(TOKEN_LIFETIME - 30)  # Refresh 30s before expiry
                
        except jwt.InvalidTokenError as e:
            logging.error(f"Token refresh failed: {str(e)}")
            raise

# Example Usage
if __name__ == "__main__":
    vault = KeyRotationVault()
    manager = JWTManager(vault)
    
    # Generate token
    token = manager.generate_token({"sub": "agent1", "permissions": ["read:data"]})
    print(f"Generated Token: {token}")
    
    # Validate token
    try:
        claims = manager.validate_token(token)
        print(f"Valid claims: {json.dumps(claims, indent=2)}")
    except Exception as e:
        print(f"Validation failed: {str(e)}")
