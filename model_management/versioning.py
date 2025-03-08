"""
YOO AGENT Versioning Engine: Immutable Release Management with ECDSA Signatures
"""

import json
import logging
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from functools import lru_cache

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.exceptions import InvalidSignature
from prometheus_client import Gauge, Counter
from semantic_version import Version, Spec

logger = logging.getLogger(__name__)

# Metrics
VERSION_ACTIVE = Gauge("agent_version", "Active version code", ["env", "component"])
ROLLBACK_COUNT = Counter("version_rollbacks", "Total version rollback events")

# Constants
VERSION_LOCKFILE = "/etc/yoo-agent/versions.lock"
SIGNING_KEY_PATH = "/etc/yoo-agent/keys/version_ecdsa_private.pem"
MAX_COMPAT_DEPTH = 3  # Max dependency graph depth for conflict resolution

class VersioningEngine:
    def __init__(self, environment: str = "prod"):
        self.environment = environment
        self._load_signing_key()
        self.version_graph = self._parse_lockfile()
        self.current_version = self._resolve_current_version()
        
    def _load_signing_key(self) -> ec.EllipticCurvePrivateKey:
        """Load ECDSA private key for version signing"""
        if not Path(SIGNING_KEY_PATH).exists():
            raise RuntimeError("Version signing key not found")
            
        with open(SIGNING_KEY_PATH, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
            
        public_key = self.private_key.public_key()
        self.public_numbers = public_key.public_numbers()
        return self.private_key

    def _parse_lockfile(self) -> Dict[Version, Dict]:
        """Parse version lockfile into dependency graph"""
        try:
            with open(VERSION_LOCKFILE, "r") as f:
                lock_data = json.load(f)
                return {
                    Version(v["version"]): {
                        "dependencies": [Version(dep) for dep in v["dependencies"]],
                        "signature": bytes.fromhex(v["signature"]),
                        "timestamp": datetime.fromisoformat(v["timestamp"])
                    } for v in lock_data["versions"]
                }
        except (FileNotFoundError, KeyError) as e:
            logger.critical(f"Version lockfile corrupted: {str(e)}")
            raise

    def _resolve_current_version(self) -> Version:
        """Determine active version based on environment policy"""
        versions = sorted(self.version_graph.keys(), reverse=True)
        for ver in versions:
            if self._is_version_allowed(ver):
                VERSION_ACTIVE.labels(env=self.environment, component="core").set(int(ver))
                return ver
        raise RuntimeError("No valid version found")

    def _is_version_allowed(self, version: Version) -> bool:
        """Check version against environment rollout policy"""
        policy = {
            "dev": Spec(">=0.1.0"),
            "staging": Spec(">=1.0.0-rc.1"),
            "prod": Spec(">=1.0.0")
        }
        return version in policy[self.environment]

    def verify_version_signature(self, version: Version) -> bool:
        """Validate ECDSA signature for a version entry"""
        if version not in self.version_graph:
            return False
            
        v_data = self.version_graph[version]
        signature = v_data["signature"]
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(),
            self.public_numbers.encode_point()
        )
        
        try:
            public_key.verify(
                signature,
                self._version_digest(version, v_data["timestamp"]),
                ec.ECDSA(hashes.SHA3_384())
            )
            return True
        except InvalidSignature:
            logger.warning(f"Invalid signature for version {version}")
            return False

    def _version_digest(self, version: Version, timestamp: datetime) -> bytes:
        """Generate cryptographic digest for signing"""
        dep_hash = hashlib.sha3_384()
        for dep in self.version_graph[version]["dependencies"]:
            dep_hash.update(str(dep).encode())
            
        payload = f"{version}|{timestamp.isoformat()}|{dep_hash.hexdigest()}"
        return hashlib.sha3_384(payload.encode()).digest()

    @lru_cache(maxsize=128)
    def check_compatibility(self, new_version: Version) -> Tuple[bool, List[Version]]:
        """Check dependency compatibility with current environment"""
        if new_version not in self.version_graph:
            return False, []
            
        visited = set()
        conflict_path = []
        stack = [(new_version, 0)]
        
        while stack:
            ver, depth = stack.pop()
            if depth > MAX_COMPAT_DEPTH:
                return False, conflict_path
                
            if ver in visited:
                conflict_path.append(ver)
                return False, conflict_path
                
            visited.add(ver)
            conflict_path.append(ver)
            
            if not self._is_version_allowed(ver):
                return False, conflict_path
                
            for dep in self.version_graph[ver]["dependencies"]:
                stack.append((dep, depth + 1))
                
        return True, []

    def safe_upgrade(self, new_version: Version) -> bool:
        """Perform zero-trust version upgrade with atomic rollback"""
        if not self.verify_version_signature(new_version):
            raise SecurityError("Invalid version signature")
            
        compatible, conflicts = self.check_compatibility(new_version)
        if not compatible:
            logger.error(f"Version conflict detected: {conflicts}")
            return False
            
        try:
            self._atomic_apply_version(new_version)
            self.current_version = new_version
            return True
        except Exception as e:
            logger.error(f"Upgrade failed: {str(e)}, initiating rollback")
            ROLLBACK_COUNT.inc()
            self._rollback_safe()
            return False

    def _atomic_apply_version(self, new_version: Version) -> None:
        """Apply new version with two-phase commit protocol"""
        # 1. Prepare phase
        temp_lockfile = f"{VERSION_LOCKFILE}.tmp"
        self._write_temp_lockfile(temp_lockfile, new_version)
        
        # 2. Validate phase
        if not self._validate_lockfile(temp_lockfile):
            os.remove(temp_lockfile)
            raise RuntimeError("Lockfile validation failed")
            
        # 3. Commit phase
        os.replace(temp_lockfile, VERSION_LOCKFILE)

    def _write_temp_lockfile(self, path: str, new_version: Version) -> None:
        """Generate temporary lockfile with new version"""
        raise NotImplementedError("Lockfile mutation requires coordinator consensus")

    def _validate_lockfile(self, path: str) -> bool:
        """Cryptographic validation of new lockfile"""
        # Verify all signatures in the proposed lockfile
        with open(path, "r") as f:
            data = json.load(f)
            for entry in data["versions"]:
                ver = Version(entry["version"])
                timestamp = datetime.fromisoformat(entry["timestamp"])
                signature = bytes.fromhex(entry["signature"])
                
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP384R1(),
                    self.public_numbers.encode_point()
                )
                try:
                    public_key.verify(
                        signature,
                        self._version_digest(ver, timestamp),
                        ec.ECDSA(hashes.SHA3_384())
                    )
                except InvalidSignature:
                    return False
        return True

    def _rollback_safe(self) -> None:
        """Rollback to last known-good version"""
        last_valid = max([
            ver for ver in self.version_graph 
            if self._is_version_allowed(ver) and ver < self.current_version
        ], default=None)
        
        if last_valid:
            self.current_version = last_valid
            VERSION_ACTIVE.labels(env=self.environment, component="core").set(int(last_valid))
        else:
            logger.critical("No valid rollback target available")

class GrayReleaseManager:
    def __init__(self, version_engine: VersioningEngine):
        self.engine = version_engine
        self.canary_nodes = set()
        
    def enable_canary(self, node_id: str) -> None:
        """Enable canary version on specific node"""
        self.canary_nodes.add(node_id)
        
    def check_canary(self, node_id: str) -> bool:
        """Check if node should receive canary version"""
        return node_id in self.canary_nodes

class SecurityError(Exception):
    """Critical security violation in versioning process"""
    pass

# Example usage with atomic upgrade
if __name__ == "__main__":
    engine = VersioningEngine(environment="prod")
    print(f"Current version: {engine.current_version}")
    
    new_ver = Version("1.2.0")
    if engine.safe_upgrade(new_ver):
        print(f"Successfully upgraded to {new_ver}")
    else:
        print("Upgrade failed, system rolled back")
