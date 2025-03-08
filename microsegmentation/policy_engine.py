"""
YOO AGENT Policy Engine: Attribute-Based Access Control (ABAC) with Real-Time Policy Enforcement
"""

import json
import logging
import time
import hashlib
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from functools import lru_cache
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from pydantic import BaseModel, ValidationError
import watchdog.observers
import watchdog.events

logger = logging.getLogger(__name__)

# Configuration
POLICY_DIR = "/etc/yoo-agent/policies"
AUDIT_LOG_PATH = "/var/log/yoo-agent/policy_audit.log"
JWT_PUBLIC_KEY_PATH = "/etc/yoo-agent/keys/public.pem"
CACHE_SIZE = 1024  # LRU cache entries
RELOAD_INTERVAL = 300  # 5 minutes

class Policy(BaseModel):
    id: str
    version: str
    effect: str  # "allow" or "deny"
    actions: List[str]
    resources: List[str]
    conditions: Dict[str, Any]
    description: Optional[str] = None

class PolicyDecision(BaseModel):
    allowed: bool
    policy_id: str
    reason: str

class PolicyEngine:
    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.jwt_public_key = self._load_jwt_public_key()
        self.lock = threading.RLock()
        self.observer = watchdog.observers.Observer()
        
        self._init_policies()
        self._start_file_watcher()
        
    def _load_jwt_public_key(self):
        """Load JWT verification public key"""
        with open(JWT_PUBLIC_KEY_PATH, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def _init_policies(self):
        """Load all policies from directory"""
        policy_files = Path(POLICY_DIR).glob("*.json")
        for pf in policy_files:
            try:
                policy = self._load_policy_file(pf)
                self.policies[f"{policy.id}:{policy.version}"] = policy
            except (ValidationError, json.JSONDecodeError) as e:
                logger.error(f"Invalid policy {pf}: {e}")

    def _load_policy_file(self, path: Path) -> Policy:
        """Load and validate single policy file"""
        with open(path, "r") as f:
            data = json.load(f)
            return Policy(**data)

    def _start_file_watcher(self):
        """Monitor policy directory for changes"""
        event_handler = watchdog.events.FileSystemEventHandler()
        event_handler.on_modified = self._on_policy_change
        self.observer.schedule(event_handler, POLICY_DIR, recursive=False)
        self.observer.start()

    def _on_policy_change(self, event):
        """Reload policies when files change"""
        if event.src_path.endswith(".json"):
            try:
                with self.lock:
                    policy = self._load_policy_file(Path(event.src_path))
                    self.policies[f"{policy.id}:{policy.version}"] = policy
                    logger.info(f"Reloaded policy {policy.id} v{policy.version}")
            except Exception as e:
                logger.error(f"Failed to reload {event.src_path}: {e}")

    @lru_cache(maxsize=CACHE_SIZE)
    def decide(
        self,
        action: str,
        resource: str,
        jwt_token: str,
        environment: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        """
        Evaluate access decision with ABAC
        
        :param action: Action being requested (e.g., "read", "write")
        :param resource: Resource identifier (e.g., "/data/sensitive")
        :param jwt_token: JWT containing user attributes
        :param environment: Runtime context (e.g., IP, time)
        :return: Policy decision with reason
        """
        # Validate inputs
        self._validate_inputs(action, resource, jwt_token)
        
        # Decode and verify JWT
        claims = self._verify_jwt(jwt_token)
        if not claims:
            return PolicyDecision(
                allowed=False,
                policy_id="",
                reason="Invalid JWT signature"
            )

        # Prepare evaluation context
        context = {
            "user": claims.get("sub"),
            "roles": claims.get("roles", []),
            "action": action,
            "resource": resource,
            "env": environment or {}
        }

        # Evaluate all applicable policies
        applicable = self._find_applicable_policies(action, resource)
        decision = PolicyDecision(allowed=False, policy_id="", reason="Default deny")

        for policy in applicable:
            if self._evaluate_conditions(policy.conditions, context):
                decision.allowed = (policy.effect == "allow")
                decision.policy_id = policy.id
                decision.reason = policy.description or f"Matched policy {policy.id}"
                break

        # Audit log
        self._log_decision(decision, context)

        return decision

    def _validate_inputs(self, action: str, resource: str, jwt_token: str):
        """Sanity check input parameters"""
        if not action or not resource or not jwt_token:
            raise ValueError("Missing required parameters")
        if not resource.startswith("/"):
            raise ValueError("Resource must be path-like")

    def _verify_jwt(self, token: str) -> Dict[str, Any]:
        """Verify JWT signature and return claims"""
        try:
            return jwt.decode(
                token,
                self.jwt_public_key,
                algorithms=["RS256"],
                options={"verify_aud": False}
            )
        except jwt.JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return {}

    def _find_applicable_policies(self, action: str, resource: str) -> List[Policy]:
        """Find policies matching action/resource patterns"""
        with self.lock:
            return [
                p for p in self.policies.values()
                if self._matches_patterns(action, p.actions) and
                   self._matches_patterns(resource, p.resources)
            ]

    def _matches_patterns(self, target: str, patterns: List[str]) -> bool:
        """Check if target matches any glob-style pattern"""
        return any(self._glob_match(target, pat) for pat in patterns)

    def _glob_match(self, target: str, pattern: str) -> bool:
        """Simple glob-style matcher (e.g., 'data/*')"""
        parts = pattern.split("*")
        if len(parts) == 1:
            return target == pattern
        return target.startswith(parts[0]) and target.endswith(parts[-1])

    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict) -> bool:
        """Evaluate ABAC conditions using safe evaluation"""
        try:
            return all(
                self._evaluate_condition(key, value, context)
                for key, value in conditions.items()
            )
        except Exception as e:
            logger.error(f"Condition evaluation failed: {e}")
            return False

    def _evaluate_condition(self, key: str, expected: Any, context: Dict) -> bool:
        """Evaluate single condition using context variables"""
        # Supported operations: eq, ne, gt, lt, in, not_in, regex
        if isinstance(expected, dict) and "op" in expected:
            op = expected["op"]
            actual = context.get(key)
            
            if op == "eq":
                return actual == expected["value"]
            elif op == "ne":
                return actual != expected["value"]
            elif op == "gt":
                return actual > expected["value"]
            elif op == "lt":
                return actual < expected["value"]
            elif op == "in":
                return actual in expected["value"]
            elif op == "not_in":
                return actual not in expected["value"]
            elif op == "regex":
                import re
                return bool(re.match(expected["value"], str(actual)))
            else:
                raise ValueError(f"Unsupported operator {op}")
        else:
            # Default to equality check
            return context.get(key) == expected

    def _log_decision(self, decision: PolicyDecision, context: Dict):
        """Write audit log entry with thread-safe file writing"""
        log_entry = {
            "timestamp": time.time(),
            "user": context.get("user"),
            "resource": context["resource"],
            "action": context["action"],
            "allowed": decision.allowed,
            "policy_id": decision.policy_id,
            "reason": decision.reason,
            "env": context["env"]
        }
        
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def list_policies(self) -> List[Dict]:
        """Get current active policies for API"""
        with self.lock:
            return [p.dict() for p in self.policies.values()]

    def reload_policies(self):
        """Force reload all policies"""
        with self.lock:
            self.policies.clear()
            self._init_policies()
            self.decide.cache_clear()

# Example Usage
if __name__ == "__main__":
    engine = PolicyEngine()
    
    # Sample JWT (for testing only)
    test_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZXMiOlsiYWRtaW4iLCJkZXZlbG9wZXIiXX0.fak3signatur3"
    
    # Test case 1: Allowed access
    decision = engine.decide(
        action="read",
        resource="/data/reports",
        jwt_token=test_jwt,
        environment={"ip": "10.0.0.1"}
    )
    print(f"Decision: {decision.allowed}, Reason: {decision.reason}")
    
    # Test case 2: Denied access
    decision = engine.decide(
        action="delete",
        resource="/data/sensitive",
        jwt_token=test_jwt
    )
    print(f"Decision: {decision.allowed}, Reason: {decision.reason}")
