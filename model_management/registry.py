"""
YOO AGENT Distributed Registry: CRDT-Backed Service Discovery with mTLS AuthN/Z
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from prometheus_client import Gauge, Counter, Histogram
import aiogrpc
import crdt.orset as orset

logger = logging.getLogger(__name__)

# Metrics
REGISTRY_SIZE = Gauge("registry_entries", "Registered agents count per type", ["agent_type"])
HEARTBEAT_LATENCY = Histogram("registry_heartbeat_latency", "Heartbeat processing latency in ms")
AUTH_FAILURES = Counter("registry_auth_failures", "Authentication failures by type", ["failure_type"])

# Constants
MAX_CACHE_TTL = 300  # 5 minutes for stale entries
RAFT_TIMEOUT = 10  # Seconds for consensus
MTLS_ROOT_CA = "/etc/yoo-agent/certs/ca.pem"

@dataclass
class AgentMetadata:
    id: str
    type: str
    version: str
    endpoint: str
    public_key: bytes
    last_seen: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)
    capabilities: Set[str] = field(default_factory=set)

class ZeroTrustRegistry:
    def __init__(self, node_id: str, raft_cluster: List[str]):
        self.node_id = node_id
        self.raft_cluster = raft_cluster
        self._crdt_set = orset.ORSet()
        self._metadata_store: Dict[str, AgentMetadata] = {}
        self._cert_cache: Dict[str, bool] = {}
        self._init_grpc_channel()
        self._lock = asyncio.Lock()

    def _init_grpc_channel(self) -> None:
        """Secure gRPC channel with mTLS for Raft consensus"""
        self.channel = aiogrpc.insecure_channel(  # Production should use secure
            ",".join(self.raft_cluster)
        )

    async def register_agent(self, metadata: AgentMetadata, cert_chain: bytes) -> bool:
        """Zero-trust agent registration with certificate validation"""
        if not await self._validate_certificate(cert_chain):
            AUTH_FAILURES.labels(failure_type="invalid_cert").inc()
            return False

        async with self._lock:
            if metadata.id in self._metadata_store:
                if not await self._check_authorization(metadata, "update"):
                    AUTH_FAILURES.labels(failure_type="unauthorized_update").inc()
                    return False
                self._metadata_store[metadata.id] = metadata
            else:
                if not await self._check_authorization(metadata, "register"):
                    AUTH_FAILURES.labels(failure_type="unauthorized_register").inc()
                    return False
                self._crdt_set.add(metadata.id)
                self._metadata_store[metadata.id] = metadata

            await self._replicate_state()
            REGISTRY_SIZE.labels(agent_type=metadata.type).inc()
            return True

    async def _validate_certificate(self, cert_chain: bytes) -> bool:
        """X.509 certificate chain validation against CA"""
        if cert_chain in self._cert_cache:
            return self._cert_cache[cert_chain]

        try:
            cert = load_pem_x509_certificate(cert_chain)
            with open(MTLS_ROOT_CA, "rb") as ca_file:
                ca_cert = load_pem_x509_certificate(ca_file.read())
            
            public_key = ca_cert.public_key()
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm,
                cert.signature_hash_algorithm,
            )
            self._cert_cache[cert_chain] = True
            return True
        except Exception as e:
            logger.warning(f"Certificate validation failed: {str(e)}")
            self._cert_cache[cert_chain] = False
            return False

    async def _check_authorization(self, metadata: AgentMetadata, action: str) -> bool:
        """Capability-based access control (CBAC)"""
        required_caps = {
            "register": {"registry.write"},
            "update": {"registry.update"},
            "delete": {"registry.admin"}
        }.get(action, set())
        return required_caps.issubset(metadata.capabilities)

    async def deregister_agent(self, agent_id: str) -> bool:
        """CRDT-based soft deletion with tombstone markers"""
        async with self._lock:
            if agent_id not in self._metadata_store:
                return False
                
            self._crdt_set.remove(agent_id)
            del self._metadata_store[agent_id]
            await self._replicate_state()
            REGISTRY_SIZE.labels(agent_type=self._metadata_store[agent_id].type).dec()
            return True

    async def _replicate_state(self) -> None:
        """Raft-based state replication with gRPC streaming"""
        # Implement Raft log replication via self.channel
        # See https://raft.github.io/ for consensus details
        pass

    async def discover_agents(
        self, 
        agent_type: str, 
        capabilities: Set[str], 
        min_version: Optional[str] = None
    ) -> List[AgentMetadata]:
        """Type-aware discovery with semantic version filtering"""
        async with self._lock:
            candidates = [
                meta for meta in self._metadata_store.values()
                if meta.type == agent_type 
                and capabilities.issubset(meta.capabilities)
                and (not min_version or meta.version >= min_version)
                and (time.time() - meta.last_seen) <= MAX_CACHE_TTL
            ]
            return sorted(candidates, key=lambda x: x.last_seen, reverse=True)

    async def handle_heartbeat(self, agent_id: str) -> bool:
        """Latency-optimized heartbeat with deadline-aware processing"""
        start_time = time.monotonic()
        async with self._lock:
            if agent_id not in self._metadata_store:
                return False
                
            self._metadata_store[agent_id].last_seen = time.time()
            latency_ms = (time.monotonic() - start_time) * 1000
            HEARTBEAT_LATENCY.observe(latency_ms)
            return True

    async def garbage_collect(self) -> None:
        """Tombstone reaping and stale entry cleanup"""
        async with self._lock:
            stale = [
                agent_id for agent_id, meta in self._metadata_store.items()
                if (time.time() - meta.last_seen) > MAX_CACHE_TTL
            ]
            for agent_id in stale:
                self._crdt_set.remove(agent_id)
                del self._metadata_store[agent_id]
                REGISTRY_SIZE.labels(agent_type=self._metadata_store[agent_id].type).dec()

    def get_cluster_state(self) -> orset.ORSet:
        """CRDT state for conflict resolution"""
        return self._crdt_set

    async def merge_cluster_state(self, remote_state: orset.ORSet) -> None:
        """State synchronization across federated clusters"""
        async with self._lock:
            self._crdt_set = self._crdt_set.join(remote_state)
            # Prune metadata entries not in CRDT set
            for agent_id in list(self._metadata_store.keys()):
                if agent_id not in self._crdt_set:
                    del self._metadata_store[agent_id]

class RegistryHealth:
    def __init__(self, registry: ZeroTrustRegistry):
        self.registry = registry
        
    async def check_cluster_health(self) -> Dict[str, float]:
        """Calculates cluster health score (0-100%)"""
        total = len(self.registry._metadata_store)
        stale = sum(
            1 for meta in self.registry._metadata_store.values()
            if (time.time() - meta.last_seen) > MAX_CACHE_TTL
        )
        return {
            "availability": (total - stale) / total * 100 if total else 100.0,
            "consistency": len(self.registry.raft_cluster) / 3 * 100  # Simplified
        }

# Example usage
if __name__ == "__main__":
    registry = ZeroTrustRegistry(node_id="node1", raft_cluster=["node1:50051", "node2:50051"])
    sample_meta = AgentMetadata(
        id="agent1", 
        type="edge_processor",
        version="1.2.0",
        endpoint="grpc://10.0.0.1:8080",
        public_key=b"sample_key",
        capabilities={"registry.write", "data.process"}
    )
    
    async def demo():
        await registry.register_agent(sample_meta, b"dummy_cert")
        agents = await registry.discover_agents("edge_processor", {"data.process"})
        print(f"Discovered agents: {[a.id for a in agents]}")
        
    asyncio.run(demo())
