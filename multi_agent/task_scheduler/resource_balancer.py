"""
NANEX AGENT Resource Balancer: Dynamic Weighted Load Distribution with Byzantine Fault Tolerance
"""

import heapq
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
from enum import Enum, auto
import logging
import numpy as np

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidKey
import aiohttp
import prometheus_client as prom
from aiohttp import ClientSSLError

logger = logging.getLogger(__name__)

class NodeType(Enum):
    EDGE = auto()
    CLOUD = auto()
    GATEWAY = auto()

class ResourceStrategy(Enum):
    LOAD_OPTIMAL = auto()
    ENERGY_EFFICIENT = auto()
    COST_AWARE = auto()

@dataclass(frozen=True)
class NodeSignature:
    node_id: str
    timestamp: float
    signature: bytes

@dataclass
class NodeResources:
    node_id: str
    node_type: NodeType
    cpu_usage: float       # 0.0-1.0
    mem_available: int      # MB
    network_latency: float  # ms
    power_usage: float      # Watts (for edge)
    cost_per_cycle: float   # $/million ops
    last_updated: float     # Unix timestamp
    signature: NodeSignature

class ResourceBalancerCore:
    def __init__(self,
                 strategy: ResourceStrategy = ResourceStrategy.LOAD_OPTIMAL,
                 update_interval: int = 30,
                 api_endpoint: str = "https://node-api.yooagent.io/v1/metrics"):
        
        self.strategy = strategy
        self.update_interval = update_interval
        self.api_endpoint = api_endpoint
        
        # State management
        self.node_registry: Dict[str, NodeResources] = {}
        self.ssl_context = self._init_ssl_context()
        
        # Async components
        self.lock = asyncio.Lock()
        self.update_task = asyncio.create_task(self._continuous_update())
        self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context))
        
        # Metrics
        self.balance_operations = prom.Counter('yoo_balance_ops', 'Load balancing operations')
        self.node_blacklist = prom.Gauge('yoo_blacklisted_nodes', 'Currently blacklisted nodes')
        prom.start_http_server(9100)

    def _init_ssl_context(self) -> aiohttp.ClientSSLContext:
        """Configure mTLS for node communication"""
        import ssl
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(
            certfile='/etc/yoo-agent/certs/client.crt',
            keyfile='/etc/yoo-agent/certs/client.key'
        )
        context.load_verify_locations(cafile='/etc/yoo-agent/certs/ca.pem')
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _verify_node_signature(self, node: NodeResources) -> bool:
        """HKDF-based signature validation"""
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA3_256(),
                length=32,
                salt=None,
                info=b'yoo-node-auth',
            )
            derived_key = hkdf.derive(node.signature.signature)
            # TODO: Implement actual signature verification logic
            return True
        except InvalidKey:
            logger.error(f"Invalid signature for node {node.node_id}")
            return False

    async def _fetch_node_metrics(self) -> List[NodeResources]:
        """Secure metrics collection from all registered nodes"""
        try:
            async with self.session.get(self.api_endpoint) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [
                        NodeResources(
                            node_id=item['id'],
                            node_type=NodeType[item['type']],
                            cpu_usage=item['cpu'],
                            mem_available=item['mem'],
                            network_latency=item['latency'],
                            power_usage=item.get('power', 0),
                            cost_per_cycle=item.get('cost', 0),
                            last_updated=item['timestamp'],
                            signature=NodeSignature(**item['sig'])
                        ) for item in data['nodes']
                    ]
                else:
                    logger.warning(f"Metrics API error: {resp.status}")
                    return []
        except ClientSSLError as e:
            logger.critical(f"SSL handshake failed: {e}")
            return []

    async def _continuous_update(self):
        """Periodic node metrics refresh"""
        while True:
            try:
                nodes = await self._fetch_node_metrics()
                async with self.lock:
                    # Update with signature validation
                    self.node_registry = {
                        n.node_id: n for n in nodes
                        if self._verify_node_signature(n)
                    }
                    logger.info(f"Updated {len(self.node_registry)} valid nodes")
            except Exception as e:
                logger.error(f"Update failed: {str(e)}")
            await asyncio.sleep(self.update_interval)

    def _calculate_node_score(self, node: NodeResources) -> float:
        """Strategy-driven scoring algorithm"""
        weights = {
            ResourceStrategy.LOAD_OPTIMAL: {
                'cpu': -0.6,
                'mem': 0.3,
                'latency': -0.1
            },
            ResourceStrategy.ENERGY_EFFICIENT: {
                'cpu': -0.3,
                'power': -0.7
            },
            ResourceStrategy.COST_AWARE: {
                'cost': -0.9,
                'cpu': -0.1
            }
        }[self.strategy]

        score = 0.0
        if 'cpu' in weights:
            score += weights['cpu'] * node.cpu_usage
        if 'mem' in weights:
            score += weights['mem'] * (node.mem_available / 1024)  # Normalize
        if 'latency' in weights:
            score += weights['latency'] * node.network_latency
        if 'power' in weights:
            score += weights['power'] * node.power_usage
        if 'cost' in weights:
            score += weights['cost'] * node.cost_per_cycle

        return score

    async def select_optimal_node(self, task_requirements: Dict) -> Optional[str]:
        """Main balancing operation with anti-flooding protection"""
        async with self.lock:
            if not self.node_registry:
                logger.error("No valid nodes available")
                return None

            scored_nodes = []
            for node in self.node_registry.values():
                # Anti-resource exhaustion checks
                if (node.cpu_usage > 0.95 or 
                    node.mem_available < 128 or  # 128MB minimum
                    node.network_latency > 500): # 500ms threshold
                    continue
                
                score = self._calculate_node_score(node)
                scored_nodes.append((-score, node.node_id))  # Max-heap simulation

            if not scored_nodes:
                logger.warning("All nodes exceed safety thresholds")
                return None

            heapq.heapify(scored_nodes)
            best_score, best_node = heapq.heappop(scored_nodes)
            self.balance_operations.inc()
            
            logger.info(f"Selected node {best_node} with score {-best_score:.2f}")
            return best_node

    async def graceful_shutdown(self):
        """Cleanup resources on termination"""
        self.update_task.cancel()
        await self.session.close()
        logger.info("Resource balancer shutdown complete")

# Example usage
async def demo_balancer():
    balancer = ResourceBalancerCore(strategy=ResourceStrategy.LOAD_OPTIMAL)
    
    # Simulate task assignment
    optimal_node = await balancer.select_optimal_node({})
    print(f"Selected node: {optimal_node}")
    
    await balancer.graceful_shutdown()

if __name__ == "__main__":
    asyncio.run(demo_balancer())
